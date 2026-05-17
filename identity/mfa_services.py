import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from io import BytesIO

import pyotp
from cryptography.fernet import Fernet
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.utils import timezone

from .auth_sessions import get_client_ip
from .models import MFAChallenge, User, UserMFASettings


GENERIC_MFA_ERROR = "Invalid credentials or verification code"


@dataclass(frozen=True)
class MFAChallengeIssue:
    token: str
    challenge: MFAChallenge
    expires_in: int


@dataclass(frozen=True)
class MFAEnrollmentSecret:
    secret: str
    encrypted_secret: str
    otpauth_uri: str
    qr_data_uri: str


@dataclass(frozen=True)
class TOTPValidationResult:
    valid: bool
    timestep: int | None = None


@dataclass(frozen=True)
class MFAFailureResult:
    failed_attempts: int
    challenge_failed_attempts: int | None
    challenge_invalidated: bool
    locked_until: datetime | None


class MFAServiceError(Exception):
    def __init__(self, detail=GENERIC_MFA_ERROR, code="mfa_error"):
        super().__init__(detail)
        self.detail = detail
        self.code = code


class MFALockedError(MFAServiceError):
    def __init__(self, locked_until):
        super().__init__(GENERIC_MFA_ERROR, code="mfa_locked")
        self.locked_until = locked_until


def get_or_create_mfa_settings(user: User) -> UserMFASettings:
    mfa_settings, _ = UserMFASettings.objects.get_or_create(user=user)
    return mfa_settings


def is_mfa_enabled(user: User) -> bool:
    return get_or_create_mfa_settings(user).mfa_enabled


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def encrypt_secret(secret: str) -> str:
    return _get_fernet().encrypt(secret.encode("utf-8")).decode("utf-8")


def decrypt_secret(encrypted_secret: str) -> str:
    return _get_fernet().decrypt(encrypted_secret.encode("utf-8")).decode("utf-8")


def create_pending_enrollment_secret(user: User) -> MFAEnrollmentSecret:
    secret = generate_totp_secret()
    encrypted_secret = encrypt_secret(secret)
    mfa_settings = get_or_create_mfa_settings(user)
    mfa_settings.pending_mfa_secret_encrypted = encrypted_secret
    mfa_settings.save(update_fields=["pending_mfa_secret_encrypted", "updated_at"])

    otpauth_uri = build_otpauth_uri(user=user, secret=secret)
    return MFAEnrollmentSecret(
        secret=secret,
        encrypted_secret=encrypted_secret,
        otpauth_uri=otpauth_uri,
        qr_data_uri=build_qr_data_uri(otpauth_uri),
    )


def build_otpauth_uri(*, user: User, secret: str) -> str:
    totp = _build_totp(secret)
    return totp.provisioning_uri(name=user.username, issuer_name=settings.MFA_ISSUER_NAME)


def build_qr_data_uri(otpauth_uri: str) -> str:
    import qrcode

    qr_image = qrcode.make(otpauth_uri)
    buffer = BytesIO()
    qr_image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def hash_challenge_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_mfa_challenge(*, user: User, purpose: str, request=None) -> MFAChallengeIssue:
    if purpose not in MFAChallenge.Purpose.values:
        raise ValueError(f"Unsupported MFA challenge purpose: {purpose}")

    expires_in = settings.MFA_CHALLENGE_TTL_SECONDS
    raw_token = secrets.token_urlsafe(32)
    challenge = MFAChallenge.objects.create(
        user=user,
        challenge_token_hash=hash_challenge_token(raw_token),
        purpose=purpose,
        expires_at=timezone.now() + timedelta(seconds=expires_in),
        ip_address=get_client_ip(request),
        user_agent=(request.META.get("HTTP_USER_AGENT", "") if request else "")[:512],
    )
    return MFAChallengeIssue(token=raw_token, challenge=challenge, expires_in=expires_in)


def get_valid_mfa_challenge(*, raw_token: str, purpose: str, user: User | None = None) -> MFAChallenge:
    query = MFAChallenge.objects.select_related("user").filter(
        challenge_token_hash=hash_challenge_token(raw_token),
        purpose=purpose,
    )
    if user is not None:
        query = query.filter(user=user)

    challenge = query.first()
    if challenge is None or not challenge.is_active:
        raise MFAServiceError(code="invalid_mfa_challenge")
    return challenge


def mark_challenge_used(challenge: MFAChallenge) -> None:
    challenge.mark_used()


def assert_not_locked(mfa_settings: UserMFASettings) -> None:
    if mfa_settings.is_locked:
        raise MFALockedError(mfa_settings.locked_until)


def get_active_totp_secret(mfa_settings: UserMFASettings) -> str:
    if not mfa_settings.mfa_secret_encrypted:
        raise MFAServiceError(code="mfa_secret_missing")
    return decrypt_secret(mfa_settings.mfa_secret_encrypted)


def get_pending_totp_secret(mfa_settings: UserMFASettings) -> str:
    if not mfa_settings.pending_mfa_secret_encrypted:
        raise MFAServiceError(code="pending_mfa_secret_missing")
    return decrypt_secret(mfa_settings.pending_mfa_secret_encrypted)


def validate_totp_code(
    *,
    mfa_settings: UserMFASettings,
    code: str,
    secret: str | None = None,
    prevent_reuse: bool = True,
) -> TOTPValidationResult:
    assert_not_locked(mfa_settings)
    totp_secret = secret or get_active_totp_secret(mfa_settings)
    timestep = _matching_totp_timestep(totp_secret, code)
    if timestep is None:
        return TOTPValidationResult(valid=False)

    if prevent_reuse and mfa_settings.last_used_totp_step is not None:
        if timestep <= mfa_settings.last_used_totp_step:
            return TOTPValidationResult(valid=False, timestep=timestep)

    return TOTPValidationResult(valid=True, timestep=timestep)


@transaction.atomic
def activate_pending_mfa_secret(*, mfa_settings: UserMFASettings, timestep: int | None = None) -> UserMFASettings:
    mfa_settings = UserMFASettings.objects.select_for_update().get(pk=mfa_settings.pk)
    if not mfa_settings.pending_mfa_secret_encrypted:
        raise MFAServiceError(code="pending_mfa_secret_missing")

    mfa_settings.mfa_secret_encrypted = mfa_settings.pending_mfa_secret_encrypted
    mfa_settings.pending_mfa_secret_encrypted = None
    mfa_settings.mfa_enabled = True
    mfa_settings.mfa_confirmed_at = timezone.now()
    mfa_settings.failed_attempts = 0
    mfa_settings.locked_until = None
    if timestep is not None:
        mfa_settings.last_used_totp_step = timestep
    mfa_settings.save(
        update_fields=[
            "mfa_secret_encrypted",
            "pending_mfa_secret_encrypted",
            "mfa_enabled",
            "mfa_confirmed_at",
            "failed_attempts",
            "locked_until",
            "last_used_totp_step",
            "updated_at",
        ]
    )
    return mfa_settings


def record_mfa_success(*, mfa_settings: UserMFASettings, timestep: int | None = None) -> UserMFASettings:
    mfa_settings.failed_attempts = 0
    mfa_settings.locked_until = None
    if timestep is not None:
        mfa_settings.last_used_totp_step = timestep
    mfa_settings.save(update_fields=["failed_attempts", "locked_until", "last_used_totp_step", "updated_at"])
    return mfa_settings


@transaction.atomic
def record_mfa_failure(
    *,
    mfa_settings: UserMFASettings,
    challenge: MFAChallenge | None = None,
) -> MFAFailureResult:
    mfa_settings = UserMFASettings.objects.select_for_update().get(pk=mfa_settings.pk)
    now = timezone.now()
    challenge_failed_attempts = None
    challenge_invalidated = False

    if challenge is not None:
        challenge = MFAChallenge.objects.select_for_update().get(pk=challenge.pk)
        challenge.failed_attempts += 1
        challenge_failed_attempts = challenge.failed_attempts
        update_fields = ["failed_attempts"]
        if challenge.failed_attempts >= settings.MFA_CHALLENGE_MAX_FAILED_ATTEMPTS and challenge.used_at is None:
            challenge.used_at = now
            update_fields.append("used_at")
            challenge_invalidated = True
        challenge.save(update_fields=update_fields)

    mfa_settings.failed_attempts += 1
    lockout_minutes = _lockout_minutes_for_failures(mfa_settings.failed_attempts)
    if lockout_minutes is not None:
        mfa_settings.locked_until = now + timedelta(minutes=lockout_minutes)
    mfa_settings.save(update_fields=["failed_attempts", "locked_until", "updated_at"])

    return MFAFailureResult(
        failed_attempts=mfa_settings.failed_attempts,
        challenge_failed_attempts=challenge_failed_attempts,
        challenge_invalidated=challenge_invalidated,
        locked_until=mfa_settings.locked_until,
    )


def _build_totp(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(secret, interval=settings.MFA_TOTP_INTERVAL_SECONDS)


def _matching_totp_timestep(secret: str, code: str) -> int | None:
    normalized_code = _normalize_totp_code(code)
    if not normalized_code:
        return None

    totp = _build_totp(secret)
    now = timezone.now()
    current_timestep = totp.timecode(now)
    valid_window = settings.MFA_TOTP_VALID_WINDOW
    for offset in range(-valid_window, valid_window + 1):
        expected_code = totp.at(now, counter_offset=offset)
        if pyotp.utils.strings_equal(normalized_code, expected_code):
            return current_timestep + offset
    return None


def _normalize_totp_code(code: str) -> str:
    return str(code or "").replace(" ", "").strip()


def _lockout_minutes_for_failures(failed_attempts: int) -> int | None:
    threshold = settings.MFA_LOCKOUT_FAILURE_THRESHOLD
    if failed_attempts < threshold:
        return None

    schedule = settings.MFA_LOCKOUT_MINUTES
    if not schedule:
        return None

    schedule_index = min((failed_attempts - threshold) // threshold, len(schedule) - 1)
    return schedule[schedule_index]


def _get_fernet() -> Fernet:
    raw_key = settings.MFA_SECRET_ENCRYPTION_KEY
    if not raw_key:
        raise ImproperlyConfigured("MFA_SECRET_ENCRYPTION_KEY must be configured.")
    if not settings.DEBUG and raw_key == settings.SECRET_KEY:
        raise ImproperlyConfigured("MFA_SECRET_ENCRYPTION_KEY must be independent from SECRET_KEY in production.")

    derived_key = base64.urlsafe_b64encode(hashlib.sha256(raw_key.encode("utf-8")).digest())
    return Fernet(derived_key)
