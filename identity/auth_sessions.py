import hashlib
from datetime import datetime, timezone as datetime_timezone

from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from .models import AuthSession, User


def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def expires_at_from_token(token: RefreshToken) -> datetime:
    return datetime.fromtimestamp(int(token["exp"]), tz=datetime_timezone.utc)


def create_auth_session(*, user: User, raw_refresh_token: str, request) -> AuthSession:
    refresh = RefreshToken(raw_refresh_token)
    return AuthSession.objects.create(
        user=user,
        refresh_jti=str(refresh["jti"]),
        refresh_token_hash=hash_token(raw_refresh_token),
        expires_at=expires_at_from_token(refresh),
        ip_address=get_client_ip(request),
        user_agent=(request.META.get("HTTP_USER_AGENT", "") if request else "")[:512],
    )


def rotate_auth_session(*, session: AuthSession, raw_refresh_token: str, request) -> AuthSession:
    refresh = RefreshToken(raw_refresh_token)
    session.refresh_jti = str(refresh["jti"])
    session.refresh_token_hash = hash_token(raw_refresh_token)
    session.expires_at = expires_at_from_token(refresh)
    session.last_seen_at = timezone.now()
    session.rotation_count += 1
    if request:
        session.ip_address = get_client_ip(request)
        session.user_agent = request.META.get("HTTP_USER_AGENT", "")[:512]
    session.save(
        update_fields=[
            "refresh_jti",
            "refresh_token_hash",
            "expires_at",
            "last_seen_at",
            "rotation_count",
            "ip_address",
            "user_agent",
        ]
    )
    return session


def revoke_session_for_refresh(raw_refresh_token: str) -> bool:
    refresh = RefreshToken(raw_refresh_token)
    session = AuthSession.objects.filter(refresh_jti=str(refresh["jti"]), revoked_at__isnull=True).first()
    if not session:
        return False
    session.revoke()
    return True


def get_active_session_for_refresh(raw_refresh_token: str) -> AuthSession | None:
    refresh = RefreshToken(raw_refresh_token)
    token_hash = hash_token(raw_refresh_token)
    return (
        AuthSession.objects.select_related("user")
        .filter(
            refresh_jti=str(refresh["jti"]),
            refresh_token_hash=token_hash,
            revoked_at__isnull=True,
            expires_at__gt=timezone.now(),
            user__is_active=True,
        )
        .first()
    )


def get_client_ip(request) -> str:
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "") if request else ""
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.META.get("REMOTE_ADDR", "") if request else ""
