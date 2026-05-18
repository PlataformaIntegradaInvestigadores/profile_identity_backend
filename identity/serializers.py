from django.conf import settings
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import serializers, status
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer

from .application.use_cases import (
    create_group,
    create_profile_information,
    register_user,
    update_profile_information,
    update_user,
)
from .auth_sessions import create_auth_session, get_active_session_for_refresh, rotate_auth_session
from .mfa_services import (
    GENERIC_MFA_ERROR,
    MFAServiceError,
    MFALockedError,
    activate_pending_mfa_secret,
    create_mfa_challenge,
    create_pending_enrollment_secret,
    get_active_totp_secret,
    get_pending_totp_secret,
    hash_challenge_token,
    mark_challenge_used,
    record_mfa_failure,
    record_mfa_success,
    validate_totp_code,
)
from .models import Group, MFAChallenge, ProfileInformation, User, UserMFASettings
from .profile_services import normalize_contact_info
from .security_events import emit_security_event


class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "first_name", "last_name", "username"]


class UserTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["user_id"] = user.id
        return token

    def validate(self, attrs):
        request = self.context.get("request")
        username = attrs.get(self.username_field)
        password = attrs.get("password")
        self.user = authenticate(request=request, **{self.username_field: username, "password": password})
        if self.user is None or not self.user.is_active:
            emit_security_event(
                event_type="login_failed",
                severity="warning",
                outcome="failure",
                request=request,
                status_code=status.HTTP_401_UNAUTHORIZED,
                reason="invalid_credentials",
                username=username,
            )
            raise AuthenticationFailed(GENERIC_MFA_ERROR, code="authorization")

        mfa_settings, _ = UserMFASettings.objects.get_or_create(user=self.user)
        if mfa_settings.is_locked:
            emit_security_event(
                event_type="account_locked",
                severity="warning",
                outcome="blocked",
                request=request,
                status_code=status.HTTP_401_UNAUTHORIZED,
                user=self.user,
                reason="mfa_locked",
            )
            raise AuthenticationFailed(GENERIC_MFA_ERROR, code="authorization")

        if mfa_settings.mfa_enabled:
            challenge = create_mfa_challenge(
                user=self.user,
                purpose=MFAChallenge.Purpose.LOGIN,
                request=request,
            )
            emit_security_event(
                event_type="mfa_required",
                severity="info",
                outcome="pending",
                request=request,
                status_code=status.HTTP_200_OK,
                user=self.user,
            )
            return {
                "status": "mfa_required",
                "mfa_challenge": challenge.token,
                "expires_in": challenge.expires_in,
            }

        enforcement_mode = settings.MFA_ENFORCEMENT_MODE
        if enforcement_mode in {"enrollment_required", "required"}:
            challenge = create_mfa_challenge(
                user=self.user,
                purpose=MFAChallenge.Purpose.ENROLLMENT,
                request=request,
            )
            emit_security_event(
                event_type="mfa_enrollment_required",
                severity="info",
                outcome="pending",
                request=request,
                status_code=status.HTTP_200_OK,
                user=self.user,
            )
            return {
                "status": "mfa_enrollment_required",
                "mfa_challenge": challenge.token,
                "expires_in": challenge.expires_in,
            }

        data = super().validate(attrs)
        create_auth_session(user=self.user, raw_refresh_token=data["refresh"], request=request)
        emit_security_event(
            event_type="login_success",
            severity="info",
            outcome="success",
            request=request,
            status_code=status.HTTP_200_OK,
            user=self.user,
        )
        return data


class MFASetupSerializer(serializers.Serializer):
    mfa_challenge = serializers.CharField(write_only=True, trim_whitespace=True)

    def save(self, **kwargs):
        request = self.context.get("request")
        with transaction.atomic():
            challenge = _get_locked_mfa_challenge(
                self.validated_data["mfa_challenge"],
                MFAChallenge.Purpose.ENROLLMENT,
                request=request,
            )
            mfa_settings, _ = UserMFASettings.objects.select_for_update().get_or_create(user=challenge.user)
            if mfa_settings.mfa_enabled:
                _raise_mfa_validation_error()

            enrollment_secret = create_pending_enrollment_secret(challenge.user)
            self.user = challenge.user
            self.challenge = challenge
            return {
                "otpauth_uri": enrollment_secret.otpauth_uri,
                "manual_key": enrollment_secret.secret,
                "qr_code": enrollment_secret.qr_data_uri,
            }


class MFAConfirmSerializer(serializers.Serializer):
    mfa_challenge = serializers.CharField(write_only=True, trim_whitespace=True)
    code = serializers.CharField(write_only=True, trim_whitespace=True)

    def validate(self, attrs):
        attrs["code"] = _normalize_totp_code_or_error(attrs.get("code"))
        return attrs

    def save(self, **kwargs):
        request = self.context.get("request")
        should_raise_failure = False
        with transaction.atomic():
            challenge = _get_locked_mfa_challenge(
                self.validated_data["mfa_challenge"],
                MFAChallenge.Purpose.ENROLLMENT,
                request=request,
            )
            mfa_settings, _ = UserMFASettings.objects.select_for_update().get_or_create(user=challenge.user)

            try:
                pending_secret = get_pending_totp_secret(mfa_settings)
                validation = validate_totp_code(
                    mfa_settings=mfa_settings,
                    code=self.validated_data["code"],
                    secret=pending_secret,
                    prevent_reuse=True,
                )
            except MFALockedError:
                emit_security_event(
                    event_type="account_locked",
                    severity="warning",
                    outcome="blocked",
                    request=request,
                    status_code=status.HTTP_400_BAD_REQUEST,
                    user=challenge.user,
                    reason="mfa_locked",
                )
                _raise_mfa_validation_error()
            except MFAServiceError:
                emit_security_event(
                    event_type="mfa_failed",
                    severity="warning",
                    outcome="failure",
                    request=request,
                    status_code=status.HTTP_400_BAD_REQUEST,
                    user=challenge.user,
                    reason="mfa_secret_error",
                )
                _raise_mfa_validation_error()

            if not validation.valid:
                failure = record_mfa_failure(mfa_settings=mfa_settings, challenge=challenge)
                emit_security_event(
                    event_type="mfa_failed",
                    severity="warning",
                    outcome="failure",
                    request=request,
                    status_code=status.HTTP_400_BAD_REQUEST,
                    user=challenge.user,
                    reason="invalid_totp",
                    failed_attempts=failure.failed_attempts,
                    challenge_failed_attempts=failure.challenge_failed_attempts,
                )
                if failure.locked_until is not None:
                    emit_security_event(
                        event_type="account_locked",
                        severity="warning",
                        outcome="blocked",
                        request=request,
                        status_code=status.HTTP_400_BAD_REQUEST,
                        user=challenge.user,
                        reason="mfa_lockout_threshold",
                    )
                should_raise_failure = True
            else:
                activate_pending_mfa_secret(mfa_settings=mfa_settings, timestep=validation.timestep)
                mark_challenge_used(challenge)
                self.user = challenge.user
                self.challenge = challenge

        if should_raise_failure:
            _raise_mfa_validation_error()
        return {"detail": "MFA enabled successfully", "user": self.user}


class MFAVerifySerializer(serializers.Serializer):
    mfa_challenge = serializers.CharField(write_only=True, trim_whitespace=True)
    code = serializers.CharField(write_only=True, trim_whitespace=True)

    def validate(self, attrs):
        attrs["code"] = _normalize_totp_code_or_error(attrs.get("code"))
        return attrs

    def save(self, **kwargs):
        request = self.context.get("request")
        should_raise_failure = False
        with transaction.atomic():
            challenge = _get_locked_mfa_challenge(
                self.validated_data["mfa_challenge"],
                MFAChallenge.Purpose.LOGIN,
                request=request,
            )
            mfa_settings, _ = UserMFASettings.objects.select_for_update().get_or_create(user=challenge.user)

            try:
                active_secret = get_active_totp_secret(mfa_settings)
                validation = validate_totp_code(
                    mfa_settings=mfa_settings,
                    code=self.validated_data["code"],
                    secret=active_secret,
                    prevent_reuse=True,
                )
            except MFALockedError:
                emit_security_event(
                    event_type="account_locked",
                    severity="warning",
                    outcome="blocked",
                    request=request,
                    status_code=status.HTTP_400_BAD_REQUEST,
                    user=challenge.user,
                    reason="mfa_locked",
                )
                _raise_mfa_validation_error()
            except MFAServiceError:
                emit_security_event(
                    event_type="mfa_failed",
                    severity="warning",
                    outcome="failure",
                    request=request,
                    status_code=status.HTTP_400_BAD_REQUEST,
                    user=challenge.user,
                    reason="mfa_secret_error",
                )
                _raise_mfa_validation_error()

            if not validation.valid:
                failure = record_mfa_failure(mfa_settings=mfa_settings, challenge=challenge)
                emit_security_event(
                    event_type="mfa_failed",
                    severity="warning",
                    outcome="failure",
                    request=request,
                    status_code=status.HTTP_400_BAD_REQUEST,
                    user=challenge.user,
                    reason="invalid_totp",
                    failed_attempts=failure.failed_attempts,
                    challenge_failed_attempts=failure.challenge_failed_attempts,
                )
                if failure.locked_until is not None:
                    emit_security_event(
                        event_type="account_locked",
                        severity="warning",
                        outcome="blocked",
                        request=request,
                        status_code=status.HTTP_400_BAD_REQUEST,
                        user=challenge.user,
                        reason="mfa_lockout_threshold",
                    )
                should_raise_failure = True
            else:
                record_mfa_success(mfa_settings=mfa_settings, timestep=validation.timestep)
                mark_challenge_used(challenge)
                self.user = challenge.user
                self.challenge = challenge

        if should_raise_failure:
            _raise_mfa_validation_error()
        return {"user": self.user}


class MFAStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserMFASettings
        fields = ["mfa_enabled", "mfa_confirmed_at"]
        read_only_fields = fields


def _get_locked_mfa_challenge(raw_token: str, purpose: str, request=None) -> MFAChallenge:
    challenge = (
        MFAChallenge.objects.select_for_update()
        .select_related("user")
        .filter(
            challenge_token_hash=hash_challenge_token(raw_token),
            purpose=purpose,
        )
        .first()
    )
    if challenge is None:
        _raise_mfa_validation_error()
    if not challenge.is_active:
        if challenge.used_at is not None:
            emit_security_event(
                event_type="mfa_challenge_reused",
                severity="warning",
                outcome="failure",
                request=request,
                status_code=status.HTTP_400_BAD_REQUEST,
                user=challenge.user,
                reason="challenge_used",
            )
        elif challenge.is_expired:
            emit_security_event(
                event_type="mfa_challenge_expired",
                severity="warning",
                outcome="failure",
                request=request,
                status_code=status.HTTP_400_BAD_REQUEST,
                user=challenge.user,
                reason="challenge_expired",
            )
        _raise_mfa_validation_error()
    return challenge


def _normalize_totp_code_or_error(code: str) -> str:
    normalized_code = str(code or "").replace(" ", "").strip()
    if len(normalized_code) != 6 or not normalized_code.isdigit():
        _raise_mfa_validation_error()
    return normalized_code


def _raise_mfa_validation_error():
    raise serializers.ValidationError({"detail": GENERIC_MFA_ERROR})


class SessionTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        request = self.context.get("request")
        try:
            session = get_active_session_for_refresh(attrs["refresh"])
        except TokenError as exc:
            raise AuthenticationFailed("Refresh token session is not active.", code="token_not_valid") from exc
        if session is None:
            raise AuthenticationFailed("Refresh token session is not active.", code="token_not_valid")
        self.auth_session = session

        data = super().validate(attrs)
        rotated_refresh = data.get("refresh")
        if rotated_refresh:
            rotate_auth_session(session=session, raw_refresh_token=rotated_refresh, request=request)
        else:
            session.last_seen_at = timezone.now()
            session.save(update_fields=["last_seen_at"])
        return data


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "first_name",
            "last_name",
            "scopus_id",
            "institution",
            "website",
            "investigation_camp",
            "profile_picture",
            "email_institution",
        ]

    def validate_website(self, value):
        if value and not value.startswith(("http://", "https://")):
            value = "http://" + value
        return value

    def update(self, instance, validated_data):
        request = self.context.get("request")
        actor = request.user if request else instance
        return update_user(actor, instance, validated_data)


class UserDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "first_name",
            "last_name",
            "username",
            "scopus_id",
            "investigation_camp",
            "institution",
            "email_institution",
            "website",
            "profile_picture",
            "is_active",
            "is_staff",
        ]


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["first_name", "last_name", "username", "scopus_id", "password"]

    def validate(self, attrs):
        user = User(
            first_name=attrs.get("first_name", ""),
            last_name=attrs.get("last_name", ""),
            username=attrs.get("username", ""),
            scopus_id=attrs.get("scopus_id"),
        )
        try:
            validate_password(attrs.get("password"), user=user)
        except DjangoValidationError as exc:
            raise serializers.ValidationError({"password": list(exc.messages)}) from exc
        return attrs

    def create(self, validated_data):
        return register_user(validated_data)


class ProfileInformationSerializer(serializers.ModelSerializer):
    class Meta:
        model = ProfileInformation
        fields = ["about_me", "disciplines", "contact_info"]

    def to_representation(self, instance):
        data = super().to_representation(instance)
        data["disciplines"] = data.get("disciplines") or []
        data["contact_info"] = normalize_contact_info(data.get("contact_info"))
        return data

    def validate_contact_info(self, value):
        return normalize_contact_info(value)

    def update(self, instance, validated_data):
        request = self.context.get("request")
        actor = request.user if request else instance.user
        return update_profile_information(actor, instance, validated_data)

    def create(self, validated_data):
        return create_profile_information(validated_data)


class GroupSerializer(serializers.ModelSerializer):
    users = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), many=True, required=False)

    class Meta:
        model = Group
        fields = ["id", "title", "description", "admin_id", "users", "voting_type"]
        read_only_fields = ["id", "admin"]

    def create(self, validated_data):
        request = self.context.get("request")
        return create_group(request.user, validated_data)


class UserGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = Group
        fields = ["id", "title", "description", "admin_id", "users", "voting_type"]
        read_only_fields = ["id", "title", "description", "admin_id", "users", "voting_type"]


class GroupDetailSerializer(serializers.ModelSerializer):
    users = UserDetailSerializer(many=True, read_only=True)

    class Meta:
        model = Group
        fields = ["id", "title", "description", "admin_id", "users", "voting_type"]
        read_only_fields = ["id", "admin_id"]
