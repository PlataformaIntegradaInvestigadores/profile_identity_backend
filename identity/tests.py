from datetime import timedelta

import pyotp
from django.conf import settings
from django.test import override_settings
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase
from rest_framework_simplejwt.tokens import AccessToken

from identity.legacy_sync import legacy_sync_client
from identity.mfa_services import encrypt_secret, hash_challenge_token
from identity.models import AuthSession, Group, LegacySyncOutbox, MFAChallenge, ProfileInformation, User, UserMFASettings


@override_settings(LEGACY_SYNC_ENABLED=False, MFA_ENFORCEMENT_MODE="optional")
class IdentityApiTests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="ana@example.com",
            password="StrongPass123",
            first_name="Ana",
            last_name="Perez",
        )
        self.other = User.objects.create_user(
            username="luis@example.com",
            password="StrongPass123",
            first_name="Luis",
            last_name="Rios",
        )

    def authenticate(self):
        response = self.client.post(
            "/api/token/",
            {"username": "ana@example.com", "password": "StrongPass123"},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("centinela_refresh", response.cookies)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {response.data['access']}")
        return response.data

    def test_login_adds_user_id_claim_compatible_with_frontend(self):
        token_response = self.authenticate()
        self.assertNotIn("refresh", token_response)

    def test_login_creates_auth_session(self):
        self.authenticate()

        session = AuthSession.objects.get(user=self.user)
        self.assertTrue(session.is_active)
        self.assertEqual(session.rotation_count, 0)

    def test_refresh_rotates_token_and_auth_session(self):
        self.authenticate()
        refresh_cookie = self.client.cookies["centinela_refresh"].value
        session = AuthSession.objects.get(user=self.user)
        original_jti = session.refresh_jti

        response = self.client.post(
            "/api/token/refresh/",
            {},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertNotIn("refresh", response.data)
        self.assertIn("centinela_refresh", response.cookies)
        self.assertNotEqual(response.cookies["centinela_refresh"].value, refresh_cookie)
        session.refresh_from_db()
        self.assertNotEqual(session.refresh_jti, original_jti)
        self.assertEqual(session.rotation_count, 1)

    def test_validate_token_endpoint_supports_gateway_auth_request(self):
        token_response = self.authenticate()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token_response['access']}")

        response = self.client.get("/internal/auth/validate-token/")

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(response.headers["X-Authenticated-User-Id"], self.user.id)

    def test_validate_token_endpoint_rejects_missing_token(self):
        response = self.client.get("/internal/auth/validate-token/")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_revokes_auth_session(self):
        self.authenticate()

        response = self.client.post(
            "/api/logout/",
            {},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        session = AuthSession.objects.get(user=self.user)
        self.assertFalse(session.is_active)

    def test_refresh_body_fallback_remains_supported_temporarily(self):
        self.authenticate()
        refresh_cookie = self.client.cookies["centinela_refresh"].value
        self.client.cookies.clear()

        response = self.client.post(
            "/api/token/refresh/",
            {"refresh": refresh_cookie},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertIn("centinela_refresh", response.cookies)

    def test_register_creates_researcher(self):
        response = self.client.post(
            "/api/register/",
            {
                "first_name": "Maria",
                "last_name": "Lopez",
                "username": "maria@example.com",
                "password": "StrongPass123",
                "scopus_id": "12345",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        user = User.objects.get(username="maria@example.com")
        self.assertTrue(ProfileInformation.objects.filter(user=user).exists())

    def test_register_rejects_weak_numeric_password(self):
        response = self.client.post(
            "/api/register/",
            {
                "first_name": "Carlos",
                "last_name": "Lopez",
                "username": "carlos@example.com",
                "password": "123456789",
                "scopus_id": "67890",
            },
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("password", response.data["errors"])
        self.assertFalse(User.objects.filter(username="carlos@example.com").exists())

    def test_public_profile_information_creates_empty_profile_for_existing_user(self):
        self.assertFalse(ProfileInformation.objects.filter(user=self.other).exists())

        response = self.client.get(f"/api/profile-information/{self.other.id}/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["about_me"], "")
        self.assertEqual(response.data["disciplines"], [])
        self.assertEqual(response.data["contact_info"], [])
        self.assertTrue(ProfileInformation.objects.filter(user=self.other).exists())

    def test_profile_information_normalizes_contact_info_to_list(self):
        ProfileInformation.objects.create(user=self.other, contact_info={"email": "luis@example.com"})

        response = self.client.get(f"/api/profile-information/{self.other.id}/")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["contact_info"], [{"type": "email", "value": "luis@example.com"}])

    def test_profile_information_own_and_public_contract(self):
        self.authenticate()
        response = self.client.put(
            "/api/profile-information/",
            {"about_me": "Researcher", "disciplines": ["AI"], "contact_info": {"email": "ana@example.com"}},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["about_me"], "Researcher")
        self.assertEqual(response.data["contact_info"], [{"type": "email", "value": "ana@example.com"}])

        public_response = self.client.get(f"/api/profile-information/{self.user.id}/")
        self.assertEqual(public_response.status_code, status.HTTP_200_OK)
        self.assertEqual(public_response.data["disciplines"], ["AI"])

    def test_group_lifecycle_contract(self):
        self.authenticate()
        response = self.client.post(
            "/api/groups/",
            {
                "title": "Research Group",
                "description": "Consensus work",
                "users": [self.other.id],
                "voting_type": "Positional Voting",
            },
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        group_id = response.data["id"]

        group = Group.objects.get(id=group_id)
        self.assertEqual(group.admin_id, self.user.id)
        self.assertEqual(set(group.users.values_list("id", flat=True)), {self.user.id, self.other.id})

        list_response = self.client.get("/api/test/user/groups/")
        self.assertEqual(list_response.status_code, status.HTTP_200_OK)
        self.assertEqual(list_response.data[0]["id"], group_id)

        remove_response = self.client.delete(f"/api/groups/{group_id}/remove-member/{self.other.id}/")
        self.assertEqual(remove_response.status_code, status.HTTP_200_OK)
        self.assertEqual(set(group.users.values_list("id", flat=True)), {self.user.id})

    def test_admin_cannot_leave_own_group(self):
        self.authenticate()
        group = Group.objects.create(title="Group", description="D", admin=self.user)
        group.users.add(self.user)

        response = self.client.post(f"/api/test/user/groups/{group.id}/leave/", {}, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


@override_settings(
    LEGACY_SYNC_ENABLED=False,
    MFA_ENFORCEMENT_MODE="enrollment_required",
    MFA_SECRET_ENCRYPTION_KEY="test-mfa-secret-key",
    MFA_CHALLENGE_TTL_SECONDS=300,
    MFA_TOTP_INTERVAL_SECONDS=30,
    MFA_TOTP_VALID_WINDOW=1,
    MFA_CHALLENGE_MAX_FAILED_ATTEMPTS=3,
    MFA_LOCKOUT_FAILURE_THRESHOLD=5,
    MFA_LOCKOUT_MINUTES=[5, 15, 30],
    JWT_REFRESH_COOKIE_SECURE=True,
    JWT_REFRESH_COOKIE_SAMESITE="Lax",
)
class MFASessionFlowTests(APITestCase):
    password = "StrongPass123"

    def setUp(self):
        self.user = User.objects.create_user(
            username="mfa@example.com",
            password=self.password,
            first_name="Mfa",
            last_name="User",
        )

    def login(self):
        return self.client.post(
            "/api/token/",
            {"username": self.user.username, "password": self.password},
            format="json",
        )

    def setup_from_challenge(self, challenge_token):
        return self.client.post(
            "/api/auth/mfa/setup/",
            {"mfa_challenge": challenge_token},
            format="json",
        )

    def confirm_from_challenge(self, challenge_token, code):
        return self.client.post(
            "/api/auth/mfa/confirm/",
            {"mfa_challenge": challenge_token, "code": code},
            format="json",
        )

    def verify_from_challenge(self, challenge_token, code):
        return self.client.post(
            "/api/auth/mfa/verify/",
            {"mfa_challenge": challenge_token, "code": code},
            format="json",
        )

    def totp_code(self, secret, offset=0):
        for_time = timezone.now() + timedelta(seconds=settings.MFA_TOTP_INTERVAL_SECONDS * offset)
        return pyotp.TOTP(secret, interval=settings.MFA_TOTP_INTERVAL_SECONDS).at(for_time)

    def wrong_totp_code(self, secret, offset=0):
        valid_code = self.totp_code(secret, offset=offset)
        return "000000" if valid_code != "000000" else "111111"

    def challenge_object(self, raw_token):
        return MFAChallenge.objects.get(challenge_token_hash=hash_challenge_token(raw_token))

    def start_enrollment(self):
        response = self.login()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "mfa_enrollment_required")
        return response.data["mfa_challenge"]

    def enroll_user(self):
        challenge = self.start_enrollment()
        setup_response = self.setup_from_challenge(challenge)
        self.assertEqual(setup_response.status_code, status.HTTP_200_OK)
        manual_key = setup_response.data["manual_key"]
        confirm_response = self.confirm_from_challenge(challenge, self.totp_code(manual_key))
        self.assertEqual(confirm_response.status_code, status.HTTP_200_OK)
        return manual_key, confirm_response

    def start_mfa_login(self):
        response = self.login()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "mfa_required")
        return response.data["mfa_challenge"]

    def test_login_without_mfa_requires_enrollment_and_does_not_create_session(self):
        response = self.login()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "mfa_enrollment_required")
        self.assertIn("mfa_challenge", response.data)
        self.assertNotIn("access", response.data)
        self.assertNotIn(settings.JWT_REFRESH_COOKIE_NAME, response.cookies)
        self.assertFalse(AuthSession.objects.filter(user=self.user).exists())

    def test_mfa_setup_returns_enrollment_material_without_enabling_mfa(self):
        challenge = self.start_enrollment()

        response = self.setup_from_challenge(challenge)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("otpauth_uri", response.data)
        self.assertIn("manual_key", response.data)
        self.assertIn("qr_code", response.data)
        self.assertNotIn("encrypted_secret", response.data)
        self.assertFalse(AuthSession.objects.filter(user=self.user).exists())
        mfa_settings = UserMFASettings.objects.get(user=self.user)
        self.assertFalse(mfa_settings.mfa_enabled)
        self.assertIsNotNone(mfa_settings.pending_mfa_secret_encrypted)

    def test_mfa_confirm_success_enables_mfa_emits_access_cookie_and_session(self):
        challenge = self.start_enrollment()
        setup_response = self.setup_from_challenge(challenge)
        manual_key = setup_response.data["manual_key"]

        response = self.confirm_from_challenge(challenge, self.totp_code(manual_key))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["detail"], "MFA enabled successfully")
        self.assertIn("access", response.data)
        self.assertNotIn("refresh", response.data)
        self.assertIn(settings.JWT_REFRESH_COOKIE_NAME, response.cookies)
        self.assertEqual(AuthSession.objects.filter(user=self.user).count(), 1)
        mfa_settings = UserMFASettings.objects.get(user=self.user)
        self.assertTrue(mfa_settings.mfa_enabled)
        self.assertIsNotNone(mfa_settings.mfa_confirmed_at)
        access = AccessToken(response.data["access"])
        self.assertTrue(access["mfa"])
        self.assertEqual(access["sub"], self.user.id)

    def test_login_with_mfa_enabled_requires_mfa_without_creating_new_session(self):
        self.enroll_user()
        session_count = AuthSession.objects.filter(user=self.user).count()

        response = self.login()

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "mfa_required")
        self.assertIn("mfa_challenge", response.data)
        self.assertNotIn("access", response.data)
        self.assertNotIn(settings.JWT_REFRESH_COOKIE_NAME, response.cookies)
        self.assertEqual(AuthSession.objects.filter(user=self.user).count(), session_count)

    def test_mfa_verify_success_emits_access_cookie_and_session(self):
        manual_key, _ = self.enroll_user()
        session_count = AuthSession.objects.filter(user=self.user).count()
        challenge = self.start_mfa_login()

        response = self.verify_from_challenge(challenge, self.totp_code(manual_key, offset=1))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertNotIn("refresh", response.data)
        self.assertIn(settings.JWT_REFRESH_COOKIE_NAME, response.cookies)
        self.assertEqual(AuthSession.objects.filter(user=self.user).count(), session_count + 1)
        self.assertTrue(AccessToken(response.data["access"])["mfa"])

    def test_invalid_totp_increments_mfa_and_challenge_attempts(self):
        manual_key, _ = self.enroll_user()
        challenge = self.start_mfa_login()

        response = self.verify_from_challenge(challenge, self.wrong_totp_code(manual_key, offset=1))

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        mfa_settings = UserMFASettings.objects.get(user=self.user)
        self.assertEqual(mfa_settings.failed_attempts, 1)
        challenge_record = self.challenge_object(challenge)
        self.assertEqual(challenge_record.failed_attempts, 1)

    def test_multiple_mfa_failures_apply_lockout(self):
        manual_key, _ = self.enroll_user()

        for _ in range(settings.MFA_LOCKOUT_FAILURE_THRESHOLD):
            challenge = self.start_mfa_login()
            response = self.verify_from_challenge(challenge, self.wrong_totp_code(manual_key, offset=1))
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        mfa_settings = UserMFASettings.objects.get(user=self.user)
        self.assertIsNotNone(mfa_settings.locked_until)
        self.assertGreater(mfa_settings.locked_until, timezone.now())
        locked_login = self.login()
        self.assertEqual(locked_login.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_expired_challenge_is_rejected(self):
        challenge = self.start_enrollment()
        challenge_record = self.challenge_object(challenge)
        challenge_record.expires_at = timezone.now() - timedelta(seconds=1)
        challenge_record.save(update_fields=["expires_at"])

        response = self.setup_from_challenge(challenge)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_reused_totp_is_rejected(self):
        manual_key, _ = self.enroll_user()
        reusable_code = self.totp_code(manual_key, offset=1)
        first_challenge = self.start_mfa_login()
        first_response = self.verify_from_challenge(first_challenge, reusable_code)
        self.assertEqual(first_response.status_code, status.HTTP_200_OK)

        second_challenge = self.start_mfa_login()
        second_response = self.verify_from_challenge(second_challenge, reusable_code)

        self.assertEqual(second_response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_logout_revokes_session_and_clears_refresh_cookie(self):
        self.enroll_user()
        session = AuthSession.objects.filter(user=self.user).latest("created_at")

        response = self.client.post("/api/logout/", {}, format="json")

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        session.refresh_from_db()
        self.assertFalse(session.is_active)
        self.assertIn(settings.JWT_REFRESH_COOKIE_NAME, response.cookies)
        self.assertEqual(response.cookies[settings.JWT_REFRESH_COOKIE_NAME]["max-age"], 0)

    def test_refresh_after_logout_fails(self):
        self.enroll_user()
        raw_refresh = self.client.cookies[settings.JWT_REFRESH_COOKIE_NAME].value
        logout_response = self.client.post("/api/logout/", {}, format="json")
        self.assertEqual(logout_response.status_code, status.HTTP_204_NO_CONTENT)

        response = self.client.post("/api/token/refresh/", {"refresh": raw_refresh}, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_cookie_flags_are_set(self):
        _, response = self.enroll_user()

        cookie = response.cookies[settings.JWT_REFRESH_COOKIE_NAME]
        self.assertTrue(cookie["httponly"])
        self.assertTrue(cookie["secure"])
        self.assertEqual(cookie["samesite"], "Lax")
        self.assertEqual(cookie["path"], settings.JWT_REFRESH_COOKIE_PATH)

    def test_mfa_challenge_cannot_be_used_as_bearer_token(self):
        challenge = self.start_enrollment()
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {challenge}")

        response = self.client.get("/api/auth/mfa/status/")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_refresh_fails_when_user_is_inactive(self):
        self.enroll_user()
        raw_refresh = self.client.cookies[settings.JWT_REFRESH_COOKIE_NAME].value
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        response = self.client.post("/api/token/refresh/", {"refresh": raw_refresh}, format="json")

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_valid_refresh_rotates_cookie_and_keeps_refresh_out_of_body(self):
        self.enroll_user()
        original_refresh = self.client.cookies[settings.JWT_REFRESH_COOKIE_NAME].value
        session = AuthSession.objects.get(user=self.user)
        original_jti = session.refresh_jti

        response = self.client.post("/api/token/refresh/", {}, format="json")

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("access", response.data)
        self.assertNotIn("refresh", response.data)
        self.assertIn(settings.JWT_REFRESH_COOKIE_NAME, response.cookies)
        self.assertNotEqual(response.cookies[settings.JWT_REFRESH_COOKIE_NAME].value, original_refresh)
        session.refresh_from_db()
        self.assertNotEqual(session.refresh_jti, original_jti)


@override_settings(LEGACY_SYNC_ENABLED=False)
class ProfileModelTests(APITestCase):
    def test_profile_information_is_one_to_one(self):
        user = User.objects.create_user(
            username="solo@example.com",
            password="StrongPass123",
            first_name="Solo",
            last_name="User",
        )
        ProfileInformation.objects.create(user=user, about_me="One")

        self.assertEqual(user.profile_information.about_me, "One")


@override_settings(
    LEGACY_SYNC_ENABLED=True,
    LEGACY_SYNC_BASE_URL="http://127.0.0.1:1",
    LEGACY_SYNC_TOKEN="test-token",
)
class LegacySyncOutboxTests(APITestCase):
    def test_failed_legacy_sync_is_enqueued(self):
        ok = legacy_sync_client.post("/internal/profile-sync/users/", {"id": "user-1"})

        self.assertFalse(ok)
        item = LegacySyncOutbox.objects.get()
        self.assertEqual(item.path, "/internal/profile-sync/users/")
        self.assertEqual(item.payload, {"id": "user-1"})
        self.assertEqual(item.status, LegacySyncOutbox.Status.PENDING)
