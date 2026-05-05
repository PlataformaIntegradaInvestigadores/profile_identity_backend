from django.test import override_settings
from rest_framework import status
from rest_framework.test import APITestCase

from identity.legacy_sync import legacy_sync_client
from identity.models import AuthSession, Group, LegacySyncOutbox, ProfileInformation, User


@override_settings(LEGACY_SYNC_ENABLED=False)
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
