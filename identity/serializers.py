from django.contrib.auth.hashers import make_password
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer

from .auth_sessions import create_auth_session, get_active_session_for_refresh, rotate_auth_session
from .legacy_sync import legacy_sync_client
from .models import Group, ProfileInformation, User
from .profile_services import ensure_profile_information, normalize_contact_info, serialize_profile_for_sync


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
        data = super().validate(attrs)
        request = self.context.get("request")
        create_auth_session(user=self.user, raw_refresh_token=data["refresh"], request=request)
        return data


class SessionTokenRefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        request = self.context.get("request")
        session = get_active_session_for_refresh(attrs["refresh"])
        if session is None:
            raise AuthenticationFailed("Refresh token session is not active.", code="token_not_valid")

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

    def create(self, validated_data):
        validated_data["password"] = make_password(validated_data["password"])
        user = super().create(validated_data)
        legacy_sync_client.post("/internal/profile-sync/users/", serialize_user_for_sync(user))
        ensure_profile_information(user)
        return user


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
        instance = super().update(instance, validated_data)
        legacy_sync_client.post(
            "/internal/profile-sync/profile-information/",
            serialize_profile_for_sync(instance),
        )
        return instance

    def create(self, validated_data):
        instance = super().create(validated_data)
        legacy_sync_client.post(
            "/internal/profile-sync/profile-information/",
            serialize_profile_for_sync(instance),
        )
        return instance


class GroupSerializer(serializers.ModelSerializer):
    users = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(), many=True, required=False)

    class Meta:
        model = Group
        fields = ["id", "title", "description", "admin_id", "users", "voting_type"]
        read_only_fields = ["id", "admin"]

    def create(self, validated_data):
        request = self.context.get("request")
        validated_data["admin"] = request.user
        users = validated_data.pop("users", [])
        group = Group.objects.create(**validated_data)
        group.users.add(request.user)
        group.users.add(*users)
        sync_group(group)
        return group


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


def serialize_user_for_sync(user):
    return {
        "id": user.id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "username": user.username,
        "password": user.password,
        "scopus_id": user.scopus_id,
        "investigation_camp": user.investigation_camp,
        "institution": user.institution,
        "email_institution": user.email_institution,
        "website": user.website,
        "profile_picture": str(user.profile_picture or ""),
        "is_active": user.is_active,
        "is_staff": user.is_staff,
        "interests": user.interests,
        "interaction_count": user.interaction_count,
    }


def serialize_group_for_sync(group):
    return {
        "id": group.id,
        "title": group.title,
        "description": group.description,
        "admin_id": group.admin_id,
        "voting_type": group.voting_type,
        "users": list(group.users.values_list("id", flat=True)),
    }


def sync_group(group):
    legacy_sync_client.post("/internal/profile-sync/groups/", serialize_group_for_sync(group))
    legacy_sync_client.post(
        "/internal/profile-sync/group-memberships/",
        {"group_id": group.id, "users": list(group.users.values_list("id", flat=True))},
    )
