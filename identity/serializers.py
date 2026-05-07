from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer, TokenRefreshSerializer

from .application.use_cases import (
    create_group,
    create_profile_information,
    register_user,
    update_profile_information,
    update_user,
)
from .auth_sessions import create_auth_session, get_active_session_for_refresh, rotate_auth_session
from .models import Group, ProfileInformation, User
from .profile_services import normalize_contact_info


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
