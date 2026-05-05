from django.shortcuts import get_object_or_404
from django.conf import settings
from rest_framework import generics, permissions, status
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed, InvalidToken, TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .auth_sessions import revoke_session_for_refresh
from .legacy_sync import legacy_sync_client
from .models import Group, ProfileInformation, User
from .profile_services import ensure_profile_information
from .serializers import (
    GroupDetailSerializer,
    GroupSerializer,
    ProfileInformationSerializer,
    RegisterSerializer,
    UserGroupSerializer,
    UserListSerializer,
    UserSerializer,
    SessionTokenRefreshSerializer,
    UserTokenObtainPairSerializer,
    sync_group,
)


class HealthLiveView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        return Response({"status": "alive"})


class UserListView(generics.ListAPIView):
    serializer_class = UserListSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return User.objects.exclude(id=self.request.user.id)


class UserUpdateView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)

    def get_object(self):
        obj = super().get_object()
        if obj.id != self.request.user.id:
            raise PermissionDenied("No tienes permiso para editar este usuario.")
        return obj

    def update(self, request, *args, **kwargs):
        kwargs["partial"] = True
        response = super().update(request, *args, **kwargs)
        user = self.get_object()
        legacy_sync_client.post(
            "/internal/profile-sync/users/",
            {
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
            },
        )
        return response


class UserTokenObtainPairView(TokenObtainPairView):
    serializer_class = UserTokenObtainPairSerializer
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        raw_refresh = response.data.get("refresh")
        if raw_refresh:
            set_refresh_cookie(response, raw_refresh)
            response.data.pop("refresh", None)
        return response


class CustomTokenRefreshView(TokenRefreshView):
    serializer_class = SessionTokenRefreshSerializer
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        data = request.data.copy()
        if not data.get("refresh"):
            cookie_refresh = request.COOKIES.get(settings.JWT_REFRESH_COOKIE_NAME)
            if cookie_refresh:
                data["refresh"] = cookie_refresh
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        response = Response(serializer.validated_data, status=status.HTTP_200_OK)
        raw_refresh = response.data.get("refresh")
        if raw_refresh:
            set_refresh_cookie(response, raw_refresh)
            response.data.pop("refresh", None)
        return response


class LogoutView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def post(self, request):
        raw_refresh = request.data.get("refresh") or request.COOKIES.get(settings.JWT_REFRESH_COOKIE_NAME)
        if not raw_refresh:
            return Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            revoke_session_for_refresh(raw_refresh)
            RefreshToken(raw_refresh).blacklist()
        except TokenError:
            response = Response({"detail": "Invalid refresh token."}, status=status.HTTP_400_BAD_REQUEST)
            clear_refresh_cookie(response)
            return response
        response = Response(status=status.HTTP_204_NO_CONTENT)
        clear_refresh_cookie(response)
        return response


class ValidateTokenView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def get(self, request):
        try:
            authentication_result = JWTAuthentication().authenticate(request)
        except (AuthenticationFailed, InvalidToken, TokenError):
            return Response({"detail": "Invalid or expired token."}, status=status.HTTP_401_UNAUTHORIZED)
        if authentication_result is None:
            return Response({"detail": "Authentication credentials were not provided."}, status=status.HTTP_401_UNAUTHORIZED)
        user, validated_token = authentication_result
        if not user or not user.is_authenticated:
            return Response({"detail": "Invalid token user."}, status=status.HTTP_401_UNAUTHORIZED)
        if not user.is_active:
            return Response({"detail": "Inactive user."}, status=status.HTTP_403_FORBIDDEN)

        response = Response(status=status.HTTP_204_NO_CONTENT)
        response["X-Authenticated-User-Id"] = str(user.id)
        response["X-Authenticated-Token-Type"] = str(validated_token.get("token_type", ""))
        return response


def set_refresh_cookie(response, raw_refresh):
    response.set_cookie(
        settings.JWT_REFRESH_COOKIE_NAME,
        raw_refresh,
        max_age=int(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds()),
        httponly=settings.JWT_REFRESH_COOKIE_HTTPONLY,
        secure=settings.JWT_REFRESH_COOKIE_SECURE,
        samesite=settings.JWT_REFRESH_COOKIE_SAMESITE,
        path=settings.JWT_REFRESH_COOKIE_PATH,
    )


def clear_refresh_cookie(response):
    response.delete_cookie(
        settings.JWT_REFRESH_COOKIE_NAME,
        path=settings.JWT_REFRESH_COOKIE_PATH,
        samesite=settings.JWT_REFRESH_COOKIE_SAMESITE,
    )


class UserDetailView(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)
        except ValidationError:
            return Response({"errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as exc:
            return Response({"error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ProfileInformationDetailView(generics.RetrieveUpdateDestroyAPIView):
    queryset = ProfileInformation.objects.all()
    serializer_class = ProfileInformationSerializer
    permission_classes = [permissions.IsAuthenticatedOrReadOnly]

    def get_object(self):
        return ensure_profile_information(self.request.user)

    def perform_update(self, serializer):
        if self.request.user.id != serializer.instance.user.id:
            raise PermissionDenied("No tienes permiso para editar este perfil.")
        serializer.save()

    def perform_destroy(self, instance):
        if self.request.user.id != instance.user.id:
            raise PermissionDenied("No tienes permiso para eliminar este perfil.")
        if not instance.about_me and not instance.disciplines and not instance.contact_info:
            instance.delete()
            legacy_sync_client.post(
                "/internal/profile-sync/profile-information/",
                {"user_id": instance.user_id, "deleted": True},
            )
        else:
            return Response(
                {"detail": "La informacion del perfil debe estar vacia para ser eliminada."},
                status=status.HTTP_400_BAD_REQUEST,
            )


class PublicProfileInformationDetailView(generics.RetrieveAPIView):
    queryset = ProfileInformation.objects.all()
    serializer_class = ProfileInformationSerializer
    permission_classes = [permissions.AllowAny]
    lookup_field = "user__id"

    def get_object(self):
        user = get_object_or_404(User, id=self.kwargs["user__id"])
        return ensure_profile_information(user)


class GroupListCreateView(generics.ListCreateAPIView):
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAuthenticated]


class UserGroupsListView(generics.ListAPIView):
    serializer_class = UserGroupSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Group.objects.filter(users=self.request.user)


class GroupDeleteView(generics.DestroyAPIView):
    queryset = Group.objects.all()
    serializer_class = GroupSerializer
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        group = self.get_object()
        if group.admin != request.user:
            return Response({"detail": "You do not have permission to delete this group."}, status=status.HTTP_403_FORBIDDEN)
        group_id = group.id
        response = self.destroy(request, *args, **kwargs)
        legacy_sync_client.post("/internal/profile-sync/groups/", {"id": group_id, "deleted": True})
        return response


class GroupLeaveView(generics.GenericAPIView):
    queryset = Group.objects.all()
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        group = self.get_object()
        if request.user == group.admin:
            return Response({"detail": "Admin cannot leave the group. You must delete the group."}, status=status.HTTP_400_BAD_REQUEST)
        group.users.remove(request.user)
        sync_group(group)
        return Response({"detail": "You have left the group."}, status=status.HTTP_200_OK)


class UserDetailViewtoGroup(generics.RetrieveAPIView):
    queryset = User.objects.all()
    serializer_class = UserListSerializer
    permission_classes = [permissions.IsAuthenticated]


class GroupDetailView(generics.RetrieveAPIView):
    queryset = Group.objects.all()
    serializer_class = GroupDetailSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, *args, **kwargs):
        group = self.get_object()
        if group.admin == request.user or group.users.filter(id=request.user.id).exists():
            return Response(self.get_serializer(group).data)
        raise PermissionDenied("You do not have permission to access this group.")


class RemoveMemberView(generics.GenericAPIView):
    queryset = Group.objects.all()
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, *args, **kwargs):
        group = self.get_object()
        user_id = self.kwargs.get("user_id")
        try:
            user_to_remove = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({"detail": "User does not exist."}, status=status.HTTP_404_NOT_FOUND)
        if group.admin != request.user:
            return Response({"detail": "You do not have permission to remove this member."}, status=status.HTTP_403_FORBIDDEN)
        if user_to_remove == request.user:
            return Response({"detail": "You cannot remove yourself from the group."}, status=status.HTTP_400_BAD_REQUEST)
        group.users.remove(user_to_remove)
        sync_group(group)
        return Response({"detail": "Member removed successfully."}, status=status.HTTP_200_OK)
