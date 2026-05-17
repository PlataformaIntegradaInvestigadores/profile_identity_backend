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

from .application.use_cases import (
    delete_group,
    delete_profile_information,
    leave_group,
    remove_group_member,
    validate_group_visibility,
)
from .auth_sessions import create_auth_session, revoke_session_for_refresh
from .domain.exceptions import DomainPermissionDenied, DomainRuleViolation, DomainValidationError
from .domain.policies import ensure_can_edit_user
from .models import Group, ProfileInformation, User, UserMFASettings
from .profile_services import ensure_profile_information
from .serializers import (
    GroupDetailSerializer,
    GroupSerializer,
    MFAConfirmSerializer,
    MFASetupSerializer,
    MFAStatusSerializer,
    MFAVerifySerializer,
    ProfileInformationSerializer,
    RegisterSerializer,
    UserGroupSerializer,
    UserListSerializer,
    UserSerializer,
    SessionTokenRefreshSerializer,
    UserTokenObtainPairSerializer,
)


def raise_drf_domain_exception(exc):
    if isinstance(exc, DomainPermissionDenied):
        raise PermissionDenied(str(exc)) from exc
    if isinstance(exc, DomainValidationError):
        raise ValidationError({"detail": str(exc)}) from exc
    raise exc


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
        try:
            ensure_can_edit_user(self.request.user, obj)
        except DomainRuleViolation as exc:
            raise_drf_domain_exception(exc)
        return obj

    def update(self, request, *args, **kwargs):
        kwargs["partial"] = True
        try:
            return super().update(request, *args, **kwargs)
        except DomainRuleViolation as exc:
            raise_drf_domain_exception(exc)


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


class MFASetupView(APIView):
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = MFASetupSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.save(), status=status.HTTP_200_OK)


class MFAConfirmView(APIView):
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = MFAConfirmSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        return issue_final_auth_response(
            user=result["user"],
            request=request,
            extra_data={"detail": result["detail"]},
        )


class MFAVerifyView(APIView):
    authentication_classes = []
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = MFAVerifySerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        return issue_final_auth_response(user=result["user"], request=request)


class MFAStatusView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        mfa_settings, _ = UserMFASettings.objects.get_or_create(user=request.user)
        return Response(MFAStatusSerializer(mfa_settings).data, status=status.HTTP_200_OK)


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
            response = Response({"detail": "Refresh token is required."}, status=status.HTTP_400_BAD_REQUEST)
            clear_refresh_cookie(response)
            return response
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


def issue_final_auth_response(*, user, request, extra_data=None):
    refresh = UserTokenObtainPairSerializer.get_token(user)
    refresh["email"] = user.username
    refresh["mfa"] = True
    raw_refresh = str(refresh)

    create_auth_session(user=user, raw_refresh_token=raw_refresh, request=request)

    response_data = {"access": str(refresh.access_token)}
    if extra_data:
        response_data.update(extra_data)

    response = Response(response_data, status=status.HTTP_200_OK)
    set_refresh_cookie(response, raw_refresh)
    return response


def set_refresh_cookie(response, raw_refresh):
    response.set_cookie(
        settings.JWT_REFRESH_COOKIE_NAME,
        raw_refresh,
        max_age=settings.JWT_REFRESH_COOKIE_MAX_AGE,
        httponly=settings.JWT_REFRESH_COOKIE_HTTPONLY,
        secure=settings.JWT_REFRESH_COOKIE_SECURE,
        samesite=settings.JWT_REFRESH_COOKIE_SAMESITE,
        path=settings.JWT_REFRESH_COOKIE_PATH,
        domain=settings.JWT_REFRESH_COOKIE_DOMAIN,
    )


def clear_refresh_cookie(response):
    response.delete_cookie(
        settings.JWT_REFRESH_COOKIE_NAME,
        path=settings.JWT_REFRESH_COOKIE_PATH,
        samesite=settings.JWT_REFRESH_COOKIE_SAMESITE,
        domain=settings.JWT_REFRESH_COOKIE_DOMAIN,
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
        try:
            serializer.save()
        except DomainRuleViolation as exc:
            raise_drf_domain_exception(exc)

    def perform_destroy(self, instance):
        try:
            delete_profile_information(self.request.user, instance)
        except DomainRuleViolation as exc:
            raise_drf_domain_exception(exc)


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
        try:
            delete_group(request.user, group)
        except DomainRuleViolation as exc:
            raise_drf_domain_exception(exc)
        return Response(status=status.HTTP_204_NO_CONTENT)


class GroupLeaveView(generics.GenericAPIView):
    queryset = Group.objects.all()
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        group = self.get_object()
        try:
            leave_group(request.user, group)
        except DomainRuleViolation as exc:
            raise_drf_domain_exception(exc)
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
        try:
            validate_group_visibility(request.user, group)
        except DomainRuleViolation as exc:
            raise_drf_domain_exception(exc)
        return Response(self.get_serializer(group).data)


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
        try:
            remove_group_member(request.user, group, user_to_remove)
        except DomainRuleViolation as exc:
            raise_drf_domain_exception(exc)
        return Response({"detail": "Member removed successfully."}, status=status.HTTP_200_OK)
