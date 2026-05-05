from django.urls import path, re_path

from .views import (
    CustomTokenRefreshView,
    GroupDeleteView,
    GroupDetailView,
    GroupLeaveView,
    LogoutView,
    GroupListCreateView,
    ProfileInformationDetailView,
    PublicProfileInformationDetailView,
    RegisterView,
    RemoveMemberView,
    UserDetailView,
    UserDetailViewtoGroup,
    UserGroupsListView,
    UserListView,
    UserTokenObtainPairView,
    UserUpdateView,
)


urlpatterns = [
    path("token/", UserTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", CustomTokenRefreshView.as_view(), name="token_refresh"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("register/", RegisterView.as_view(), name="register"),
    re_path(r"^users/(?P<pk>[a-zA-Z0-9]+)/$", UserDetailView.as_view(), name="user-detail"),
    re_path(r"^users/(?P<pk>[a-zA-Z0-9]+)/update/$", UserUpdateView.as_view(), name="user-update"),
    path("users/", UserListView.as_view(), name="user-list"),
    path("groups/", GroupListCreateView.as_view(), name="group-list-create"),
    path("profile-information/", ProfileInformationDetailView.as_view(), name="profile-information-detail"),
    path(
        "profile-information/<str:user__id>/",
        PublicProfileInformationDetailView.as_view(),
        name="public-profile-information-detail",
    ),
    path("test/user/groups/", UserGroupsListView.as_view(), name="test-user-groups-list"),
    path("test/user/groups/<pk>/delete/", GroupDeleteView.as_view(), name="group-delete"),
    path("test/user/groups/<pk>/leave/", GroupLeaveView.as_view(), name="group-leave"),
    path("test/users/groups/<str:pk>/", UserDetailViewtoGroup.as_view(), name="user-detail-group"),
    path("groups/<str:pk>/", GroupDetailView.as_view(), name="group-detail"),
    path("groups/<str:pk>/remove-member/<str:user_id>/", RemoveMemberView.as_view(), name="remove-member"),
]
