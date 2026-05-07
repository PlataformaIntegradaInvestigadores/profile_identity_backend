from identity.domain.events import (
    GroupCreated,
    GroupDeleted,
    GroupMembershipChanged,
    ProfileInformationDeleted,
    ProfileInformationUpdated,
    UserRegistered,
    UserUpdated,
)
from identity.legacy_sync import legacy_sync_client
from identity.models import Group, ProfileInformation, User
from identity.profile_services import normalize_contact_info


def handle_legacy_sync_event(event):
    if isinstance(event, (UserRegistered, UserUpdated)):
        user = User.objects.get(id=event.user_id)
        legacy_sync_client.post("/internal/profile-sync/users/", serialize_user_for_sync(user))
        return

    if isinstance(event, ProfileInformationUpdated):
        profile = ProfileInformation.objects.get(user_id=event.user_id)
        legacy_sync_client.post("/internal/profile-sync/profile-information/", serialize_profile_for_sync(profile))
        return

    if isinstance(event, ProfileInformationDeleted):
        legacy_sync_client.post(
            "/internal/profile-sync/profile-information/",
            {"user_id": event.user_id, "deleted": True},
        )
        return

    if isinstance(event, GroupCreated):
        group = Group.objects.get(id=event.group_id)
        sync_group(group)
        return

    if isinstance(event, GroupMembershipChanged):
        group = Group.objects.get(id=event.group_id)
        sync_group(group)
        return

    if isinstance(event, GroupDeleted):
        legacy_sync_client.post("/internal/profile-sync/groups/", {"id": event.group_id, "deleted": True})


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


def serialize_profile_for_sync(profile):
    return {
        "user_id": profile.user_id,
        "about_me": profile.about_me,
        "disciplines": profile.disciplines,
        "contact_info": normalize_contact_info(profile.contact_info),
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
