from django.contrib.auth.hashers import make_password
from django.db import transaction

from identity.domain.events import (
    GroupCreated,
    GroupDeleted,
    GroupMembershipChanged,
    ProfileInformationDeleted,
    ProfileInformationUpdated,
    UserRegistered,
    UserUpdated,
)
from identity.domain.policies import (
    ensure_can_delete_group,
    ensure_can_delete_profile,
    ensure_can_edit_profile,
    ensure_can_edit_user,
    ensure_can_leave_group,
    ensure_can_remove_group_member,
    ensure_can_view_group,
)
from identity.infrastructure.legacy_event_handlers import handle_legacy_sync_event
from identity.models import Group, ProfileInformation, User
from identity.profile_services import ensure_profile_information


def publish_events(events):
    for event in events:
        handle_legacy_sync_event(event)


@transaction.atomic
def register_user(validated_data):
    user_data = validated_data.copy()
    user_data["password"] = make_password(user_data["password"])
    user = User.objects.create(**user_data)
    ensure_profile_information(user, sync_legacy=False)
    publish_events([UserRegistered(user.id), ProfileInformationUpdated(user.id)])
    return user


@transaction.atomic
def update_user(actor, user, validated_data):
    ensure_can_edit_user(actor, user)
    for field, value in validated_data.items():
        setattr(user, field, value)
    user.save()
    publish_events([UserUpdated(user.id)])
    return user


@transaction.atomic
def update_profile_information(actor, profile, validated_data):
    ensure_can_edit_profile(actor, profile)
    for field, value in validated_data.items():
        setattr(profile, field, value)
    profile.save()
    publish_events([ProfileInformationUpdated(profile.user_id)])
    return profile


@transaction.atomic
def create_profile_information(validated_data):
    profile = ProfileInformation.objects.create(**validated_data)
    publish_events([ProfileInformationUpdated(profile.user_id)])
    return profile


@transaction.atomic
def delete_profile_information(actor, profile):
    ensure_can_delete_profile(actor, profile)
    user_id = profile.user_id
    profile.delete()
    publish_events([ProfileInformationDeleted(user_id)])


@transaction.atomic
def create_group(admin, validated_data):
    group_data = validated_data.copy()
    users = group_data.pop("users", [])
    group = Group.objects.create(admin=admin, **group_data)
    group.users.add(admin)
    group.users.add(*users)
    publish_events([GroupCreated(group.id)])
    return group


@transaction.atomic
def delete_group(actor, group):
    ensure_can_delete_group(actor, group)
    group_id = group.id
    group.delete()
    publish_events([GroupDeleted(group_id)])


@transaction.atomic
def leave_group(actor, group):
    ensure_can_leave_group(actor, group)
    group.users.remove(actor)
    publish_events([GroupMembershipChanged(group.id)])


@transaction.atomic
def remove_group_member(actor, group, member):
    ensure_can_remove_group_member(actor, group, member)
    group.users.remove(member)
    publish_events([GroupMembershipChanged(group.id)])


def validate_group_visibility(actor, group):
    ensure_can_view_group(actor, group)
