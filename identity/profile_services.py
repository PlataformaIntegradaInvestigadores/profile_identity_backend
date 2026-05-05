from .legacy_sync import legacy_sync_client
from .models import ProfileInformation, User


def normalize_contact_info(value):
    if isinstance(value, list):
        return value
    if not value:
        return []
    if isinstance(value, dict):
        if "type" in value and "value" in value:
            return [value]
        return [{"type": key, "value": item} for key, item in value.items() if item]
    return []


def serialize_profile_for_sync(profile):
    return {
        "user_id": profile.user_id,
        "about_me": profile.about_me,
        "disciplines": profile.disciplines,
        "contact_info": normalize_contact_info(profile.contact_info),
    }


def ensure_profile_information(user, sync_legacy=True):
    profile, created = ProfileInformation.objects.get_or_create(
        user=user,
        defaults={"about_me": "", "disciplines": [], "contact_info": []},
    )
    if created and sync_legacy:
        legacy_sync_client.post(
            "/internal/profile-sync/profile-information/",
            serialize_profile_for_sync(profile),
        )
    return profile


def backfill_missing_profile_information(sync_legacy=True):
    created = 0
    users_without_profile = User.objects.filter(profile_information__isnull=True)
    for user in users_without_profile.iterator():
        ensure_profile_information(user, sync_legacy=sync_legacy)
        created += 1
    return created
