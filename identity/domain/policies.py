from .exceptions import DomainPermissionDenied, DomainValidationError


def ensure_can_edit_user(actor, target_user):
    if actor.id != target_user.id:
        raise DomainPermissionDenied("No tienes permiso para editar este usuario.")


def ensure_can_edit_profile(actor, profile):
    if actor.id != profile.user_id:
        raise DomainPermissionDenied("No tienes permiso para editar este perfil.")


def ensure_can_delete_profile(actor, profile):
    ensure_can_edit_profile(actor, profile)
    if profile.about_me or profile.disciplines or profile.contact_info:
        raise DomainValidationError("La informacion del perfil debe estar vacia para ser eliminada.")


def ensure_can_delete_group(actor, group):
    if group.admin_id != actor.id:
        raise DomainPermissionDenied("You do not have permission to delete this group.")


def ensure_can_leave_group(actor, group):
    if group.admin_id == actor.id:
        raise DomainValidationError("Admin cannot leave the group. You must delete the group.")


def ensure_can_view_group(actor, group):
    if group.admin_id == actor.id or group.users.filter(id=actor.id).exists():
        return
    raise DomainPermissionDenied("You do not have permission to access this group.")


def ensure_can_remove_group_member(actor, group, member):
    if group.admin_id != actor.id:
        raise DomainPermissionDenied("You do not have permission to remove this member.")
    if member.id == actor.id:
        raise DomainValidationError("You cannot remove yourself from the group.")
