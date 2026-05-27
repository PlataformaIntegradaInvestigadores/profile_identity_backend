from dataclasses import dataclass
from datetime import datetime, timedelta

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import User


@dataclass(frozen=True)
class PasswordFailureResult:
    failed_attempts: int
    locked_until: datetime | None


def get_user_for_password_lockout(username: str | None) -> User | None:
    if not username:
        return None
    return User.objects.filter(username__iexact=str(username).strip()).first()


def is_password_locked(user: User) -> bool:
    return user.password_locked_until is not None and user.password_locked_until > timezone.now()


def reset_password_failures(user: User) -> None:
    update_fields = []
    if user.failed_login_attempts != 0:
        user.failed_login_attempts = 0
        update_fields.append("failed_login_attempts")
    if user.password_locked_until is not None:
        user.password_locked_until = None
        update_fields.append("password_locked_until")
    if update_fields:
        user.save(update_fields=update_fields)


@transaction.atomic
def record_password_failure(user: User) -> PasswordFailureResult:
    locked_user = User.objects.select_for_update().get(pk=user.pk)
    locked_user.failed_login_attempts += 1
    lockout_minutes = _lockout_minutes_for_failures(locked_user.failed_login_attempts)
    if lockout_minutes is not None:
        locked_user.password_locked_until = timezone.now() + timedelta(minutes=lockout_minutes)
    locked_user.save(update_fields=["failed_login_attempts", "password_locked_until"])
    return PasswordFailureResult(
        failed_attempts=locked_user.failed_login_attempts,
        locked_until=locked_user.password_locked_until,
    )


def _lockout_minutes_for_failures(failed_attempts: int) -> int | None:
    threshold = settings.AUTH_PASSWORD_LOCKOUT_FAILURE_THRESHOLD
    if threshold <= 0 or failed_attempts < threshold:
        return None

    schedule = settings.AUTH_PASSWORD_LOCKOUT_MINUTES
    if not schedule:
        return None

    schedule_index = min((failed_attempts - threshold) // threshold, len(schedule) - 1)
    return schedule[schedule_index]
