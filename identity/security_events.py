import json
import logging

from django.conf import settings
from django.utils import timezone

from .metrics import record_security_event


SECURITY_LOGGER_NAME = "security.events"
SECURITY_LOGGER = logging.getLogger(SECURITY_LOGGER_NAME)
SENSITIVE_FIELD_NAMES = {
    "password",
    "code",
    "totp",
    "totp_code",
    "mfa_secret",
    "mfa_challenge",
    "access",
    "access_token",
    "refresh",
    "refresh_token",
    "cookie",
    "cookies",
    "authorization",
    "api_key",
    "secret",
}


def emit_security_event(
    *,
    event_type,
    severity,
    outcome,
    request=None,
    status_code=None,
    user=None,
    reason=None,
    **extra_fields,
):
    event = {
        "timestamp": _utc_timestamp(),
        "service": getattr(settings, "SECURITY_LOG_SERVICE_NAME", "identity-backend"),
        "environment": getattr(settings, "SECURITY_LOG_ENVIRONMENT", "dev"),
        "event_type": event_type,
        "severity": severity,
        "outcome": outcome,
        "request_id": _request_id(request),
        "path": getattr(request, "path", None),
        "method": getattr(request, "method", None),
        "status_code": status_code,
    }
    event.update(_request_actor_fields(request=request, user=user))
    if reason:
        event["reason"] = str(reason)
    for key, value in extra_fields.items():
        if key not in SENSITIVE_FIELD_NAMES and value is not None:
            event[key] = value

    SECURITY_LOGGER.log(_level_for_severity(severity), json.dumps(_compact(event), ensure_ascii=True, sort_keys=True))
    record_security_event(event_type=event_type, severity=severity, outcome=outcome)


def _utc_timestamp():
    return timezone.now().isoformat().replace("+00:00", "Z")


def _request_id(request):
    if request is None:
        return None
    return getattr(request, "request_id", None) or request.META.get("HTTP_X_REQUEST_ID")


def _request_actor_fields(*, request=None, user=None):
    actor = user
    if actor is None and request is not None:
        request_user = getattr(request, "user", None)
        if getattr(request_user, "is_authenticated", False):
            actor = request_user

    fields = {
        "ip": _client_ip(request),
        "user_agent": _user_agent(request),
    }
    if actor is not None:
        fields["user_id"] = str(getattr(actor, "id", ""))
        if getattr(settings, "SECURITY_LOG_INCLUDE_USERNAME", True):
            fields["username"] = getattr(actor, "username", None)
    return fields


def _client_ip(request):
    if request is None:
        return None
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded_for:
        return forwarded_for.split(",", 1)[0].strip()
    return request.META.get("REMOTE_ADDR")


def _user_agent(request):
    if request is None:
        return None
    return request.META.get("HTTP_USER_AGENT", "")[:512]


def _compact(event):
    return {key: value for key, value in event.items() if value not in (None, "")}


def _level_for_severity(severity):
    return {
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL,
    }.get(severity, logging.INFO)
