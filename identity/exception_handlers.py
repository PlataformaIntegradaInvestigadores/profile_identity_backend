from rest_framework.exceptions import AuthenticationFailed, NotAuthenticated
from rest_framework.views import exception_handler
from rest_framework_simplejwt.exceptions import InvalidToken

from .security_events import emit_security_event


def security_exception_handler(exc, context):
    response = exception_handler(exc, context)
    request = context.get("request")

    if response is not None and _should_log_invalid_token(exc, request):
        emit_security_event(
            event_type="invalid_token",
            severity="warning",
            outcome="failure",
            request=request,
            status_code=response.status_code,
            reason="invalid_or_missing_token",
        )

    return response


def _should_log_invalid_token(exc, request):
    if request is None:
        return False
    if not isinstance(exc, (AuthenticationFailed, InvalidToken, NotAuthenticated)):
        return False

    path = getattr(request, "path", "")
    excluded_paths = (
        "/api/token/",
        "/api/token/refresh/",
        "/api/logout/",
        "/api/auth/mfa/setup/",
        "/api/auth/mfa/confirm/",
        "/api/auth/mfa/verify/",
    )
    return path not in excluded_paths
