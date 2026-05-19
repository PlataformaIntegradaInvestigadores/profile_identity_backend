import uuid
from time import monotonic

from django.conf import settings

from .metrics import record_http_request


class RequestIDMiddleware:
    header_name = "HTTP_X_REQUEST_ID"
    response_header_name = "X-Request-ID"
    max_length = 128

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        request_id = self._request_id_from_header(request) or self._generate_request_id()
        request.request_id = request_id

        response = self.get_response(request)
        response[self.response_header_name] = request_id
        return response

    def _request_id_from_header(self, request):
        value = request.META.get(self.header_name, "").strip()
        if not value:
            return None
        return value[: self.max_length]

    def _generate_request_id(self):
        return f"req-{uuid.uuid4().hex}"


class PrometheusMetricsMiddleware:
    excluded_paths = {"/internal/metrics/"}

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        started_at = monotonic()
        response = self.get_response(request)
        if getattr(settings, "METRICS_ENABLED", True) and request.path not in self.excluded_paths:
            record_http_request(
                request=request,
                response=response,
                duration_seconds=monotonic() - started_at,
            )
        return response
