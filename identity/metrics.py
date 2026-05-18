from __future__ import annotations

from django.conf import settings
from django.http import HttpResponse


try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
except ImportError:  # pragma: no cover - used only before dependencies are installed.
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
    Counter = Gauge = Histogram = None
    generate_latest = None


_PROMETHEUS_AVAILABLE = generate_latest is not None

if _PROMETHEUS_AVAILABLE:
    HTTP_REQUESTS_TOTAL = Counter(
        "identity_http_requests_total",
        "Total HTTP requests handled by the identity microservice.",
        ["method", "route", "status_code"],
    )
    HTTP_REQUEST_DURATION_SECONDS = Histogram(
        "identity_http_request_duration_seconds",
        "HTTP request duration in seconds for the identity microservice.",
        ["method", "route"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
    )
    SECURITY_EVENTS_TOTAL = Counter(
        "identity_security_events_total",
        "Total structured security events emitted by the identity microservice.",
        ["event_type", "severity", "outcome"],
    )
    SERVICE_UP = Gauge(
        "identity_service_up",
        "Identity microservice metrics endpoint availability.",
        ["service", "environment"],
    )


def record_http_request(*, request, response, duration_seconds: float) -> None:
    if not _PROMETHEUS_AVAILABLE:
        return
    route = _route_label(request)
    method = getattr(request, "method", "UNKNOWN")
    status_code = str(getattr(response, "status_code", 0))
    HTTP_REQUESTS_TOTAL.labels(method=method, route=route, status_code=status_code).inc()
    HTTP_REQUEST_DURATION_SECONDS.labels(method=method, route=route).observe(duration_seconds)


def record_security_event(*, event_type: str, severity: str, outcome: str) -> None:
    if not _PROMETHEUS_AVAILABLE:
        return
    SECURITY_EVENTS_TOTAL.labels(event_type=event_type, severity=severity, outcome=outcome).inc()


def prometheus_metrics_response() -> HttpResponse:
    service = getattr(settings, "SECURITY_LOG_SERVICE_NAME", "identity-backend")
    environment = getattr(settings, "SECURITY_LOG_ENVIRONMENT", "dev")
    if not getattr(settings, "METRICS_ENABLED", True):
        return HttpResponse("metrics disabled\n", status=404, content_type="text/plain; charset=utf-8")
    if not _PROMETHEUS_AVAILABLE:
        payload = (
            "# HELP identity_service_up Identity microservice metrics endpoint availability.\n"
            "# TYPE identity_service_up gauge\n"
            f'identity_service_up{{service="{service}",environment="{environment}"}} 1\n'
        )
        return HttpResponse(payload, content_type=CONTENT_TYPE_LATEST)

    SERVICE_UP.labels(service=service, environment=environment).set(1)
    return HttpResponse(generate_latest(), content_type=CONTENT_TYPE_LATEST)


def _route_label(request) -> str:
    resolver_match = getattr(request, "resolver_match", None)
    route = getattr(resolver_match, "route", None)
    if route:
        return "/" + route.lstrip("/")
    return getattr(request, "path", "unknown")
