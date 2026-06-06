import logging

import requests
from django.conf import settings
from django.utils import timezone


logger = logging.getLogger(__name__)


class LegacySyncClient:
    def __init__(self):
        self.base_url = settings.LEGACY_SYNC_BASE_URL
        self.token = settings.LEGACY_SYNC_TOKEN
        self.enabled = settings.LEGACY_SYNC_ENABLED and bool(self.base_url and self.token)

    def post(self, path, payload, *, enqueue_on_failure=True):
        base_url = settings.LEGACY_SYNC_BASE_URL.rstrip("/")
        token = settings.LEGACY_SYNC_TOKEN
        enabled = settings.LEGACY_SYNC_ENABLED and bool(base_url and token)
        if not enabled:
            return True
        return send_legacy_sync(path, payload, enqueue_on_failure=enqueue_on_failure)


def send_legacy_sync(path, payload, *, enqueue_on_failure=True):
    base_url = settings.LEGACY_SYNC_BASE_URL.rstrip("/")
    token = settings.LEGACY_SYNC_TOKEN
    enabled = settings.LEGACY_SYNC_ENABLED and bool(base_url and token)
    if not enabled:
        return True

    url = f"{base_url}{path}"
    try:
        response = requests.post(
            url,
            json=payload,
            headers={"X-Internal-Sync-Token": token},
            timeout=5,
        )
        if response.status_code == 410:
            logger.info("Legacy sync endpoint retired for %s; event treated as completed.", path)
            return True
        response.raise_for_status()
        return True
    except requests.RequestException as exc:
        logger.error("Legacy sync failed for %s: %s", path, exc)
        if enqueue_on_failure:
            enqueue_legacy_sync(path, payload, str(exc))
        return False


def enqueue_legacy_sync(path, payload, error):
    from .models import LegacySyncOutbox

    LegacySyncOutbox.objects.create(
        path=path,
        payload=payload,
        status=LegacySyncOutbox.Status.PENDING,
        attempts=1,
        last_error=error,
        next_retry_at=timezone.now(),
    )


def retry_outbox_item(item):
    from .models import LegacySyncOutbox

    item.status = LegacySyncOutbox.Status.PROCESSING
    item.save(update_fields=["status", "updated_at"])
    try:
        ok = send_legacy_sync(item.path, item.payload, enqueue_on_failure=False)
        if ok:
            item.status = LegacySyncOutbox.Status.COMPLETED
            item.completed_at = timezone.now()
            item.last_error = ""
            item.save(update_fields=["status", "completed_at", "last_error", "updated_at"])
            return True
    except Exception as exc:
        item.last_error = str(exc)

    item.status = LegacySyncOutbox.Status.FAILED
    item.attempts += 1
    item.next_retry_at = timezone.now() + settings.LEGACY_SYNC_RETRY_DELAY
    item.save(update_fields=["status", "attempts", "last_error", "next_retry_at", "updated_at"])
    return False


legacy_sync_client = LegacySyncClient()
