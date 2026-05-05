from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from identity.legacy_sync import retry_outbox_item
from identity.models import LegacySyncOutbox


class Command(BaseCommand):
    help = "Retry pending or failed legacy synchronization outbox records."

    def add_arguments(self, parser):
        parser.add_argument("--limit", type=int, default=50)

    def handle(self, *args, **options):
        limit = options["limit"]
        candidates = (
            LegacySyncOutbox.objects.filter(
                status__in=[LegacySyncOutbox.Status.PENDING, LegacySyncOutbox.Status.FAILED],
                next_retry_at__lte=timezone.now(),
            )
            .order_by("created_at")
            .values_list("id", flat=True)[:limit]
        )

        completed = 0
        failed = 0
        for item_id in candidates:
            with transaction.atomic():
                item = LegacySyncOutbox.objects.select_for_update().get(id=item_id)
                if item.status not in {LegacySyncOutbox.Status.PENDING, LegacySyncOutbox.Status.FAILED}:
                    continue
                ok = retry_outbox_item(item)
            if ok:
                completed += 1
            else:
                failed += 1

        self.stdout.write(
            self.style.SUCCESS(
                f"legacy_sync_outbox processed={completed + failed} completed={completed} failed={failed}"
            )
        )
