import json

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from identity.models import Group, ProfileInformation, User
from identity.profile_services import backfill_missing_profile_information


class Command(BaseCommand):
    help = "Importa un JSON exportado desde el monolito hacia el microservicio de identidad."

    def add_arguments(self, parser):
        parser.add_argument("path", help="Ruta del archivo JSON con users, profiles, groups y group_memberships.")

    @transaction.atomic
    def handle(self, *args, **options):
        try:
            with open(options["path"], encoding="utf-8") as source:
                payload = json.load(source)
        except OSError as exc:
            raise CommandError(f"No se pudo abrir el archivo: {exc}") from exc

        for item in payload.get("users", []):
            user_id = item["id"]
            defaults = {key: value for key, value in item.items() if key != "id"}
            User.objects.update_or_create(id=user_id, defaults=defaults)

        for item in payload.get("profiles", []):
            user = User.objects.get(id=item.pop("user_id"))
            ProfileInformation.objects.update_or_create(user=user, defaults=item)

        for item in payload.get("groups", []):
            group_id = item["id"]
            users = item.pop("users", [])
            defaults = {key: value for key, value in item.items() if key != "id"}
            group, _ = Group.objects.update_or_create(id=group_id, defaults=defaults)
            group.users.set(User.objects.filter(id__in=users))

        for item in payload.get("group_memberships", []):
            group = Group.objects.get(id=item["group_id"])
            users = User.objects.filter(id__in=item.get("users", []))
            group.users.set(users)

        created_profiles = backfill_missing_profile_information(sync_legacy=False)

        self.stdout.write(
            self.style.SUCCESS(
                f"Importacion idempotente completada. Perfiles vacios creados: {created_profiles}."
            )
        )
