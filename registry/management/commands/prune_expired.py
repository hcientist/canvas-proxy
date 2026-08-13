"""Delete spent OAuth state and aged-out audit rows. Run from cron, daily."""

from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from gateway.models import RequestLog
from oauth.models import AuthorizationCode, AuthorizationRequest, ProxyToken


class Command(BaseCommand):
    help = "Remove expired authorization state, dead tokens and old request logs."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report what would be deleted without deleting it.",
        )

    def handle(self, *args, **options):
        now = timezone.now()
        dry_run = options["dry_run"]

        # Keep dead refresh tokens around for a grace period so replay
        # detection still has something to match against.
        token_cutoff = now - timezone.timedelta(days=7)
        log_cutoff = now - timezone.timedelta(days=settings.REQUEST_LOG_RETENTION_DAYS)

        targets = [
            ("authorization requests", AuthorizationRequest.objects.filter(expires_at__lt=now)),
            ("authorization codes", AuthorizationCode.objects.filter(expires_at__lt=now)),
            (
                "expired proxy tokens",
                ProxyToken.objects.filter(
                    expires_at__lt=token_cutoff, refresh_expires_at__lt=token_cutoff
                ),
            ),
            ("request logs", RequestLog.objects.filter(created_at__lt=log_cutoff)),
        ]

        for label, queryset in targets:
            count = queryset.count()
            if not dry_run and count:
                queryset.delete()
            if options["verbosity"] > 0:
                verb = "would delete" if dry_run else "deleted"
                self.stdout.write(f"{verb} {count} {label}")
