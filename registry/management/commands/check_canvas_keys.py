"""Pre-flight the configured developer keys against the real Canvas instance.

Asks Canvas to start an authorization for each tier and reads the error it
returns. This is a plain GET with no user involved and no side effects -- it
never completes a flow or creates a grant -- so it is safe to run any time.

    python manage.py check_canvas_keys
"""

import re

import requests
from django.conf import settings
from django.core.management.base import BaseCommand

from accounts.views import dashboard_redirect_uri
from canvasclient import client
from oauth.views import canvas_redirect_uri
from registry.models import AccessTier


class Command(BaseCommand):
    help = "Verify each tier's Canvas developer key and its registered redirect URI."

    def add_arguments(self, parser):
        parser.add_argument(
            "--tier", help="Check only this tier slug.", default=None
        )

    def handle(self, *args, **options):
        # Two different flows, two different callbacks. Every key needs the
        # authorization one; the login tier's key also serves dashboard sign-in
        # and external-app identity checks, so it needs both.
        authorize_uri = canvas_redirect_uri()
        signin_uri = dashboard_redirect_uri()

        self.stdout.write(f"Canvas: {settings.CANVAS_BASE_URL}")
        self.stdout.write(f"App authorization callback: {authorize_uri}")
        self.stdout.write(f"Dashboard sign-in callback: {signin_uri}")
        self.stdout.write("")

        tiers = AccessTier.objects.filter(is_active=True)
        if options["tier"]:
            tiers = tiers.filter(slug=options["tier"])

        missing = set()
        problems = 0
        for tier in tiers:
            is_login_tier = tier.slug == settings.CANVAS_LOGIN_TIER
            wanted = [("app authorization", authorize_uri)]
            if is_login_tier:
                wanted.append(("dashboard sign-in", signin_uri))

            for label, uri in wanted:
                ok, message = self._check(tier, uri)
                style = self.style.SUCCESS if ok else self.style.ERROR
                self.stdout.write(f"{tier.slug:12} {label:20} {style(message)}")
                if not ok:
                    problems += 1
                    if "not registered" in message:
                        missing.add(uri)

        self.stdout.write("")
        if problems:
            note = (
                f"{problems} check(s) failed. In Canvas, open the developer key "
                "and add the missing line to its Redirect URIs box:"
            )
            self.stdout.write(self.style.WARNING(note))
            for uri in sorted(missing) or [authorize_uri]:
                self.stdout.write(f"  {uri}")
            return

        self.stdout.write(self.style.SUCCESS("All configured tiers are ready."))

    def _check(self, tier, redirect_uri):
        if not tier.is_configured:
            return False, "no developer key configured for this tier"

        url = client.authorize_url(
            client_id=tier.canvas_client_id,
            redirect_uri=redirect_uri,
            state="preflight",
            scopes=tier.scopes if tier.enforces_scopes else (),
        )
        try:
            response = requests.get(url, timeout=20, allow_redirects=False)
        except requests.RequestException as exc:
            return False, f"could not reach Canvas: {exc}"

        # A valid key with a matching redirect URI sends the user on to log in.
        if response.status_code in (301, 302):
            return True, f"ready (key {tier.canvas_client_id})"

        body = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", response.text)).strip()
        lowered = body.lower()

        if "unknown client" in lowered or "invalid_client" in lowered:
            return False, f"Canvas does not recognise key {tier.canvas_client_id}"
        if "redirect_uri" in lowered:
            return False, (
                f"key {tier.canvas_client_id} exists, but this redirect URI is "
                "not registered on it"
            )
        if response.status_code == 200 and "login" in lowered:
            return True, f"ready (key {tier.canvas_client_id})"
        return False, f"HTTP {response.status_code}: {body[:120]}"
