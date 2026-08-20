from unittest import mock
from urllib.parse import parse_qs, urlsplit

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, override_settings
from django.urls import reverse

from accounts.views import SESSION_STATE_KEY
from canvasclient import client
from registry.models import AccessTier
from registry.tests import make_tier

User = get_user_model()

CANVAS = "https://canvas.test"
PROXY = "https://proxy.test"

TOKEN_PAYLOAD = {
    "access_token": "login-token",
    "expires_in": 3600,
    "user": {"id": 99, "name": "Grace Hopper"},
}
PROFILE = {
    "name": "Grace Hopper",
    "login_id": "ghopper",
    "primary_email": "ghopper@example.edu",
    "avatar_url": "https://canvas.test/avatar.png",
}


@override_settings(
    CANVAS_BASE_URL=CANVAS, PROXY_BASE_URL=PROXY, CANVAS_LOGIN_TIER="auth_only"
)
class CanvasSignInTests(TestCase):
    def setUp(self):
        self.tier = make_tier()

    def start(self):
        return self.client.post(reverse("accounts:canvas_start"))

    def finish(self, state, token_payload=None, profile=None):
        with mock.patch.object(
            client, "exchange_code", return_value=token_payload or dict(TOKEN_PAYLOAD)
        ), mock.patch.object(
            client, "get_json", return_value=profile if profile is not None else dict(PROFILE)
        ), mock.patch.object(
            client, "revoke", return_value=True
        ) as revoke:
            response = self.client.get(
                reverse("accounts:canvas_callback"), {"code": "c", "state": state}
            )
        self.revoke_mock = revoke
        return response

    def test_start_redirects_to_canvas_with_the_login_tier_key(self):
        response = self.start()
        self.assertEqual(response.status_code, 302)
        location = urlsplit(response["Location"])
        self.assertEqual(f"{location.scheme}://{location.netloc}", CANVAS)
        query = parse_qs(location.query)
        self.assertEqual(query["client_id"], [self.tier.canvas_client_id])
        self.assertEqual(
            query["redirect_uri"], [f"{PROXY}/accounts/canvas/login/callback/"]
        )

    def test_a_successful_callback_creates_the_user(self):
        self.start()
        state = self.client.session[SESSION_STATE_KEY]
        response = self.finish(state)

        self.assertEqual(response.status_code, 302)
        user = User.objects.get(canvas_user_id="99")
        self.assertEqual(user.canvas_name, "Grace Hopper")
        self.assertEqual(user.canvas_login_id, "ghopper")
        self.assertEqual(user.email, "ghopper@example.edu")
        self.assertEqual(user.username, "canvas-99")
        self.assertIsNotNone(user.last_canvas_login)

    def test_the_sign_in_token_is_revoked_immediately(self):
        self.start()
        state = self.client.session[SESSION_STATE_KEY]
        self.finish(state)
        self.revoke_mock.assert_called_once_with("login-token")

    def test_signing_in_twice_reuses_the_same_account(self):
        self.start()
        self.finish(self.client.session[SESSION_STATE_KEY])
        self.client.post(reverse("accounts:logout"))
        self.start()
        self.finish(self.client.session[SESSION_STATE_KEY])
        self.assertEqual(User.objects.filter(canvas_user_id="99").count(), 1)

    def test_a_mismatched_state_is_refused(self):
        self.start()
        response = self.finish("not-the-state")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["Location"])
        self.assertFalse(User.objects.exists())

    def test_a_callback_without_a_started_flow_is_refused(self):
        response = self.client.get(
            reverse("accounts:canvas_callback"), {"code": "c", "state": "x"}
        )
        self.assertIn("/login/", response["Location"])
        self.assertFalse(User.objects.exists())

    def test_a_failed_exchange_does_not_create_a_user(self):
        self.start()
        state = self.client.session[SESSION_STATE_KEY]
        with mock.patch.object(
            client, "exchange_code", side_effect=client.CanvasError("nope")
        ):
            response = self.client.get(
                reverse("accounts:canvas_callback"), {"code": "c", "state": state}
            )
        self.assertIn("/login/", response["Location"])
        self.assertFalse(User.objects.exists())

    def test_a_missing_profile_still_signs_the_user_in(self):
        self.start()
        state = self.client.session[SESSION_STATE_KEY]
        with mock.patch.object(client, "exchange_code", return_value=dict(TOKEN_PAYLOAD)), \
            mock.patch.object(client, "get_json", side_effect=client.CanvasError("403")), \
            mock.patch.object(client, "revoke", return_value=True):
            self.client.get(
                reverse("accounts:canvas_callback"), {"code": "c", "state": state}
            )
        user = User.objects.get(canvas_user_id="99")
        self.assertEqual(user.canvas_name, "Grace Hopper")

    def test_canvas_denial_is_reported(self):
        self.start()
        response = self.client.get(
            reverse("accounts:canvas_callback"), {"error": "access_denied"}
        )
        self.assertIn("/login/", response["Location"])

    def test_sign_in_is_blocked_when_the_tier_has_no_key(self):
        AccessTier.objects.update(canvas_client_id="", canvas_client_secret_encrypted="")
        response = self.start()
        self.assertIn("/login/", response["Location"])

    def test_open_redirects_are_not_honoured_after_sign_in(self):
        self.client.post(reverse("accounts:canvas_start"), {"next": "https://evil.example.com"})
        state = self.client.session[SESSION_STATE_KEY]
        response = self.finish(state)
        self.assertEqual(response["Location"], "/apps/")

    def test_a_relative_next_is_honoured(self):
        self.client.post(reverse("accounts:canvas_start"), {"next": "/apps/new"})
        state = self.client.session[SESSION_STATE_KEY]
        response = self.finish(state)
        self.assertEqual(response["Location"], "/apps/new")


class SeedTiersCommandTests(TestCase):
    def test_it_creates_three_tiers(self):
        call_command("seed_tiers", verbosity=0)
        self.assertEqual(AccessTier.objects.count(), 3)
        self.assertEqual(
            set(AccessTier.objects.values_list("slug", flat=True)),
            {"auth_only", "read_only", "read_write"},
        )

    def test_rerunning_does_not_clobber_operator_edits(self):
        call_command("seed_tiers", verbosity=0)
        tier = AccessTier.objects.get(slug="auth_only")
        tier.path_rules = [{"methods": ["GET"], "pattern": "^/api/v1/mine"}]
        tier.save()

        call_command("seed_tiers", verbosity=0)
        tier.refresh_from_db()
        self.assertEqual(tier.path_rules, [{"methods": ["GET"], "pattern": "^/api/v1/mine"}])

    def test_reset_rules_restores_the_defaults(self):
        call_command("seed_tiers", verbosity=0)
        tier = AccessTier.objects.get(slug="auth_only")
        tier.path_rules = []
        tier.save()

        call_command("seed_tiers", "--reset-rules", verbosity=0)
        tier.refresh_from_db()
        self.assertTrue(tier.path_rules)

    def test_seeded_tiers_enforce_their_intent(self):
        call_command("seed_tiers", verbosity=0)
        auth = AccessTier.objects.get(slug="auth_only")
        read = AccessTier.objects.get(slug="read_only")
        write = AccessTier.objects.get(slug="read_write")

        self.assertTrue(auth.permits("GET", "/api/v1/users/self/profile")[0])
        self.assertFalse(auth.permits("GET", "/api/v1/courses/1")[0])
        self.assertFalse(auth.permits("GET", "/api/graphql")[0])

        self.assertTrue(read.permits("GET", "/api/v1/courses/1")[0])
        self.assertFalse(read.permits("POST", "/api/v1/courses/1")[0])
        self.assertFalse(read.permits("GET", "/api/graphql")[0])

        self.assertTrue(write.permits("POST", "/api/v1/courses/1/assignments")[0])
        self.assertFalse(write.permits("GET", "/api/graphql")[0])
        self.assertFalse(write.allow_masquerade)


class PruneCommandTests(TestCase):
    def test_it_runs_clean_on_an_empty_database(self):
        call_command("prune_expired", verbosity=0)
        call_command("prune_expired", "--dry-run", verbosity=0)
