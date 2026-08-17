"""Authorizing an external-API app: Canvas proves identity and nothing more."""

from unittest import mock
from urllib.parse import parse_qs, urlsplit

from django.test import TestCase, override_settings
from django.urls import reverse

from canvasclient import client
from gateway.tests_external import API, make_external_app
from oauth.models import AuthorizationRequest, CanvasGrant, ProxyToken
from registry.tests import make_tier, make_user

CANVAS = "https://canvas.test"
PROXY = "https://proxy.test"

CANVAS_TOKEN_PAYLOAD = {
    "access_token": "canvas-access-token",
    "refresh_token": "canvas-refresh-token",
    "expires_in": 3600,
    "user": {"id": 4321, "name": "Ada Lovelace", "global_id": "10000000004321"},
}


@override_settings(
    CANVAS_BASE_URL=CANVAS, PROXY_BASE_URL=PROXY, CANVAS_LOGIN_TIER="read_basic"
)
class ExternalAuthorizationTests(TestCase):
    def setUp(self):
        # External apps have no tier of their own; they borrow the sign-in key.
        self.login_tier = make_tier(slug="read_basic")
        self.owner = make_user("student")
        self.app = make_external_app(owner=self.owner)
        self.secret = self.app.rotate_secret()

    def start(self, **overrides):
        params = {
            "client_id": self.app.client_id,
            "redirect_uri": "https://app.example.edu/callback",
            "response_type": "code",
            "state": "app-state",
        }
        params.update(overrides)
        return self.client.get(reverse("oauth:authorize"), params)

    def run_flow(self):
        self.start()
        auth_request = AuthorizationRequest.objects.latest("created_at")
        self.client.post(
            reverse("oauth:confirm", args=[auth_request.id]), {"decision": "allow"}
        )
        with mock.patch.object(
            client, "exchange_code", return_value=dict(CANVAS_TOKEN_PAYLOAD)
        ), mock.patch.object(client, "revoke", return_value=True) as revoke:
            response = self.client.get(
                reverse("accounts:canvas_callback"),
                {"code": "canvas-code", "state": auth_request.proxy_state},
            )
        self.revoke_mock = revoke
        return response

    def issued_token(self):
        response = self.run_flow()
        code = parse_qs(urlsplit(response["Location"]).query)["code"][0]
        return self.client.post(
            reverse("oauth:token"),
            {
                "grant_type": "authorization_code",
                "client_id": self.app.client_id,
                "client_secret": self.secret,
                "redirect_uri": "https://app.example.edu/callback",
                "code": code,
            },
        ).json()

    # -- consent ------------------------------------------------------------

    def test_consent_names_the_external_api_not_canvas_access(self):
        response = self.start()
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.app.name)
        self.assertContains(response, API)
        self.assertContains(response, "confirm who you are")
        self.assertNotContains(response, "wants access to your Canvas account")

    def test_consent_says_only_identity_is_read(self):
        response = self.start()
        self.assertContains(response, "Your name and Canvas user id")

    def test_an_app_with_no_api_base_url_cannot_start(self):
        self.app.api_base_url = ""
        self.app.save()
        response = self.start()
        self.assertEqual(response.status_code, 302)
        self.assertIn("temporarily_unavailable", response["Location"])

    # -- the Canvas hop -----------------------------------------------------

    def test_sign_in_uses_the_login_tier_key_with_identity_scopes_only(self):
        self.start()
        auth_request = AuthorizationRequest.objects.latest("created_at")
        response = self.client.post(
            reverse("oauth:confirm", args=[auth_request.id]), {"decision": "allow"}
        )
        query = parse_qs(urlsplit(response["Location"]).query)
        self.assertEqual(query["client_id"], [self.login_tier.canvas_client_id])
        self.assertEqual(query["scope"], ["url:GET|/api/v1/users/:user_id/profile"])

    def test_the_canvas_token_is_revoked_immediately(self):
        self.run_flow()
        self.revoke_mock.assert_called_once_with("canvas-access-token")

    def test_no_canvas_token_is_stored(self):
        self.run_flow()
        grant = CanvasGrant.objects.get()
        self.assertEqual(grant.access_token_encrypted, "")
        self.assertEqual(grant.refresh_token_encrypted, "")
        self.assertFalse(grant.holds_canvas_token)

    def test_the_grant_records_the_canvas_identity_but_no_tier(self):
        self.run_flow()
        grant = CanvasGrant.objects.get()
        self.assertEqual(grant.canvas_user_id, "4321")
        self.assertEqual(grant.canvas_user_name, "Ada Lovelace")
        self.assertIsNone(grant.tier)
        self.assertEqual(grant.scopes, [])

    def test_the_app_is_returned_a_code(self):
        response = self.run_flow()
        self.assertEqual(response.status_code, 302)
        query = parse_qs(urlsplit(response["Location"]).query)
        self.assertEqual(query["state"], ["app-state"])
        self.assertIn("code", query)

    # -- tokens -------------------------------------------------------------

    def test_the_code_exchanges_for_a_working_proxy_token(self):
        body = self.issued_token()
        self.assertIn("access_token", body)
        self.assertEqual(body["user"]["id"], 4321)
        self.assertTrue(ProxyToken.objects.exists())

    def test_no_canvas_token_leaks_in_the_response(self):
        body = self.issued_token()
        self.assertNotIn("canvas-access-token", str(body))
        self.assertNotIn("canvas-refresh-token", str(body))

    def test_revoking_the_grant_needs_no_upstream_call(self):
        self.issued_token()
        grant = CanvasGrant.objects.get()
        with mock.patch.object(client, "revoke") as revoke:
            grant.revoke()
        revoke.assert_not_called()
        self.assertIsNotNone(grant.revoked_at)
        self.assertFalse(ProxyToken.objects.filter(revoked_at__isnull=True).exists())

    def test_suspending_the_app_cuts_off_its_tokens(self):
        self.issued_token()
        staff = make_user("staff", is_staff=True)
        with mock.patch.object(client, "revoke"):
            self.app.suspend(staff, "abuse")
        self.assertFalse(ProxyToken.objects.filter(revoked_at__isnull=True).exists())

    def test_an_unapproved_external_app_cannot_authorize(self):
        self.app.status = "pending"
        self.app.save()
        response = self.start()
        self.assertIn("error=access_denied", response["Location"])

    def test_sign_in_fails_cleanly_when_no_login_tier_is_configured(self):
        self.login_tier.canvas_client_id = ""
        self.login_tier.canvas_client_secret_encrypted = ""
        self.login_tier.save()
        response = self.start()
        self.assertEqual(response.status_code, 302)
        self.assertIn("temporarily_unavailable", response["Location"])
