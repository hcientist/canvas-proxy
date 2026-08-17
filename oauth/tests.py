import base64
import hashlib
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from canvasclient import client, crypto
from oauth.models import AuthorizationCode, AuthorizationRequest, CanvasGrant, ProxyToken
from registry.models import AppStatus
from registry.tests import make_app, make_tier, make_user

CANVAS = "https://canvas.test"
PROXY = "https://proxy.test"

CANVAS_TOKEN_PAYLOAD = {
    "access_token": "canvas-access-token",
    "refresh_token": "canvas-refresh-token",
    "token_type": "Bearer",
    "expires_in": 3600,
    "user": {"id": 4321, "name": "Ada Lovelace", "global_id": "10000000004321"},
}


@override_settings(CANVAS_BASE_URL=CANVAS, PROXY_BASE_URL=PROXY)
class OAuthFlowTestCase(TestCase):
    """Shared setup: one approved confidential app on a read-only tier."""

    def setUp(self):
        self.tier = make_tier()
        self.owner = make_user("owner")
        self.app = make_app(self.owner, self.tier)
        self.secret = self.app.rotate_secret()
        self.app.save()

    # -- helpers ------------------------------------------------------------

    def start_authorization(self, **overrides):
        params = {
            "client_id": self.app.client_id,
            "redirect_uri": "https://app.example.edu/callback",
            "response_type": "code",
            "state": "client-state-123",
        }
        params.update(overrides)
        return self.client.get(reverse("oauth:authorize"), params)

    def consent(self, auth_request, decision="allow"):
        return self.client.post(
            reverse("oauth:confirm", args=[auth_request.id]), {"decision": decision}
        )

    def complete_canvas_callback(self, auth_request, payload=None):
        with mock.patch.object(
            client, "exchange_code", return_value=payload or dict(CANVAS_TOKEN_PAYLOAD)
        ) as exchange:
            response = self.client.get(
                reverse("accounts:canvas_callback"),
                {"code": "canvas-code", "state": auth_request.proxy_state},
            )
        return response, exchange

    def authorized_code(self):
        """Run the flow up to the point the app has a usable code."""
        self.start_authorization()
        auth_request = AuthorizationRequest.objects.latest("created_at")
        self.consent(auth_request)
        response, _ = self.complete_canvas_callback(auth_request)
        query = parse_qs(urlsplit(response["Location"]).query)
        return query["code"][0], auth_request

    def exchange(self, code, **overrides):
        data = {
            "grant_type": "authorization_code",
            "client_id": self.app.client_id,
            "client_secret": self.secret,
            "redirect_uri": "https://app.example.edu/callback",
            "code": code,
        }
        data.update(overrides)
        return self.client.post(reverse("oauth:token"), data)

    def issued_token(self):
        code, _ = self.authorized_code()
        return self.exchange(code).json()


class AuthorizeEndpointTests(OAuthFlowTestCase):
    def test_valid_request_shows_a_consent_screen_naming_the_app(self):
        response = self.start_authorization()
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.app.name)
        self.assertContains(response, self.tier.name)
        self.assertEqual(AuthorizationRequest.objects.count(), 1)

    def test_unknown_client_gets_an_error_page_not_a_redirect(self):
        response = self.start_authorization(client_id="nope")
        self.assertEqual(response.status_code, 400)
        self.assertContains(response, "Unknown client_id", status_code=400)

    def test_unregistered_redirect_uri_is_never_redirected_to(self):
        response = self.start_authorization(redirect_uri="https://evil.example.com/cb")
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("Location", response)

    def test_unapproved_app_is_bounced_back_with_an_error(self):
        self.app.status = AppStatus.PENDING
        self.app.save()
        response = self.start_authorization()
        self.assertEqual(response.status_code, 302)
        query = parse_qs(urlsplit(response["Location"]).query)
        self.assertEqual(query["error"], ["access_denied"])
        self.assertEqual(query["state"], ["client-state-123"])

    def test_suspended_app_cannot_start_a_flow(self):
        self.app.status = AppStatus.SUSPENDED
        self.app.save()
        response = self.start_authorization()
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=access_denied", response["Location"])

    def test_unsupported_response_type_is_reported(self):
        response = self.start_authorization(response_type="token")
        self.assertIn("unsupported_response_type", response["Location"])

    def test_inactive_tier_stops_the_flow(self):
        self.tier.is_active = False
        self.tier.save()
        response = self.start_authorization()
        self.assertIn("temporarily_unavailable", response["Location"])

    def test_consent_sends_the_user_to_canvas_with_the_tier_key(self):
        self.start_authorization()
        auth_request = AuthorizationRequest.objects.latest("created_at")
        response = self.consent(auth_request)
        self.assertEqual(response.status_code, 302)
        location = urlsplit(response["Location"])
        self.assertEqual(f"{location.scheme}://{location.netloc}", CANVAS)
        query = parse_qs(location.query)
        self.assertEqual(query["client_id"], [self.tier.canvas_client_id])
        self.assertEqual(query["state"], [auth_request.proxy_state])
        self.assertEqual(
            query["redirect_uri"], [f"{PROXY}/accounts/canvas/login/callback/"]
        )

    def test_the_apps_state_is_never_sent_to_canvas(self):
        self.start_authorization()
        auth_request = AuthorizationRequest.objects.latest("created_at")
        response = self.consent(auth_request)
        self.assertNotIn("client-state-123", response["Location"])

    def test_declining_returns_access_denied_to_the_app(self):
        self.start_authorization()
        auth_request = AuthorizationRequest.objects.latest("created_at")
        response = self.consent(auth_request, decision="deny")
        self.assertIn("error=access_denied", response["Location"])
        self.assertTrue(response["Location"].startswith("https://app.example.edu/callback"))

    def test_expired_authorization_request_cannot_be_confirmed(self):
        self.start_authorization()
        auth_request = AuthorizationRequest.objects.latest("created_at")
        auth_request.expires_at = timezone.now() - timezone.timedelta(seconds=1)
        auth_request.save()
        response = self.consent(auth_request)
        self.assertEqual(response.status_code, 400)


class CanvasCallbackTests(OAuthFlowTestCase):
    def test_callback_stores_a_grant_and_redirects_with_a_code(self):
        self.start_authorization()
        auth_request = AuthorizationRequest.objects.latest("created_at")
        self.consent(auth_request)
        response, exchange = self.complete_canvas_callback(auth_request)

        self.assertEqual(response.status_code, 302)
        exchange.assert_called_once()
        self.assertEqual(
            exchange.call_args.kwargs["redirect_uri"], f"{PROXY}/accounts/canvas/login/callback/"
        )

        location = urlsplit(response["Location"])
        self.assertEqual(
            f"{location.scheme}://{location.netloc}{location.path}",
            "https://app.example.edu/callback",
        )
        query = parse_qs(location.query)
        self.assertEqual(query["state"], ["client-state-123"])
        self.assertIn("code", query)

        grant = CanvasGrant.objects.get()
        self.assertEqual(grant.canvas_user_id, "4321")
        self.assertEqual(grant.access_token, "canvas-access-token")

    def test_canvas_tokens_are_encrypted_at_rest(self):
        self.authorized_code()
        grant = CanvasGrant.objects.get()
        self.assertNotIn("canvas-access-token", grant.access_token_encrypted)
        self.assertNotIn("canvas-refresh-token", grant.refresh_token_encrypted)

    def test_the_authorization_code_is_only_stored_as_a_digest(self):
        raw_code, _ = self.authorized_code()
        stored = AuthorizationCode.objects.get()
        self.assertNotEqual(stored.code_digest, raw_code)
        self.assertEqual(stored.code_digest, crypto.token_digest(raw_code))

    def test_unknown_state_is_refused(self):
        # The shared callback cannot tell which flow an unrecognised state was
        # meant for, so it falls through to the sign-in path and says so there.
        response = self.client.get(
            reverse("accounts:canvas_callback"), {"code": "x", "state": "made-up"}
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/accounts/login/", response["Location"])
        self.assertFalse(CanvasGrant.objects.exists())

    def test_the_callback_routes_an_app_authorization_not_a_sign_in(self):
        self.start_authorization()
        auth_request = AuthorizationRequest.objects.latest("created_at")
        self.consent(auth_request)
        response, _ = self.complete_canvas_callback(auth_request)
        # Sent back to the app, not signed in to the dashboard.
        self.assertTrue(response["Location"].startswith("https://app.example.edu/callback"))
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_state_cannot_be_replayed(self):
        self.start_authorization()
        auth_request = AuthorizationRequest.objects.latest("created_at")
        self.consent(auth_request)
        self.complete_canvas_callback(auth_request)
        second, _ = self.complete_canvas_callback(auth_request)
        self.assertEqual(second.status_code, 400)
        self.assertEqual(CanvasGrant.objects.count(), 1)

    def test_canvas_errors_are_reported_to_the_app(self):
        self.start_authorization()
        auth_request = AuthorizationRequest.objects.latest("created_at")
        self.consent(auth_request)
        with mock.patch.object(
            client, "exchange_code", side_effect=client.CanvasError("bad key")
        ):
            response = self.client.get(
                reverse("accounts:canvas_callback"),
                {"code": "c", "state": auth_request.proxy_state},
            )
        self.assertEqual(response.status_code, 302)
        self.assertIn("error=server_error", response["Location"])
        self.assertFalse(CanvasGrant.objects.exists())

    def test_user_denial_at_canvas_is_relayed(self):
        self.start_authorization()
        auth_request = AuthorizationRequest.objects.latest("created_at")
        self.consent(auth_request)
        response = self.client.get(
            reverse("accounts:canvas_callback"),
            {"error": "access_denied", "state": auth_request.proxy_state},
        )
        self.assertIn("error=access_denied", response["Location"])


class TokenEndpointTests(OAuthFlowTestCase):
    def test_code_exchange_returns_a_proxy_token(self):
        code, _ = self.authorized_code()
        response = self.exchange(code)
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["token_type"], "Bearer")
        self.assertIn("access_token", body)
        self.assertIn("refresh_token", body)
        self.assertEqual(body["user"]["id"], 4321)
        self.assertEqual(response["Cache-Control"], "no-store")

    def test_the_canvas_token_is_never_returned_to_the_app(self):
        body = self.issued_token()
        self.assertNotEqual(body["access_token"], "canvas-access-token")
        self.assertNotEqual(body["refresh_token"], "canvas-refresh-token")
        self.assertNotIn("canvas-access-token", str(body))

    def test_proxy_tokens_are_stored_only_as_digests(self):
        body = self.issued_token()
        stored = ProxyToken.objects.get()
        self.assertEqual(
            stored.access_token_digest, crypto.token_digest(body["access_token"])
        )
        self.assertNotIn(body["access_token"], stored.access_token_digest)

    def test_basic_auth_credentials_are_accepted(self):
        code, _ = self.authorized_code()
        creds = base64.b64encode(
            f"{self.app.client_id}:{self.secret}".encode()
        ).decode()
        response = self.client.post(
            reverse("oauth:token"),
            {
                "grant_type": "authorization_code",
                "redirect_uri": "https://app.example.edu/callback",
                "code": code,
            },
            HTTP_AUTHORIZATION=f"Basic {creds}",
        )
        self.assertEqual(response.status_code, 200)

    def test_wrong_secret_is_refused(self):
        code, _ = self.authorized_code()
        response = self.exchange(code, client_secret="wrong")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["error"], "invalid_client")

    def test_another_app_cannot_redeem_the_code(self):
        code, _ = self.authorized_code()
        thief = make_app(make_user("thief"), self.tier, name="Thief")
        thief_secret = thief.rotate_secret()
        thief.save()
        response = self.client.post(
            reverse("oauth:token"),
            {
                "grant_type": "authorization_code",
                "client_id": thief.client_id,
                "client_secret": thief_secret,
                "redirect_uri": "https://app.example.edu/callback",
                "code": code,
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid_grant")

    def test_mismatched_redirect_uri_is_refused(self):
        code, _ = self.authorized_code()
        response = self.exchange(code, redirect_uri="https://app.example.edu/other")
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["error"], "invalid_grant")

    def test_code_replay_revokes_the_grant(self):
        code, _ = self.authorized_code()
        self.assertEqual(self.exchange(code).status_code, 200)

        with mock.patch.object(client, "revoke", return_value=True) as revoke:
            second = self.exchange(code)
        self.assertEqual(second.status_code, 400)
        revoke.assert_called_once()

        grant = CanvasGrant.objects.get()
        self.assertIsNotNone(grant.revoked_at)
        self.assertEqual(grant.access_token_encrypted, "")
        self.assertFalse(ProxyToken.objects.filter(revoked_at__isnull=True).exists())

    def test_expired_code_is_refused(self):
        code, _ = self.authorized_code()
        AuthorizationCode.objects.update(
            expires_at=timezone.now() - timezone.timedelta(seconds=1)
        )
        response = self.exchange(code)
        self.assertEqual(response.status_code, 400)

    def test_unsupported_grant_type(self):
        response = self.client.post(
            reverse("oauth:token"),
            {"grant_type": "password", "client_id": self.app.client_id},
        )
        self.assertEqual(response.json()["error"], "unsupported_grant_type")

    def test_suspended_app_cannot_exchange(self):
        code, _ = self.authorized_code()
        self.app.status = AppStatus.SUSPENDED
        self.app.save()
        response = self.exchange(code)
        self.assertEqual(response.status_code, 403)

    def test_canvas_style_token_url_also_works(self):
        code, _ = self.authorized_code()
        response = self.client.post(
            "/login/oauth2/token",
            {
                "grant_type": "authorization_code",
                "client_id": self.app.client_id,
                "client_secret": self.secret,
                "redirect_uri": "https://app.example.edu/callback",
                "code": code,
            },
        )
        self.assertEqual(response.status_code, 200)


class RefreshTokenTests(OAuthFlowTestCase):
    def refresh(self, refresh_token):
        return self.client.post(
            reverse("oauth:token"),
            {
                "grant_type": "refresh_token",
                "client_id": self.app.client_id,
                "client_secret": self.secret,
                "refresh_token": refresh_token,
            },
        )

    def test_refresh_returns_a_new_pair(self):
        first = self.issued_token()
        response = self.refresh(first["refresh_token"])
        self.assertEqual(response.status_code, 200)
        second = response.json()
        self.assertNotEqual(second["access_token"], first["access_token"])
        self.assertNotEqual(second["refresh_token"], first["refresh_token"])

    def test_the_old_refresh_token_stops_working(self):
        first = self.issued_token()
        self.refresh(first["refresh_token"])
        with mock.patch.object(client, "revoke", return_value=True):
            replay = self.refresh(first["refresh_token"])
        self.assertEqual(replay.status_code, 400)

    def test_refresh_reuse_kills_the_whole_grant(self):
        first = self.issued_token()
        self.refresh(first["refresh_token"])
        with mock.patch.object(client, "revoke", return_value=True):
            self.refresh(first["refresh_token"])
        grant = CanvasGrant.objects.get()
        self.assertIsNotNone(grant.revoked_at)
        self.assertFalse(ProxyToken.objects.filter(revoked_at__isnull=True).exists())

    def test_refresh_after_grant_revocation_is_refused(self):
        first = self.issued_token()
        with mock.patch.object(client, "revoke", return_value=True):
            CanvasGrant.objects.get().revoke()
        self.assertEqual(self.refresh(first["refresh_token"]).status_code, 400)

    def test_unknown_refresh_token_is_refused(self):
        self.assertEqual(self.refresh("made-up").status_code, 400)


class PKCETests(OAuthFlowTestCase):
    verifier = "a" * 64

    @property
    def challenge(self):
        digest = hashlib.sha256(self.verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    def setUp(self):
        super().setUp()
        self.app.is_public_client = True
        self.app.client_secret_hash = ""
        self.app.save()

    def test_public_client_must_send_a_challenge(self):
        response = self.start_authorization()
        self.assertEqual(response.status_code, 302)
        self.assertIn("invalid_request", response["Location"])

    def test_public_client_flow_with_a_valid_verifier(self):
        self.start_authorization(
            code_challenge=self.challenge, code_challenge_method="S256"
        )
        auth_request = AuthorizationRequest.objects.latest("created_at")
        self.consent(auth_request)
        response, _ = self.complete_canvas_callback(auth_request)
        code = parse_qs(urlsplit(response["Location"]).query)["code"][0]

        token_response = self.client.post(
            reverse("oauth:token"),
            {
                "grant_type": "authorization_code",
                "client_id": self.app.client_id,
                "redirect_uri": "https://app.example.edu/callback",
                "code": code,
                "code_verifier": self.verifier,
            },
        )
        self.assertEqual(token_response.status_code, 200)

    def test_wrong_verifier_is_refused(self):
        self.start_authorization(
            code_challenge=self.challenge, code_challenge_method="S256"
        )
        auth_request = AuthorizationRequest.objects.latest("created_at")
        self.consent(auth_request)
        response, _ = self.complete_canvas_callback(auth_request)
        code = parse_qs(urlsplit(response["Location"]).query)["code"][0]

        token_response = self.client.post(
            reverse("oauth:token"),
            {
                "grant_type": "authorization_code",
                "client_id": self.app.client_id,
                "redirect_uri": "https://app.example.edu/callback",
                "code": code,
                "code_verifier": "b" * 64,
            },
        )
        self.assertEqual(token_response.status_code, 400)
        self.assertEqual(token_response.json()["error"], "invalid_grant")

    def test_a_public_client_sending_a_secret_is_refused(self):
        self.start_authorization(
            code_challenge=self.challenge, code_challenge_method="S256"
        )
        auth_request = AuthorizationRequest.objects.latest("created_at")
        self.consent(auth_request)
        response, _ = self.complete_canvas_callback(auth_request)
        code = parse_qs(urlsplit(response["Location"]).query)["code"][0]

        token_response = self.client.post(
            reverse("oauth:token"),
            {
                "grant_type": "authorization_code",
                "client_id": self.app.client_id,
                "client_secret": "anything",
                "redirect_uri": "https://app.example.edu/callback",
                "code": code,
                "code_verifier": self.verifier,
            },
        )
        self.assertEqual(token_response.status_code, 401)

    def test_unsupported_challenge_method_is_refused(self):
        response = self.start_authorization(
            code_challenge=self.challenge, code_challenge_method="MD5"
        )
        self.assertIn("invalid_request", response["Location"])


class RevocationTests(OAuthFlowTestCase):
    def test_revoking_an_access_token_kills_the_grant(self):
        body = self.issued_token()
        with mock.patch.object(client, "revoke", return_value=True) as canvas_revoke:
            response = self.client.post(
                reverse("oauth:revoke"), {"token": body["access_token"]}
            )
        self.assertEqual(response.status_code, 200)
        canvas_revoke.assert_called_once_with("canvas-access-token")
        self.assertIsNotNone(CanvasGrant.objects.get().revoked_at)

    def test_unknown_tokens_return_200(self):
        response = self.client.post(reverse("oauth:revoke"), {"token": "made-up"})
        self.assertEqual(response.status_code, 200)

    def test_canvas_style_delete_revokes(self):
        body = self.issued_token()
        with mock.patch.object(client, "revoke", return_value=True):
            response = self.client.delete(
                "/login/oauth2/token",
                HTTP_AUTHORIZATION=f"Bearer {body['access_token']}",
            )
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(CanvasGrant.objects.get().revoked_at)


class GrantRefreshTests(OAuthFlowTestCase):
    def test_a_stale_canvas_token_is_refreshed_before_use(self):
        self.authorized_code()
        grant = CanvasGrant.objects.get()
        grant.access_token_expires_at = timezone.now() - timezone.timedelta(seconds=10)
        grant.save()

        with mock.patch.object(
            client,
            "refresh_token",
            return_value={"access_token": "fresh-token", "expires_in": 3600},
        ) as refresh:
            token = grant.usable_access_token()

        refresh.assert_called_once()
        self.assertEqual(token, "fresh-token")
        grant.refresh_from_db()
        # Canvas omits refresh_token on refresh; the stored one must survive.
        self.assertEqual(grant.refresh_token, "canvas-refresh-token")

    def test_a_fresh_token_is_used_as_is(self):
        self.authorized_code()
        grant = CanvasGrant.objects.get()
        with mock.patch.object(client, "refresh_token") as refresh:
            self.assertEqual(grant.usable_access_token(), "canvas-access-token")
        refresh.assert_not_called()


class MetadataTests(OAuthFlowTestCase):
    def test_metadata_advertises_the_proxy_endpoints(self):
        response = self.client.get(reverse("oauth:metadata"))
        body = response.json()
        self.assertEqual(body["authorization_endpoint"], f"{PROXY}/oauth2/auth")
        self.assertEqual(body["token_endpoint"], f"{PROXY}/oauth2/token")
        self.assertIn("S256", body["code_challenge_methods_supported"])

    def test_well_known_alias(self):
        response = self.client.get("/.well-known/oauth-authorization-server")
        self.assertEqual(response.status_code, 200)
