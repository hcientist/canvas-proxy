"""Browser access: CORS, and the API-key style APIs like Giphy use."""

from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings

from gateway.cors import allowed_origins, origin_of
from gateway.models import RequestLog
from gateway.tests import FakeUpstream
from gateway.tests_external import make_external_app, public_dns
from oauth.models import CanvasGrant, ProxyToken
from registry.models import AppStatus, CredentialStyle
from registry.tests import make_user

ORIGIN = "https://student.github.io"
PROXY = "https://proxy.test"


class OriginDerivationTests(TestCase):
    def setUp(self):
        cache.clear()

    def test_an_origin_is_the_scheme_host_and_port(self):
        self.assertEqual(origin_of("https://a.example.edu/oauth/cb"), "https://a.example.edu")
        self.assertEqual(origin_of("http://localhost:3000/cb"), "http://localhost:3000")

    def test_a_relative_uri_has_no_origin(self):
        self.assertEqual(origin_of("/callback"), "")

    def test_approved_apps_contribute_their_origins(self):
        make_external_app(redirect_uris=[f"{ORIGIN}/cb"], status=AppStatus.APPROVED)
        self.assertIn(ORIGIN, allowed_origins())

    def test_unapproved_apps_do_not(self):
        make_external_app(redirect_uris=[f"{ORIGIN}/cb"], status=AppStatus.PENDING)
        self.assertNotIn(ORIGIN, allowed_origins())

    def test_a_decision_takes_effect_without_waiting_for_the_cache(self):
        app = make_external_app(redirect_uris=[f"{ORIGIN}/cb"], status=AppStatus.PENDING)
        self.assertNotIn(ORIGIN, allowed_origins())  # populates the cache

        app.approve(make_user("staff", is_staff=True))
        self.assertIn(ORIGIN, allowed_origins())

    def test_suspending_removes_the_origin_immediately(self):
        app = make_external_app(redirect_uris=[f"{ORIGIN}/cb"], status=AppStatus.APPROVED)
        self.assertIn(ORIGIN, allowed_origins())

        with mock.patch("canvasclient.client.revoke"):
            app.suspend(make_user("staff2", is_staff=True), "abuse")
        self.assertNotIn(ORIGIN, allowed_origins())


@override_settings(PROXY_BASE_URL=PROXY)
class CorsBehaviourTests(TestCase):
    def setUp(self):
        cache.clear()
        self.app = make_external_app(
            redirect_uris=[f"{ORIGIN}/cb"], status=AppStatus.APPROVED
        )
        self.grant = CanvasGrant.objects.create(
            app=self.app, tier=None, canvas_user_id="4321"
        )
        self.token, self.access, _ = ProxyToken.issue(self.grant)

    def preflight(self, path="/ext/gifs/search", origin=ORIGIN, method="GET"):
        return self.client.options(
            path,
            HTTP_ORIGIN=origin,
            HTTP_ACCESS_CONTROL_REQUEST_METHOD=method,
            HTTP_ACCESS_CONTROL_REQUEST_HEADERS="authorization",
        )

    def test_a_preflight_from_a_registered_origin_is_allowed(self):
        response = self.preflight()
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response["Access-Control-Allow-Origin"], ORIGIN)
        self.assertIn("GET", response["Access-Control-Allow-Methods"])
        self.assertIn("authorization", response["Access-Control-Allow-Headers"].lower())

    def test_a_preflight_never_reaches_the_proxy_view(self):
        # Otherwise it would be forwarded upstream, or rejected for having no
        # bearer token, and the browser would call it a CORS failure either way.
        with mock.patch("gateway.views.requests.request") as request:
            self.preflight()
        request.assert_not_called()
        self.assertFalse(RequestLog.objects.exists())

    def test_an_unregistered_origin_is_refused(self):
        response = self.preflight(origin="https://evil.example.com")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("Access-Control-Allow-Origin", response)

    def test_a_real_request_carries_the_headers(self):
        with mock.patch(
            "gateway.views.requests.request", return_value=FakeUpstream()
        ), public_dns():
            response = self.client.get(
                "/ext/gifs/search",
                HTTP_ORIGIN=ORIGIN,
                HTTP_AUTHORIZATION=f"Bearer {self.access}",
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Access-Control-Allow-Origin"], ORIGIN)
        self.assertIn("Link", response["Access-Control-Expose-Headers"])

    def test_the_token_endpoint_is_reachable_from_a_browser(self):
        # A public client doing PKCE has to POST here from script.
        response = self.preflight(path="/oauth2/token", method="POST")
        self.assertEqual(response.status_code, 204)
        self.assertEqual(response["Access-Control-Allow-Origin"], ORIGIN)

    def test_the_canvas_api_surface_is_covered_too(self):
        response = self.preflight(path="/api/v1/courses")
        self.assertEqual(response.status_code, 204)

    def test_the_dashboard_is_not_exposed_cross_origin(self):
        response = self.client.get("/apps/", HTTP_ORIGIN=ORIGIN)
        self.assertNotIn("Access-Control-Allow-Origin", response)

    def test_the_consent_screen_is_not_exposed_cross_origin(self):
        response = self.client.get("/oauth2/auth", HTTP_ORIGIN=ORIGIN)
        self.assertNotIn("Access-Control-Allow-Origin", response)

    def test_cookies_are_never_allowed_cross_origin(self):
        # With credentials allowed, any approved app's origin could script the
        # dashboard session of whoever visited it.
        response = self.preflight()
        self.assertNotIn("Access-Control-Allow-Credentials", response)

    def test_responses_vary_on_origin(self):
        with mock.patch(
            "gateway.views.requests.request", return_value=FakeUpstream()
        ), public_dns():
            response = self.client.get(
                "/ext/gifs/search",
                HTTP_ORIGIN="https://evil.example.com",
                HTTP_AUTHORIZATION=f"Bearer {self.access}",
            )
        # No allow-origin for the wrong origin, but Vary must still be set so a
        # cache cannot hand this response to the right one.
        self.assertNotIn("Access-Control-Allow-Origin", response)
        self.assertIn("Origin", response["Vary"])

    def test_a_request_without_an_origin_is_untouched(self):
        with mock.patch(
            "gateway.views.requests.request", return_value=FakeUpstream()
        ), public_dns():
            response = self.client.get(
                "/ext/gifs/search", HTTP_AUTHORIZATION=f"Bearer {self.access}"
            )
        self.assertNotIn("Access-Control-Allow-Origin", response)


@override_settings(PROXY_BASE_URL=PROXY)
class ApiKeyStyleTests(TestCase):
    """The Giphy shape: a base URL prefix plus a key in the query string."""

    def setUp(self):
        cache.clear()
        self.app = make_external_app(
            api_base_url="https://api.giphy.com/v1",
            credential_style=CredentialStyle.QUERY,
            credential_name="api_key",
            redirect_uris=[f"{ORIGIN}/cb"],
        )
        self.app.upstream_client_secret = "GIPHY-SECRET"
        self.app.save()
        self.grant = CanvasGrant.objects.create(
            app=self.app, tier=None, canvas_user_id="4321"
        )
        _, self.access, _ = ProxyToken.issue(self.grant)

    def call(self, path):
        with mock.patch(
            "gateway.views.requests.request", return_value=FakeUpstream()
        ) as request, public_dns():
            response = self.client.get(
                path, HTTP_AUTHORIZATION=f"Bearer {self.access}", HTTP_ORIGIN=ORIGIN
            )
        self.request_mock = request
        return response

    def test_the_caller_supplies_only_the_rest_of_the_url(self):
        response = self.call("/ext/gifs/search?q=cheeseburgers&limit=5")
        self.assertEqual(response.status_code, 200)
        sent = self.request_mock.call_args.kwargs
        self.assertEqual(sent["url"], "https://api.giphy.com/v1/gifs/search")
        self.assertIn(("q", "cheeseburgers"), sent["params"])
        self.assertIn(("limit", "5"), sent["params"])
        self.assertIn(("api_key", "GIPHY-SECRET"), sent["params"])

    def test_the_key_is_never_sent_to_the_browser(self):
        response = self.call("/ext/gifs/search?q=x")
        self.assertNotIn("GIPHY-SECRET", str(response.serialize_headers()))

    def test_the_key_is_never_written_to_the_audit_log(self):
        self.call("/ext/gifs/search?q=cheeseburgers")
        log = RequestLog.objects.get()
        self.assertEqual(log.path, "/gifs/search")
        self.assertEqual(log.query, "q=cheeseburgers")
        self.assertNotIn("GIPHY-SECRET", log.query)

    def test_a_caller_cannot_substitute_its_own_key(self):
        response = self.call("/ext/gifs/search?api_key=someone-elses")
        self.assertEqual(response.status_code, 403)

    def test_trending_and_search_share_one_registration(self):
        self.call("/ext/gifs/trending")
        self.assertEqual(
            self.request_mock.call_args.kwargs["url"],
            "https://api.giphy.com/v1/gifs/trending",
        )
