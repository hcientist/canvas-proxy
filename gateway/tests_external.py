"""External-API proxying: the SSRF guard, credential injection, and forwarding."""

import base64
import socket
from unittest import mock

from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.utils import timezone

from gateway.models import RequestLog
from gateway.netguard import (
    UnsafeUpstream,
    assert_safe_host,
    check_upstream_url,
    normalize_api_base_url,
    validate_api_base_url,
)
from gateway.tests import FakeUpstream
from oauth.models import CanvasGrant, ProxyToken
from registry.models import AppKind, CredentialStyle, ProxyApp
from registry.tests import make_tier, make_user

PROXY = "https://proxy.test"
API = "https://api.example.com/v2"


def dns(*addresses):
    """Patch name resolution to return exactly these addresses."""
    results = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in addresses]
    return mock.patch("gateway.netguard.socket.getaddrinfo", return_value=results)


def public_dns():
    return dns("93.184.216.34")


class NetguardResolutionTests(TestCase):
    def test_a_public_address_is_allowed(self):
        with public_dns():
            self.assertTrue(assert_safe_host("api.example.com"))

    def test_loopback_is_refused(self):
        with dns("127.0.0.1"), self.assertRaises(UnsafeUpstream):
            assert_safe_host("localhost.example.com")

    def test_private_ranges_are_refused(self):
        for address in ("10.0.0.5", "192.168.1.1", "172.16.0.9"):
            with self.subTest(address=address):
                with dns(address), self.assertRaises(UnsafeUpstream):
                    assert_safe_host("internal.example.com")

    def test_cloud_metadata_address_is_refused(self):
        with dns("169.254.169.254"), self.assertRaises(UnsafeUpstream):
            assert_safe_host("metadata.example.com")

    def test_ipv6_loopback_is_refused(self):
        with dns("::1"), self.assertRaises(UnsafeUpstream):
            assert_safe_host("v6.example.com")

    def test_a_mixed_answer_is_refused(self):
        # A name that returns one public and one private address must not pass:
        # the private one would still be reachable.
        with dns("93.184.216.34", "10.0.0.5"), self.assertRaises(UnsafeUpstream):
            assert_safe_host("sneaky.example.com")

    def test_an_unresolvable_name_is_refused(self):
        with mock.patch(
            "gateway.netguard.socket.getaddrinfo", side_effect=socket.gaierror("nope")
        ), self.assertRaises(UnsafeUpstream):
            assert_safe_host("does-not-exist.example.com")

    def test_an_empty_answer_is_refused(self):
        with dns(), self.assertRaises(UnsafeUpstream):
            assert_safe_host("empty.example.com")


class ApiBaseUrlValidationTests(TestCase):
    def test_a_public_https_url_is_accepted(self):
        with public_dns():
            self.assertEqual(validate_api_base_url(API), API)

    def test_http_is_refused(self):
        with public_dns(), self.assertRaises(ValidationError):
            validate_api_base_url("http://api.example.com")

    def test_credentials_in_the_url_are_refused(self):
        with public_dns(), self.assertRaises(ValidationError):
            validate_api_base_url("https://user:pw@api.example.com")

    def test_a_query_string_is_refused(self):
        with public_dns(), self.assertRaises(ValidationError):
            validate_api_base_url("https://api.example.com/v2?key=abc")

    def test_a_fragment_is_refused(self):
        with public_dns(), self.assertRaises(ValidationError):
            validate_api_base_url("https://api.example.com/v2#x")

    def test_a_database_port_is_refused(self):
        with public_dns(), self.assertRaises(ValidationError):
            validate_api_base_url("https://api.example.com:5432")

    def test_a_private_host_is_refused(self):
        with dns("10.1.2.3"), self.assertRaises(ValidationError):
            validate_api_base_url("https://internal.example.com")

    def test_trailing_slashes_are_normalised(self):
        self.assertEqual(normalize_api_base_url("https://a.example.com/v2/"), "https://a.example.com/v2")

    def test_request_time_check_reports_a_reason(self):
        with dns("10.0.0.1"):
            ok, reason = check_upstream_url("https://api.example.com/v2/items")
        self.assertFalse(ok)
        self.assertIn("private", reason)


def make_external_app(owner=None, **kwargs):
    defaults = {
        "name": "Weather Board",
        "kind": AppKind.EXTERNAL,
        "api_base_url": API,
        "redirect_uris": ["https://app.example.edu/callback"],
        "allowed_methods": ["GET"],
        "status": "approved",
    }
    defaults.update(kwargs)
    if owner is None:
        # Unique, so a test can build more than one app without colliding.
        owner = make_user(f"student{ProxyApp.objects.count() + 1}")
    app = ProxyApp(owner=owner, **defaults)
    app.save()
    return app


@override_settings(PROXY_BASE_URL=PROXY)
class ExternalGatewayTestCase(TestCase):
    def setUp(self):
        self.app = make_external_app()
        self.grant = CanvasGrant.objects.create(
            app=self.app,
            tier=None,
            canvas_user_id="4321",
            canvas_user_name="Ada Lovelace",
        )
        self.token, self.access, _ = ProxyToken.issue(self.grant)

    def call(self, path="/ext/items", method="get", upstream=None, token=None, **kwargs):
        with mock.patch(
            "gateway.views.requests.request", return_value=upstream or FakeUpstream()
        ) as request, public_dns():
            response = getattr(self.client, method)(
                path,
                HTTP_AUTHORIZATION=f"Bearer {token or self.access}",
                **kwargs,
            )
        self.request_mock = request
        return response

    def sent(self):
        return self.request_mock.call_args.kwargs


class ExternalForwardingTests(ExternalGatewayTestCase):
    def test_the_path_is_appended_to_the_registered_base_url(self):
        response = self.call("/ext/items/42")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.sent()["url"], f"{API}/items/42")

    def test_a_grant_without_a_canvas_token_still_works(self):
        # External grants deliberately hold no Canvas token.
        self.assertFalse(self.grant.holds_canvas_token)
        self.assertEqual(self.call().status_code, 200)

    def test_no_authorization_header_is_sent_when_the_api_needs_none(self):
        self.call()
        self.assertNotIn("Authorization", self.sent()["headers"])

    def test_the_callers_token_is_not_forwarded(self):
        self.call()
        self.assertNotIn(self.access, str(self.sent()["headers"]))

    def test_query_parameters_are_forwarded(self):
        self.call("/ext/items?q=rain&page=2")
        params = self.sent()["params"]
        self.assertIn(("q", "rain"), params)
        self.assertIn(("page", "2"), params)

    def test_methods_outside_the_registration_are_refused(self):
        response = self.call("/ext/items", method="post")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"], "insufficient_scope")

    def test_an_allowed_method_passes(self):
        self.app.allowed_methods = ["GET", "POST"]
        self.app.save()
        self.assertEqual(self.call("/ext/items", method="post").status_code, 200)

    def test_path_rules_further_restrict_the_app(self):
        self.app.path_rules = [{"methods": ["GET"], "pattern": r"^/public(/|$)"}]
        self.app.save()
        self.assertEqual(self.call("/ext/private/data").status_code, 403)
        self.assertEqual(self.call("/ext/public/data").status_code, 200)

    def test_pagination_links_are_rewritten_to_the_ext_prefix(self):
        link = f'<{API}/items?page=2>; rel="next"'
        response = self.call(upstream=FakeUpstream(headers={"Link": link}))
        self.assertEqual(response["Link"], f'<{PROXY}/ext/items?page=2>; rel="next"')

    def test_a_redirect_off_the_api_host_passes_through_untouched(self):
        elsewhere = "https://cdn.example.net/file.pdf?sig=abc"
        response = self.call(
            upstream=FakeUpstream(status_code=302, headers={"Location": elsewhere})
        )
        self.assertEqual(response["Location"], elsewhere)

    def test_upstream_status_and_body_are_preserved(self):
        response = self.call(upstream=FakeUpstream(status_code=404, body=b'{"e":1}'))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(b"".join(response.streaming_content), b'{"e":1}')

    def test_calls_are_audited(self):
        self.call("/ext/items?q=rain")
        log = RequestLog.objects.get()
        self.assertEqual(log.app, self.app)
        self.assertEqual(log.path, "/items")
        self.assertEqual(log.canvas_user_id, "4321")


class ExternalCredentialTests(ExternalGatewayTestCase):
    def set_style(self, style, name="", client_id="", secret="s3cret"):
        self.app.credential_style = style
        self.app.credential_name = name
        self.app.upstream_client_id = client_id
        self.app.upstream_client_secret = secret
        self.app.save()

    def test_bearer(self):
        self.set_style(CredentialStyle.BEARER)
        self.call()
        self.assertEqual(self.sent()["headers"]["Authorization"], "Bearer s3cret")

    def test_basic(self):
        self.set_style(CredentialStyle.BASIC, client_id="alice")
        self.call()
        expected = base64.b64encode(b"alice:s3cret").decode()
        self.assertEqual(self.sent()["headers"]["Authorization"], f"Basic {expected}")

    def test_custom_header(self):
        self.set_style(CredentialStyle.HEADER, name="X-Api-Key")
        self.call()
        self.assertEqual(self.sent()["headers"]["X-Api-Key"], "s3cret")

    def test_query_parameter(self):
        self.set_style(CredentialStyle.QUERY, name="api_key")
        self.call("/ext/items?q=rain")
        self.assertIn(("api_key", "s3cret"), self.sent()["params"])

    def test_the_secret_is_encrypted_at_rest(self):
        self.set_style(CredentialStyle.BEARER)
        self.app.refresh_from_db()
        self.assertNotIn("s3cret", self.app.upstream_client_secret_encrypted)
        self.assertEqual(self.app.upstream_client_secret, "s3cret")

    def test_the_caller_cannot_supply_the_credential_parameter(self):
        # Otherwise a caller could override the stored key, or probe which
        # value the upstream accepts.
        self.set_style(CredentialStyle.QUERY, name="api_key")
        response = self.call("/ext/items?api_key=mine")
        self.assertEqual(response.status_code, 403)
        self.assertIn("api_key", response.json()["error_description"])

    def test_a_caller_supplied_authorization_header_is_replaced(self):
        self.set_style(CredentialStyle.BEARER)
        self.call(HTTP_X_FORWARDED_FOR="1.2.3.4")
        self.assertEqual(self.sent()["headers"]["Authorization"], "Bearer s3cret")

    def test_no_credentials_are_sent_for_a_public_api(self):
        self.set_style(CredentialStyle.NONE, secret="")
        self.call()
        headers = self.sent()["headers"]
        self.assertNotIn("Authorization", headers)


class ExternalSsrfTests(ExternalGatewayTestCase):
    def test_a_host_that_turns_private_after_approval_is_refused(self):
        # The registration passed review, but DNS now answers with a private
        # address. The request-time check is what catches this.
        with mock.patch("gateway.views.requests.request") as request, dns("10.0.0.5"):
            response = self.client.get(
                "/ext/items", HTTP_AUTHORIZATION=f"Bearer {self.access}"
            )
        self.assertEqual(response.status_code, 502)
        request.assert_not_called()

    def test_the_refusal_is_audited(self):
        with mock.patch("gateway.views.requests.request"), dns("127.0.0.1"):
            self.client.get("/ext/items", HTTP_AUTHORIZATION=f"Bearer {self.access}")
        self.assertTrue(RequestLog.objects.get().was_denied)


@override_settings(PROXY_BASE_URL=PROXY)
class AnonymousExternalProxyTests(TestCase):
    """Tests for /ext/public/<client_id>/... (origin-gated, no bearer token)."""

    def setUp(self):
        self.app = make_external_app(
            allow_anonymous=True,
            credential_style=CredentialStyle.QUERY,
            credential_name="api_key",
            redirect_uris=["https://student.github.io/Rhyphy/"],
        )
        self.app.upstream_client_secret = "giphy-secret"
        self.app.save()

    def url(self, path="items"):
        return f"/ext/public/{self.app.client_id}/{path}"

    def call(self, path="items", origin="https://student.github.io", upstream=None, **kwargs):
        with mock.patch(
            "gateway.views.requests.request", return_value=upstream or FakeUpstream()
        ) as request, public_dns():
            response = self.client.get(
                self.url(path),
                HTTP_ORIGIN=origin,
                **kwargs,
            )
        self.request_mock = request
        return response

    def sent(self):
        return self.request_mock.call_args.kwargs

    def test_a_request_from_a_registered_origin_is_forwarded(self):
        response = self.call()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.sent()["url"], f"{API}/items")

    def test_credentials_are_attached_server_side(self):
        self.call("gifs/search?q=cats")
        self.assertIn(("api_key", "giphy-secret"), self.sent()["params"])

    def test_no_bearer_token_is_required(self):
        # The request has no Authorization header at all.
        response = self.call()
        self.assertEqual(response.status_code, 200)

    def test_an_unknown_origin_is_refused(self):
        response = self.call(origin="https://evil.example.com")
        self.assertEqual(response.status_code, 403)
        self.assertIn("origin", response.json()["error_description"].lower())

    def test_a_missing_origin_is_refused(self):
        with mock.patch("gateway.views.requests.request") as request, public_dns():
            response = self.client.get(self.url())
        self.assertEqual(response.status_code, 403)
        request.assert_not_called()

    def test_an_unknown_client_id_returns_404(self):
        with mock.patch("gateway.views.requests.request"), public_dns():
            response = self.client.get(
                "/ext/public/00000000000000000000000000000000/items",
                HTTP_ORIGIN="https://student.github.io",
            )
        self.assertEqual(response.status_code, 404)

    def test_a_non_anonymous_app_is_refused(self):
        self.app.allow_anonymous = False
        self.app.save()
        response = self.call()
        self.assertEqual(response.status_code, 403)

    def test_a_suspended_app_is_refused(self):
        self.app.status = "suspended"
        self.app.save()
        response = self.call()
        self.assertEqual(response.status_code, 403)

    def test_method_restrictions_are_enforced(self):
        with mock.patch("gateway.views.requests.request"), public_dns():
            response = self.client.post(
                self.url(),
                HTTP_ORIGIN="https://student.github.io",
            )
        self.assertEqual(response.status_code, 403)

    def test_the_credential_parameter_cannot_be_supplied_by_the_caller(self):
        response = self.call("items?api_key=mine")
        self.assertEqual(response.status_code, 403)

    def test_calls_are_audited(self):
        self.call("items?q=cats")
        log = RequestLog.objects.get()
        self.assertEqual(log.app, self.app)
        self.assertEqual(log.path, "/items")
        self.assertEqual(log.canvas_user_id, "")

    def test_ssrf_is_checked_at_request_time(self):
        with mock.patch("gateway.views.requests.request") as request, dns("10.0.0.5"):
            response = self.client.get(
                self.url(),
                HTTP_ORIGIN="https://student.github.io",
            )
        self.assertEqual(response.status_code, 502)
        request.assert_not_called()


class PrefixSeparationTests(ExternalGatewayTestCase):
    def test_an_external_app_cannot_use_the_canvas_prefix(self):
        with mock.patch("gateway.views.requests.request") as request:
            response = self.client.get(
                "/api/v1/courses", HTTP_AUTHORIZATION=f"Bearer {self.access}"
            )
        self.assertEqual(response.status_code, 404)
        request.assert_not_called()

    def test_a_canvas_app_cannot_use_the_external_prefix(self):
        tier = make_tier()
        canvas_app = ProxyApp.objects.create(
            owner=make_user("dev2"),
            tier=tier,
            name="Canvas App",
            redirect_uris=["https://a.example.edu/cb"],
            status="approved",
        )
        grant = CanvasGrant.objects.create(
            app=canvas_app,
            tier=tier,
            canvas_user_id="9",
            access_token_expires_at=timezone.now() + timezone.timedelta(hours=1),
        )
        grant.store_canvas_payload({"access_token": "t", "expires_in": 3600})
        grant.save()
        _, access, _ = ProxyToken.issue(grant)

        with mock.patch("gateway.views.requests.request") as request:
            response = self.client.get("/ext/items", HTTP_AUTHORIZATION=f"Bearer {access}")
        self.assertEqual(response.status_code, 404)
        request.assert_not_called()
