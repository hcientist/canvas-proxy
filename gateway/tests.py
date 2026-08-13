from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from canvasclient import client
from gateway.models import RequestLog
from oauth.models import CanvasGrant, ProxyToken
from registry.models import AppStatus
from registry.tests import make_app, make_tier, make_user

CANVAS = "https://canvas.test"
PROXY = "https://proxy.test"


class FakeUpstream:
    """Stands in for a `requests.Response` from Canvas."""

    def __init__(self, status_code=200, headers=None, body=b'{"ok":true}'):
        self.status_code = status_code
        self.headers = headers or {"Content-Type": "application/json"}
        self._body = body

    def iter_content(self, chunk_size=None):
        yield self._body


@override_settings(CANVAS_BASE_URL=CANVAS, PROXY_BASE_URL=PROXY)
class GatewayTestCase(TestCase):
    def setUp(self):
        cache.clear()
        self.tier = make_tier()
        self.app = make_app(make_user("owner"), self.tier)
        self.grant = CanvasGrant.objects.create(
            app=self.app,
            tier=self.tier,
            canvas_user_id="4321",
            canvas_user_name="Ada Lovelace",
            access_token_expires_at=timezone.now() + timezone.timedelta(hours=1),
        )
        self.grant.store_canvas_payload(
            {"access_token": "canvas-access-token", "refresh_token": "r", "expires_in": 3600}
        )
        self.grant.save()
        self.token, self.access, self.refresh = ProxyToken.issue(self.grant)

    def call(self, path="/api/v1/courses", method="get", token=None, upstream=None, **kwargs):
        headers = {"HTTP_AUTHORIZATION": f"Bearer {token or self.access}"}
        headers.update(kwargs.pop("extra", {}))
        with mock.patch(
            "gateway.views.requests.request", return_value=upstream or FakeUpstream()
        ) as request:
            response = getattr(self.client, method)(path, **headers, **kwargs)
        self.request_mock = request
        return response


class ProxyAuthenticationTests(GatewayTestCase):
    def test_a_valid_token_reaches_canvas(self):
        response = self.call()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content), b'{"ok":true}')

        call = self.request_mock.call_args.kwargs
        self.assertEqual(call["url"], f"{CANVAS}/api/v1/courses")
        self.assertEqual(call["headers"]["Authorization"], "Bearer canvas-access-token")

    def test_missing_token_is_401(self):
        response = self.client.get("/api/v1/courses")
        self.assertEqual(response.status_code, 401)
        self.assertIn("Bearer", response["WWW-Authenticate"])

    def test_unknown_token_is_401(self):
        response = self.call(token="made-up")
        self.assertEqual(response.status_code, 401)

    def test_expired_token_is_401(self):
        ProxyToken.objects.update(expires_at=timezone.now() - timezone.timedelta(seconds=1))
        response = self.call()
        self.assertEqual(response.status_code, 401)
        self.assertIn("expired", response.json()["error_description"])

    def test_revoked_token_is_401(self):
        self.token.revoke()
        self.assertEqual(self.call().status_code, 401)

    def test_revoked_grant_is_401(self):
        CanvasGrant.objects.update(revoked_at=timezone.now())
        self.assertEqual(self.call().status_code, 401)

    def test_suspended_app_is_403(self):
        self.app.status = AppStatus.SUSPENDED
        self.app.save()
        response = self.call()
        self.assertEqual(response.status_code, 403)

    def test_disabled_tier_is_403(self):
        self.tier.is_active = False
        self.tier.save()
        self.assertEqual(self.call().status_code, 403)

    def test_the_apps_own_token_is_not_forwarded_upstream(self):
        self.call()
        headers = self.request_mock.call_args.kwargs["headers"]
        self.assertNotIn(self.access, str(headers))


class TierEnforcementTests(GatewayTestCase):
    def test_write_is_refused_on_a_read_tier(self):
        response = self.call(method="post", path="/api/v1/courses")
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["error"], "insufficient_scope")

    def test_path_outside_the_allowlist_is_refused(self):
        response = self.call(path="/api/v1/accounts/1/users")
        self.assertEqual(response.status_code, 403)

    def test_graphql_is_refused_on_a_read_tier(self):
        response = self.call(method="post", path="/api/graphql")
        self.assertEqual(response.status_code, 403)

    def test_refused_requests_never_reach_canvas(self):
        with mock.patch("gateway.views.requests.request") as request:
            self.client.post(
                "/api/v1/courses", HTTP_AUTHORIZATION=f"Bearer {self.access}"
            )
        request.assert_not_called()

    def test_masquerade_is_blocked_by_default(self):
        response = self.call(path="/api/v1/courses?as_user_id=99")
        self.assertEqual(response.status_code, 403)
        self.assertIn("as_user_id", response.json()["error_description"])

    def test_masquerade_is_allowed_when_the_tier_permits_it(self):
        self.tier.allow_masquerade = True
        self.tier.save()
        response = self.call(path="/api/v1/courses?as_user_id=99")
        self.assertEqual(response.status_code, 200)

    def test_an_inline_access_token_param_is_refused(self):
        response = self.call(path="/api/v1/courses?access_token=sneaky")
        self.assertEqual(response.status_code, 403)
        self.assertIn("access_token", response.json()["error_description"])

    def test_ordinary_query_params_are_forwarded(self):
        self.call(path="/api/v1/courses?per_page=50&enrollment_state=active")
        params = self.request_mock.call_args.kwargs["params"]
        self.assertIn(("per_page", "50"), params)
        self.assertIn(("enrollment_state", "active"), params)

    def test_repeated_query_params_survive(self):
        self.call(path="/api/v1/courses?include[]=term&include[]=teachers")
        params = self.request_mock.call_args.kwargs["params"]
        self.assertEqual(
            [value for name, value in params if name == "include[]"],
            ["term", "teachers"],
        )


class ResponseRelayTests(GatewayTestCase):
    def test_pagination_links_are_rewritten_to_the_proxy(self):
        link = (
            f'<{CANVAS}/api/v1/courses?page=2>; rel="next", '
            f'<{CANVAS}/api/v1/courses?page=9>; rel="last"'
        )
        response = self.call(upstream=FakeUpstream(headers={"Link": link}))
        self.assertEqual(
            response["Link"],
            f'<{PROXY}/api/v1/courses?page=2>; rel="next", '
            f'<{PROXY}/api/v1/courses?page=9>; rel="last"',
        )
        self.assertNotIn(CANVAS, response["Link"])

    def test_file_download_redirects_pass_through_untouched(self):
        presigned = "https://instructure-uploads.s3.amazonaws.com/f.pdf?X-Amz-Signature=abc"
        response = self.call(
            upstream=FakeUpstream(status_code=302, headers={"Location": presigned})
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response["Location"], presigned)

    def test_api_redirects_are_rewritten(self):
        response = self.call(
            upstream=FakeUpstream(
                status_code=302, headers={"Location": f"{CANVAS}/api/v1/courses/1"}
            )
        )
        self.assertEqual(response["Location"], f"{PROXY}/api/v1/courses/1")

    def test_upstream_cookies_are_not_relayed(self):
        response = self.call(
            upstream=FakeUpstream(headers={"Set-Cookie": "canvas_session=abc"})
        )
        self.assertNotIn("Set-Cookie", response)

    def test_upstream_status_codes_are_preserved(self):
        response = self.call(upstream=FakeUpstream(status_code=404, body=b"{}"))
        self.assertEqual(response.status_code, 404)

    def test_rate_limit_headers_from_canvas_are_passed_on(self):
        response = self.call(
            upstream=FakeUpstream(headers={"X-Rate-Limit-Remaining": "412.5"})
        )
        self.assertEqual(response["X-Rate-Limit-Remaining"], "412.5")


class UpstreamFailureTests(GatewayTestCase):
    def test_timeouts_become_504(self):
        import requests

        with mock.patch(
            "gateway.views.requests.request", side_effect=requests.Timeout()
        ):
            response = self.client.get(
                "/api/v1/courses", HTTP_AUTHORIZATION=f"Bearer {self.access}"
            )
        self.assertEqual(response.status_code, 504)

    def test_connection_errors_become_502(self):
        import requests

        with mock.patch(
            "gateway.views.requests.request",
            side_effect=requests.ConnectionError("down"),
        ):
            response = self.client.get(
                "/api/v1/courses", HTTP_AUTHORIZATION=f"Bearer {self.access}"
            )
        self.assertEqual(response.status_code, 502)

    def test_a_failed_canvas_refresh_becomes_502(self):
        CanvasGrant.objects.update(
            access_token_expires_at=timezone.now() - timezone.timedelta(seconds=1)
        )
        with mock.patch.object(
            client, "refresh_token", side_effect=client.CanvasError("revoked")
        ):
            response = self.client.get(
                "/api/v1/courses", HTTP_AUTHORIZATION=f"Bearer {self.access}"
            )
        self.assertEqual(response.status_code, 502)

    def test_a_stale_canvas_token_is_refreshed_mid_request(self):
        CanvasGrant.objects.update(
            access_token_expires_at=timezone.now() - timezone.timedelta(seconds=1)
        )
        with mock.patch.object(
            client,
            "refresh_token",
            return_value={"access_token": "fresh", "expires_in": 3600},
        ):
            response = self.call()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            self.request_mock.call_args.kwargs["headers"]["Authorization"],
            "Bearer fresh",
        )


@override_settings(RATE_LIMIT_PER_MINUTE=3, CANVAS_BASE_URL=CANVAS, PROXY_BASE_URL=PROXY)
class RateLimitTests(GatewayTestCase):
    def test_requests_beyond_the_ceiling_are_429(self):
        for _ in range(3):
            self.assertEqual(self.call().status_code, 200)
        response = self.call()
        self.assertEqual(response.status_code, 429)
        self.assertIn("Retry-After", response)

    def test_the_limit_is_per_app(self):
        other_app = make_app(make_user("other"), self.tier, name="Other")
        other_grant = CanvasGrant.objects.create(
            app=other_app,
            tier=self.tier,
            canvas_user_id="1",
            access_token_expires_at=timezone.now() + timezone.timedelta(hours=1),
        )
        other_grant.store_canvas_payload({"access_token": "t", "expires_in": 3600})
        other_grant.save()
        _, other_access, _ = ProxyToken.issue(other_grant)

        for _ in range(3):
            self.call()
        self.assertEqual(self.call().status_code, 429)
        self.assertEqual(self.call(token=other_access).status_code, 200)


class AuditLogTests(GatewayTestCase):
    def test_successful_calls_are_logged(self):
        self.call(path="/api/v1/courses?per_page=10")
        log = RequestLog.objects.get()
        self.assertEqual(log.app, self.app)
        self.assertEqual(log.grant, self.grant)
        self.assertEqual(log.method, "GET")
        self.assertEqual(log.path, "/api/v1/courses")
        self.assertEqual(log.query, "per_page=10")
        self.assertEqual(log.status_code, 200)
        self.assertEqual(log.canvas_user_id, "4321")
        self.assertFalse(log.was_denied)

    def test_denials_are_logged_with_a_reason(self):
        self.call(method="post", path="/api/v1/courses")
        log = RequestLog.objects.get()
        self.assertEqual(log.status_code, 403)
        self.assertTrue(log.was_denied)

    def test_unauthenticated_attempts_are_logged(self):
        self.client.get("/api/v1/courses")
        log = RequestLog.objects.get()
        self.assertIsNone(log.app)
        self.assertEqual(log.status_code, 401)

    def test_last_used_timestamps_are_updated(self):
        self.call()
        self.token.refresh_from_db()
        self.grant.refresh_from_db()
        self.assertIsNotNone(self.token.last_used_at)
        self.assertIsNotNone(self.grant.last_used_at)


class HeaderHandlingTests(GatewayTestCase):
    def test_client_cookies_are_not_forwarded(self):
        self.client.cookies["sessionid"] = "should-not-travel"
        self.call()
        headers = self.request_mock.call_args.kwargs["headers"]
        self.assertNotIn("cookie", {k.lower() for k in headers})

    def test_content_type_is_forwarded(self):
        self.tier.allowed_methods = ["GET", "POST"]
        self.tier.path_rules = [
            {"methods": ["GET", "POST"], "pattern": r"^/api/v1/courses(/|$)"}
        ]
        self.tier.save()
        self.call(
            method="post",
            path="/api/v1/courses",
            data='{"a":1}',
            content_type="application/json",
        )
        headers = self.request_mock.call_args.kwargs["headers"]
        self.assertEqual(headers["content-type"], "application/json")

    def test_request_bodies_are_forwarded(self):
        self.tier.allowed_methods = ["GET", "POST"]
        self.tier.path_rules = [
            {"methods": ["GET", "POST"], "pattern": r"^/api/v1/courses(/|$)"}
        ]
        self.tier.save()
        self.call(
            method="post",
            path="/api/v1/courses",
            data='{"name":"x"}',
            content_type="application/json",
        )
        self.assertEqual(self.request_mock.call_args.kwargs["data"], b'{"name":"x"}')

    def test_forwarded_for_headers_from_the_client_are_dropped(self):
        self.call(extra={"HTTP_X_FORWARDED_FOR": "10.0.0.9"})
        headers = self.request_mock.call_args.kwargs["headers"]
        self.assertNotIn("x-forwarded-for", {k.lower() for k in headers})
