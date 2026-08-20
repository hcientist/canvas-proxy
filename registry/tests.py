from unittest import mock

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.urls import reverse

from canvasclient import client
from oauth.models import CanvasGrant, ProxyToken
from registry.models import AccessTier, AppStatus, ProxyApp, validate_redirect_uri

User = get_user_model()


def make_tier(slug="auth_only", **kwargs):
    defaults = {
        "name": "Read-only",
        "canvas_client_id": "10000000000001",
        "allowed_methods": ["GET", "HEAD"],
        "path_rules": [{"methods": ["GET"], "pattern": r"^/api/v1/courses(/|$)"}],
        "denied_patterns": [r"^/api/graphql"],
    }
    defaults.update(kwargs)
    tier = AccessTier(slug=slug, **defaults)
    tier.canvas_client_secret = "canvas-secret"
    tier.save()
    return tier


def make_user(username="dev", **kwargs):
    return User.objects.create_user(username=username, password="pw", **kwargs)


def make_app(owner, tier, status=AppStatus.APPROVED, **kwargs):
    defaults = {
        "name": "Gradebook Sync",
        "redirect_uris": ["https://app.example.edu/callback"],
    }
    defaults.update(kwargs)
    app = ProxyApp(owner=owner, tier=tier, status=status, **defaults)
    app.save()
    return app


class RedirectURIValidationTests(TestCase):
    def test_https_uri_is_accepted(self):
        self.assertEqual(
            validate_redirect_uri("https://a.example.edu/cb"),
            "https://a.example.edu/cb",
        )

    def test_localhost_may_use_http(self):
        validate_redirect_uri("http://localhost:3000/cb")

    def test_plain_http_elsewhere_is_rejected(self):
        with self.assertRaises(ValidationError):
            validate_redirect_uri("http://evil.example.com/cb")

    def test_wildcards_are_rejected(self):
        with self.assertRaises(ValidationError):
            validate_redirect_uri("https://*.example.edu/cb")

    def test_fragments_are_rejected(self):
        with self.assertRaises(ValidationError):
            validate_redirect_uri("https://a.example.edu/cb#token")

    def test_relative_uri_is_rejected(self):
        with self.assertRaises(ValidationError):
            validate_redirect_uri("/callback")


class RedirectURIMatchingTests(TestCase):
    def setUp(self):
        self.app = make_app(make_user(), make_tier())

    def test_exact_match_allowed(self):
        self.assertTrue(self.app.redirect_uri_allowed("https://app.example.edu/callback"))

    def test_trailing_slash_is_a_different_uri(self):
        self.assertFalse(self.app.redirect_uri_allowed("https://app.example.edu/callback/"))

    def test_prefix_extension_is_refused(self):
        self.assertFalse(
            self.app.redirect_uri_allowed("https://app.example.edu/callback/../evil")
        )

    def test_other_host_is_refused(self):
        self.assertFalse(self.app.redirect_uri_allowed("https://evil.example.com/callback"))

    def test_empty_is_refused(self):
        self.assertFalse(self.app.redirect_uri_allowed(""))


class TierPermissionTests(TestCase):
    def setUp(self):
        self.read = make_tier()
        self.full = make_tier(
            slug="read_write",
            name="Read/write",
            allowed_methods=[],
            path_rules=[],
            denied_patterns=[],
        )

    def test_allowed_path_and_method(self):
        allowed, _ = self.read.permits("GET", "/api/v1/courses/1/assignments")
        self.assertTrue(allowed)

    def test_write_method_refused_on_read_tier(self):
        allowed, reason = self.read.permits("POST", "/api/v1/courses/1/assignments")
        self.assertFalse(allowed)
        self.assertIn("only GET, HEAD", reason)

    def test_path_outside_allowlist_refused(self):
        allowed, reason = self.read.permits("GET", "/api/v1/accounts/1/users")
        self.assertFalse(allowed)
        self.assertIn("allowlist", reason)

    def test_denied_pattern_beats_allowlist(self):
        allowed, _ = self.read.permits("GET", "/api/graphql")
        self.assertFalse(allowed)

    def test_empty_rules_allow_everything(self):
        self.assertTrue(self.full.permits("DELETE", "/api/v1/accounts/1/users/2")[0])

    def test_malformed_pattern_does_not_widen_access(self):
        tier = make_tier(slug="broken", path_rules=[{"methods": ["GET"], "pattern": "["}])
        self.assertFalse(tier.permits("GET", "/api/v1/courses")[0])


class ClientSecretTests(TestCase):
    def setUp(self):
        self.app = make_app(make_user(), make_tier())

    def test_secret_is_not_stored_in_the_clear(self):
        raw = self.app.rotate_secret()
        self.assertNotIn(raw, self.app.client_secret_hash)
        self.assertTrue(self.app.check_secret(raw))

    def test_wrong_secret_is_refused(self):
        self.app.rotate_secret()
        self.assertFalse(self.app.check_secret("nope"))

    def test_rotation_invalidates_the_old_secret(self):
        first = self.app.rotate_secret()
        self.app.rotate_secret()
        self.assertFalse(self.app.check_secret(first))

    def test_a_rotated_secret_survives_a_later_partial_save(self):
        # approve() saves a field subset; the new hash must already be on disk.
        raw = self.app.rotate_secret()
        self.app.approve(make_user("staff", is_staff=True))
        self.app.refresh_from_db()
        self.assertTrue(self.app.check_secret(raw))

    def test_public_clients_never_authenticate_by_secret(self):
        self.app.is_public_client = True
        raw = self.app.rotate_secret()
        self.assertFalse(self.app.check_secret(raw))


class ApprovalWorkflowTests(TestCase):
    def setUp(self):
        self.owner = make_user("owner")
        self.staff = make_user("staff", is_staff=True)
        self.tier = make_tier()
        self.app = make_app(self.owner, self.tier, status=AppStatus.PENDING)

    def test_pending_app_is_not_usable(self):
        self.assertFalse(self.app.is_usable)

    def test_approval_makes_it_usable(self):
        self.app.approve(self.staff, "Looks fine")
        self.assertTrue(self.app.is_usable)
        self.assertEqual(self.app.reviewed_by, self.staff)

    def test_suspension_revokes_live_grants(self):
        self.app.approve(self.staff)
        grant = CanvasGrant.objects.create(
            app=self.app,
            tier=self.tier,
            canvas_user_id="7",
        )
        grant.store_canvas_payload({"access_token": "canvas-token", "expires_in": 3600})
        grant.save()
        _, _, _ = ProxyToken.issue(grant)

        with mock.patch.object(client, "revoke", return_value=True) as revoke:
            self.app.suspend(self.staff, "Abuse report")

        grant.refresh_from_db()
        self.assertIsNotNone(grant.revoked_at)
        self.assertFalse(self.app.is_usable)
        # The whole point of suspending is that nothing keeps working.
        revoke.assert_called_once_with("canvas-token")
        self.assertFalse(ProxyToken.objects.filter(revoked_at__isnull=True).exists())

    def test_disabling_a_tier_disables_its_apps(self):
        self.app.approve(self.staff)
        self.tier.is_active = False
        self.tier.save()
        self.app.refresh_from_db()
        self.assertFalse(self.app.is_usable)

    def test_staff_can_approve_through_the_review_view(self):
        self.client.force_login(self.staff)
        response = self.client.post(
            reverse("registry:review_app", args=[self.app.pk]),
            {"decision": "approve", "notes": "ok"},
        )
        self.assertEqual(response.status_code, 302)
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, AppStatus.APPROVED)

    def test_non_staff_cannot_reach_the_review_queue(self):
        self.client.force_login(self.owner)
        response = self.client.get(reverse("registry:review_queue"))
        self.assertNotEqual(response.status_code, 200)

    def test_rejection_requires_notes(self):
        self.client.force_login(self.staff)
        self.client.post(
            reverse("registry:review_app", args=[self.app.pk]),
            {"decision": "reject", "notes": ""},
        )
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, AppStatus.PENDING)


class DashboardTests(TestCase):
    def setUp(self):
        self.owner = make_user("owner")
        self.other = make_user("other")
        self.tier = make_tier()
        self.app = make_app(self.owner, self.tier)

    def test_owner_sees_their_app(self):
        self.client.force_login(self.owner)
        response = self.client.get(reverse("registry:app_detail", args=[self.app.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.app.client_id)

    def test_another_developer_cannot_see_it(self):
        self.client.force_login(self.other)
        response = self.client.get(reverse("registry:app_detail", args=[self.app.pk]))
        self.assertEqual(response.status_code, 302)

    def test_another_developer_cannot_edit_it(self):
        self.client.force_login(self.other)
        response = self.client.get(reverse("registry:app_edit", args=[self.app.pk]))
        self.assertEqual(response.status_code, 404)

    def test_anonymous_is_sent_to_sign_in(self):
        response = self.client.get(reverse("registry:app_list"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response["Location"])

    def test_creating_an_app_reveals_the_secret_once(self):
        self.client.force_login(self.owner)
        response = self.client.post(
            reverse("registry:app_create"),
            {
                "name": "New App",
                "description": "Testing",
                "homepage_url": "",
                "tier": self.tier.pk,
                "redirect_uris": "https://new.example.edu/cb",
            },
            follow=True,
        )
        self.assertEqual(response.status_code, 200)
        app = ProxyApp.objects.get(name="New App")
        self.assertEqual(app.status, AppStatus.DRAFT)
        self.assertContains(response, "Copy this now")

        # Reloading the page must not show it again.
        again = self.client.get(reverse("registry:app_detail", args=[app.pk]))
        self.assertNotContains(again, "Copy this now")

    def test_bad_redirect_uri_is_rejected_at_registration(self):
        self.client.force_login(self.owner)
        response = self.client.post(
            reverse("registry:app_create"),
            {
                "name": "Bad App",
                "description": "Testing",
                "homepage_url": "",
                "tier": self.tier.pk,
                "redirect_uris": "http://evil.example.com/cb",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(ProxyApp.objects.filter(name="Bad App").exists())

    def test_changing_redirect_uris_sends_an_approved_app_back_for_review(self):
        self.client.force_login(self.owner)
        self.client.post(
            reverse("registry:app_edit", args=[self.app.pk]),
            {
                "name": self.app.name,
                "description": "",
                "homepage_url": "",
                "tier": self.tier.pk,
                "redirect_uris": "https://app.example.edu/callback\nhttps://app.example.edu/other",
            },
        )
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, AppStatus.PENDING)

    def test_renaming_alone_does_not_reset_approval(self):
        self.client.force_login(self.owner)
        self.client.post(
            reverse("registry:app_edit", args=[self.app.pk]),
            {
                "name": "Renamed",
                "description": "",
                "homepage_url": "",
                "tier": self.tier.pk,
                "redirect_uris": "https://app.example.edu/callback",
            },
        )
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, AppStatus.APPROVED)
        self.assertEqual(self.app.name, "Renamed")


@override_settings(CANVAS_BASE_URL="https://canvas.test")
class HomePageTests(TestCase):
    def test_home_lists_active_tiers(self):
        make_tier()
        make_tier(slug="read_write", name="Read/write", is_active=False)
        response = self.client.get(reverse("registry:home"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Read-only")
        self.assertNotContains(response, "Read/write")
