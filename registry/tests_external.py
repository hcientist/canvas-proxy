"""Registering, editing and reviewing an external-API app."""

from django.test import TestCase
from django.urls import reverse

from gateway.tests_external import API, dns, make_external_app, public_dns
from registry.models import AppKind, AppStatus, CredentialStyle, ProxyApp
from registry.tests import make_tier, make_user


class ExternalAppModelTests(TestCase):
    def setUp(self):
        self.app = make_external_app()

    def test_it_is_not_usable_without_an_api_base_url(self):
        self.app.api_base_url = ""
        self.assertFalse(self.app.is_usable)

    def test_an_approved_app_with_a_base_url_is_usable(self):
        self.assertTrue(self.app.is_usable)

    def test_a_pending_app_is_not_usable(self):
        self.app.status = AppStatus.PENDING
        self.assertFalse(self.app.is_usable)

    def test_it_needs_no_tier(self):
        self.assertIsNone(self.app.tier)
        self.assertTrue(self.app.is_external)

    def test_labels_describe_the_upstream(self):
        self.assertEqual(self.app.upstream_label, "api.example.com")
        self.assertIn("api.example.com", self.app.access_label)

    def test_permits_uses_the_apps_own_methods(self):
        allowed, _ = self.app.permits("GET", "/items")
        self.assertTrue(allowed)
        allowed, reason = self.app.permits("DELETE", "/items")
        self.assertFalse(allowed)
        self.assertIn("only GET", reason)

    def test_a_canvas_app_without_a_tier_permits_nothing(self):
        orphan = ProxyApp(
            owner=make_user("x"), name="Orphan", redirect_uris=["https://a.test/cb"]
        )
        allowed, reason = orphan.permits("GET", "/api/v1/courses")
        self.assertFalse(allowed)
        self.assertIn("no access tier", reason)

    def test_the_base_url_is_stored_without_a_trailing_slash(self):
        app = make_external_app(api_base_url="https://api.example.com/v2/")
        self.assertEqual(app.api_base_url, "https://api.example.com/v2")


class ExternalRegistrationTests(TestCase):
    def setUp(self):
        self.owner = make_user("student")
        self.client.force_login(self.owner)

    def form_data(self, **overrides):
        data = {
            "name": "Weather Board",
            "description": "Shows the forecast on a course page.",
            "homepage_url": "",
            "api_base_url": API,
            "redirect_uris": "https://app.example.edu/callback",
            "allowed_methods": ["GET"],
            "credential_style": CredentialStyle.NONE,
            "credential_name": "",
            "upstream_client_id": "",
            "upstream_client_secret": "",
        }
        data.update(overrides)
        return data

    def post(self, **overrides):
        with public_dns():
            return self.client.post(
                reverse("registry:app_create_external"), self.form_data(**overrides)
            )

    def test_the_chooser_offers_both_kinds(self):
        make_tier()
        response = self.client.get(reverse("registry:app_choose_kind"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, reverse("registry:app_create"))
        self.assertContains(response, reverse("registry:app_create_external"))

    def test_registering_creates_a_draft_external_app(self):
        response = self.post()
        self.assertEqual(response.status_code, 302)
        app = ProxyApp.objects.get(name="Weather Board")
        self.assertEqual(app.kind, AppKind.EXTERNAL)
        self.assertEqual(app.status, AppStatus.DRAFT)
        self.assertEqual(app.api_base_url, API)
        self.assertEqual(app.allowed_methods, ["GET"])
        self.assertEqual(app.owner, self.owner)
        self.assertIsNone(app.tier)

    def test_a_client_secret_is_issued_for_a_confidential_app(self):
        self.post()
        app = ProxyApp.objects.get(name="Weather Board")
        self.assertTrue(app.client_secret_hash)

    def test_an_http_base_url_is_rejected(self):
        response = self.post(api_base_url="http://api.example.com")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(ProxyApp.objects.filter(name="Weather Board").exists())

    def test_a_private_address_is_rejected(self):
        with dns("10.0.0.5"):
            response = self.client.post(
                reverse("registry:app_create_external"),
                self.form_data(api_base_url="https://internal.example.com"),
            )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "private or reserved")
        self.assertFalse(ProxyApp.objects.exists())

    def test_the_cloud_metadata_address_is_rejected(self):
        with dns("169.254.169.254"):
            response = self.client.post(
                reverse("registry:app_create_external"),
                self.form_data(api_base_url="https://metadata.example.com"),
            )
        self.assertFalse(ProxyApp.objects.exists())
        self.assertEqual(response.status_code, 200)

    def test_a_bearer_style_needs_a_secret(self):
        response = self.post(credential_style=CredentialStyle.BEARER)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "needs a secret")
        self.assertFalse(ProxyApp.objects.exists())

    def test_a_header_style_needs_a_name(self):
        response = self.post(
            credential_style=CredentialStyle.HEADER, upstream_client_secret="k"
        )
        self.assertContains(response, "needs a header or parameter name")
        self.assertFalse(ProxyApp.objects.exists())

    def test_basic_style_needs_a_client_id(self):
        response = self.post(
            credential_style=CredentialStyle.BASIC, upstream_client_secret="k"
        )
        self.assertContains(response, "needs a client id")
        self.assertFalse(ProxyApp.objects.exists())

    def test_a_supplied_secret_is_stored_encrypted(self):
        self.post(credential_style=CredentialStyle.BEARER, upstream_client_secret="k3y")
        app = ProxyApp.objects.get(name="Weather Board")
        self.assertNotIn("k3y", app.upstream_client_secret_encrypted)
        self.assertEqual(app.upstream_client_secret, "k3y")

    def test_at_least_one_method_is_required(self):
        response = self.post(allowed_methods=[])
        self.assertEqual(response.status_code, 200)
        self.assertFalse(ProxyApp.objects.exists())

    def test_the_upstream_secret_is_never_rendered_back(self):
        self.post(credential_style=CredentialStyle.BEARER, upstream_client_secret="k3y")
        app = ProxyApp.objects.get(name="Weather Board")
        detail = self.client.get(reverse("registry:app_detail", args=[app.pk]))
        self.assertNotContains(detail, "k3y")
        with public_dns():
            edit = self.client.get(reverse("registry:app_edit", args=[app.pk]))
        self.assertNotContains(edit, "k3y")


class ExternalEditTests(TestCase):
    def setUp(self):
        self.owner = make_user("student")
        self.app = make_external_app(owner=self.owner, status=AppStatus.APPROVED)
        self.client.force_login(self.owner)

    def edit(self, **overrides):
        data = {
            "name": self.app.name,
            "description": "",
            "homepage_url": "",
            "api_base_url": self.app.api_base_url,
            "redirect_uris": "https://app.example.edu/callback",
            "allowed_methods": ["GET"],
            "credential_style": CredentialStyle.NONE,
            "credential_name": "",
            "upstream_client_id": "",
            "upstream_client_secret": "",
        }
        data.update(overrides)
        with public_dns():
            return self.client.post(reverse("registry:app_edit", args=[self.app.pk]), data)

    def test_changing_the_api_base_url_sends_it_back_for_review(self):
        self.edit(api_base_url="https://other.example.com/v1")
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, AppStatus.PENDING)

    def test_widening_the_methods_sends_it_back_for_review(self):
        self.edit(allowed_methods=["GET", "DELETE"])
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, AppStatus.PENDING)

    def test_changing_the_credential_style_sends_it_back_for_review(self):
        self.edit(credential_style=CredentialStyle.BEARER, upstream_client_secret="k")
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, AppStatus.PENDING)

    def test_renaming_alone_does_not(self):
        self.edit(name="Renamed")
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, AppStatus.APPROVED)
        self.assertEqual(self.app.name, "Renamed")

    def test_the_stored_secret_survives_an_edit_that_leaves_it_blank(self):
        self.app.credential_style = CredentialStyle.BEARER
        self.app.upstream_client_secret = "keep-me"
        self.app.save()
        self.edit(credential_style=CredentialStyle.BEARER, upstream_client_secret="")
        self.app.refresh_from_db()
        self.assertEqual(self.app.upstream_client_secret, "keep-me")


class ExternalReviewTests(TestCase):
    def setUp(self):
        self.staff = make_user("staff", is_staff=True)
        self.app = make_external_app(status=AppStatus.PENDING)
        self.client.force_login(self.staff)

    def test_the_review_page_shows_where_traffic_will_go(self):
        response = self.client.get(reverse("registry:review_app", args=[self.app.pk]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, API)
        self.assertContains(response, "External API")

    def test_approving_makes_it_usable(self):
        self.client.post(
            reverse("registry:review_app", args=[self.app.pk]),
            {"decision": "approve", "notes": "fine"},
        )
        self.app.refresh_from_db()
        self.assertEqual(self.app.status, AppStatus.APPROVED)
        self.assertTrue(self.app.is_usable)

    def test_external_apps_appear_in_the_queue(self):
        response = self.client.get(reverse("registry:review_queue"))
        self.assertContains(response, self.app.name)
