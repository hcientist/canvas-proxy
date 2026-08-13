"""Access tiers (one per Canvas developer key) and the apps registered against them."""

import re
import uuid
from urllib.parse import urlsplit

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone

from canvasclient import crypto

LOCAL_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1"}


def validate_redirect_uri(value):
    """Redirect URIs must be absolute, exact, and (off localhost) TLS-protected."""
    parts = urlsplit(value)
    if parts.scheme not in {"http", "https"}:
        raise ValidationError(f"{value}: must be an http(s) URL.")
    if not parts.netloc:
        raise ValidationError(f"{value}: missing a host.")
    if parts.fragment:
        raise ValidationError(f"{value}: must not contain a fragment (#...).")
    if "*" in value:
        raise ValidationError(f"{value}: wildcards are not allowed.")
    hostname = parts.hostname or ""
    if parts.scheme == "http" and hostname not in LOCAL_HOSTS:
        raise ValidationError(f"{value}: http is only allowed for localhost.")
    return value


class AccessTier(models.Model):
    """One Canvas developer key, plus the limits imposed on apps that use it.

    Canvas enforces the key's own scopes upstream; the method/path rules here
    are a second, proxy-side gate so a broadly-scoped key can still back a
    narrow tier.
    """

    slug = models.SlugField(max_length=50, unique=True)
    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    sort_order = models.PositiveIntegerField(default=0)

    canvas_client_id = models.CharField(
        max_length=100, blank=True, help_text="Canvas developer key ID."
    )
    canvas_client_secret_encrypted = models.TextField(blank=True)

    enforces_scopes = models.BooleanField(
        default=True,
        help_text="Send an explicit scope list to Canvas. Match this to the "
        "'Enforce Scopes' setting on the developer key.",
    )
    scopes = models.JSONField(
        default=list,
        blank=True,
        help_text='Canvas scope strings, e.g. ["url:GET|/api/v1/courses"].',
    )

    allowed_methods = models.JSONField(
        default=list,
        blank=True,
        help_text='HTTP methods apps on this tier may proxy. Empty means all.',
    )
    path_rules = models.JSONField(
        default=list,
        blank=True,
        help_text='Allowlist entries: [{"methods": ["GET"], "pattern": '
        '"^/api/v1/courses(/|$)"}]. Empty means every path is allowed.',
    )
    denied_patterns = models.JSONField(
        default=list,
        blank=True,
        help_text="Regexes always refused on this tier, checked before the allowlist.",
    )
    allow_masquerade = models.BooleanField(
        default=False,
        help_text="Permit as_user_id= masquerading. Only enable for a tier whose "
        "developer key is trusted with account-admin acting-as rights.",
    )

    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("sort_order", "slug")

    def __str__(self):
        return self.name

    # -- credentials --------------------------------------------------------

    @property
    def canvas_client_secret(self):
        return crypto.decrypt(self.canvas_client_secret_encrypted)

    @canvas_client_secret.setter
    def canvas_client_secret(self, value):
        self.canvas_client_secret_encrypted = crypto.encrypt(value or "")

    @property
    def is_configured(self):
        return bool(self.canvas_client_id and self.canvas_client_secret_encrypted)

    # -- request gating -----------------------------------------------------

    def permits(self, method, path):
        """Return (allowed, reason). `path` is the upstream path, e.g. /api/v1/courses."""
        method = method.upper()

        for pattern in self.denied_patterns or []:
            if _matches(pattern, path):
                return False, f"{path} is not reachable through the {self.name} tier."

        allowed_methods = [m.upper() for m in (self.allowed_methods or [])]
        if allowed_methods and method not in allowed_methods:
            return False, f"The {self.name} tier allows only {', '.join(allowed_methods)}."

        rules = self.path_rules or []
        if not rules:
            return True, ""

        for rule in rules:
            rule_methods = [m.upper() for m in rule.get("methods") or []]
            if rule_methods and method not in rule_methods:
                continue
            if _matches(rule.get("pattern", ""), path):
                return True, ""

        return False, f"{method} {path} is outside the {self.name} tier's allowlist."

    def clean(self):
        errors = {}
        for pattern in (self.denied_patterns or []):
            try:
                re.compile(pattern)
            except re.error as exc:
                errors["denied_patterns"] = f"Invalid regex {pattern!r}: {exc}"
        for rule in (self.path_rules or []):
            if not isinstance(rule, dict) or "pattern" not in rule:
                errors["path_rules"] = 'Each rule needs a "pattern" key.'
                break
            try:
                re.compile(rule["pattern"])
            except re.error as exc:
                errors["path_rules"] = f"Invalid regex {rule['pattern']!r}: {exc}"
                break
        if errors:
            raise ValidationError(errors)


def _matches(pattern, path):
    if not pattern:
        return False
    try:
        return re.search(pattern, path) is not None
    except re.error:
        # A malformed stored pattern must never accidentally widen access.
        return False


class AppStatus(models.TextChoices):
    DRAFT = "draft", "Draft"
    PENDING = "pending", "Pending review"
    APPROVED = "approved", "Approved"
    REJECTED = "rejected", "Rejected"
    SUSPENDED = "suspended", "Suspended"


class ProxyApp(models.Model):
    """A third-party app registered by a developer against one access tier."""

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="apps"
    )
    name = models.CharField(max_length=120)
    description = models.TextField(
        blank=True, help_text="What the app does and why it needs this access."
    )
    homepage_url = models.URLField(blank=True)

    tier = models.ForeignKey(
        AccessTier, on_delete=models.PROTECT, related_name="apps"
    )
    redirect_uris = models.JSONField(default=list)

    client_id = models.CharField(max_length=64, unique=True, editable=False)
    client_secret_hash = models.CharField(max_length=255, blank=True)
    client_secret_hint = models.CharField(max_length=16, blank=True)
    secret_rotated_at = models.DateTimeField(null=True, blank=True)
    is_public_client = models.BooleanField(
        default=False,
        help_text="Public clients (SPAs, mobile, CLI) hold no secret and must use PKCE.",
    )

    status = models.CharField(
        max_length=20, choices=AppStatus.choices, default=AppStatus.DRAFT
    )
    submitted_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reviewed_apps",
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_notes = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [models.Index(fields=["status"])]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.client_id:
            self.client_id = uuid.uuid4().hex
        super().save(*args, **kwargs)

    # -- state --------------------------------------------------------------

    @property
    def is_usable(self):
        return self.status == AppStatus.APPROVED and self.tier.is_active

    def submit_for_review(self):
        self.status = AppStatus.PENDING
        self.submitted_at = timezone.now()
        self.reviewed_by = None
        self.reviewed_at = None

    def approve(self, reviewer, notes=""):
        self.status = AppStatus.APPROVED
        self.reviewed_by = reviewer
        self.reviewed_at = timezone.now()
        self.review_notes = notes
        self.save(
            update_fields=["status", "reviewed_by", "reviewed_at", "review_notes", "updated_at"]
        )

    def reject(self, reviewer, notes=""):
        self.status = AppStatus.REJECTED
        self.reviewed_by = reviewer
        self.reviewed_at = timezone.now()
        self.review_notes = notes
        self.save(
            update_fields=["status", "reviewed_by", "reviewed_at", "review_notes", "updated_at"]
        )

    def suspend(self, reviewer, notes=""):
        """Stop the app immediately and cut off every grant it holds."""
        self.status = AppStatus.SUSPENDED
        self.reviewed_by = reviewer
        self.reviewed_at = timezone.now()
        self.review_notes = notes
        self.save(
            update_fields=["status", "reviewed_by", "reviewed_at", "review_notes", "updated_at"]
        )
        self.grants.filter(revoked_at__isnull=True).update(revoked_at=timezone.now())

    # -- credentials --------------------------------------------------------

    def rotate_secret(self):
        """Generate a new client secret, persist it, and return the plaintext once.

        This saves immediately: a later partial save() elsewhere would otherwise
        drop the new hash and leave the returned secret unusable.
        """
        raw = crypto.generate_token(32)
        self.client_secret_hash = make_password(raw)
        self.client_secret_hint = raw[-6:]
        self.secret_rotated_at = timezone.now()
        if self.pk:
            self.save(
                update_fields=[
                    "client_secret_hash",
                    "client_secret_hint",
                    "secret_rotated_at",
                    "updated_at",
                ]
            )
        return raw

    def check_secret(self, raw):
        if self.is_public_client or not self.client_secret_hash:
            return False
        return check_password(raw or "", self.client_secret_hash)

    # -- redirect URIs ------------------------------------------------------

    def redirect_uri_allowed(self, uri):
        """Exact string match only -- no prefix or wildcard matching."""
        if not uri:
            return False
        return any(crypto.constant_time_equals(uri, stored) for stored in self.redirect_uris)

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0] if self.redirect_uris else ""
