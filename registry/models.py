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
from gateway.netguard import normalize_api_base_url

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
        return evaluate_rules(
            method,
            path,
            allowed_methods=self.allowed_methods,
            path_rules=self.path_rules,
            denied_patterns=self.denied_patterns,
            label=f"the {self.name} tier",
        )

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


def evaluate_rules(method, path, allowed_methods, path_rules, denied_patterns, label):
    """Shared method/path gate for both access tiers and external apps.

    Returns (allowed, reason). Empty rule lists mean "no restriction", so an
    unconfigured tier or app is limited only by whatever is upstream.
    """
    method = method.upper()

    for pattern in denied_patterns or []:
        if _matches(pattern, path):
            return False, f"{path} is not reachable through {label}."

    methods = [m.upper() for m in (allowed_methods or [])]
    if methods and method not in methods:
        return False, _sentence(f"{label} allows only {', '.join(methods)}.")

    rules = path_rules or []
    if not rules:
        return True, ""

    for rule in rules:
        rule_methods = [m.upper() for m in rule.get("methods") or []]
        if rule_methods and method not in rule_methods:
            continue
        if _matches(rule.get("pattern", ""), path):
            return True, ""

    return False, f"{method} {path} is outside {label}'s allowlist."


def _sentence(text):
    """Capitalise the first letter only, leaving names like 'Read-only' alone."""
    return text[:1].upper() + text[1:]


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


class AppKind(models.TextChoices):
    CANVAS = "canvas", "Canvas API"
    EXTERNAL = "external", "External API"


class CredentialStyle(models.TextChoices):
    """How the proxy presents an external app's credentials upstream."""

    NONE = "none", "No credentials (public API)"
    BEARER = "bearer", "Authorization: Bearer <secret>"
    BASIC = "basic", "HTTP Basic (client id + secret)"
    HEADER = "header", "Custom header"
    QUERY = "query", "Query parameter"


class ProxyApp(models.Model):
    """A third-party app registered by a developer.

    Two kinds, sharing one registration, approval and token pipeline:

    * `canvas`   -- proxies to the Canvas API using one of the operator's
      developer keys, chosen by tier. The end user grants real Canvas access.
    * `external` -- proxies to a third-party API the developer nominates, using
      credentials the developer supplies. Canvas is used only to establish who
      the end user is; no Canvas token is kept.
    """

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="apps"
    )
    kind = models.CharField(
        max_length=20, choices=AppKind.choices, default=AppKind.CANVAS
    )
    name = models.CharField(max_length=120)
    description = models.TextField(
        blank=True, help_text="What the app does and why it needs this access."
    )
    homepage_url = models.URLField(blank=True)

    tier = models.ForeignKey(
        AccessTier,
        on_delete=models.PROTECT,
        related_name="apps",
        null=True,
        blank=True,
        help_text="Canvas apps only.",
    )
    redirect_uris = models.JSONField(default=list)

    # --- external apps only ------------------------------------------------

    api_base_url = models.URLField(
        max_length=500,
        blank=True,
        help_text="Base URL of the third-party API, e.g. https://api.example.com/v2",
    )
    credential_style = models.CharField(
        max_length=20, choices=CredentialStyle.choices, default=CredentialStyle.NONE
    )
    credential_name = models.CharField(
        max_length=100,
        blank=True,
        help_text="Header or query parameter name, for those credential styles.",
    )
    upstream_client_id = models.CharField(max_length=255, blank=True)
    upstream_client_secret_encrypted = models.TextField(blank=True)
    allowed_methods = models.JSONField(
        default=list,
        blank=True,
        help_text="HTTP methods this app may use upstream. Empty means all.",
    )
    path_rules = models.JSONField(
        default=list,
        blank=True,
        help_text='Optional allowlist: [{"methods": ["GET"], "pattern": "^/v2/items"}]. '
        "Empty means every path under the base URL.",
    )
    allow_anonymous = models.BooleanField(
        default=False,
        help_text="Allow requests without a bearer token, gated by Origin. "
        "External apps only. Requests arrive at /ext/public/<client_id>/…",
    )

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
        if self.api_base_url:
            self.api_base_url = normalize_api_base_url(self.api_base_url)
        super().save(*args, **kwargs)

    # -- state --------------------------------------------------------------

    @property
    def is_external(self):
        return self.kind == AppKind.EXTERNAL

    @property
    def is_usable(self):
        if self.status != AppStatus.APPROVED:
            return False
        if self.is_external:
            return bool(self.api_base_url)
        return bool(self.tier and self.tier.is_active)

    @property
    def upstream_label(self):
        """Where this app's traffic goes, for consent screens and review."""
        if self.is_external:
            return urlsplit(self.api_base_url).netloc or self.api_base_url
        return urlsplit(settings.CANVAS_BASE_URL).netloc

    @property
    def access_label(self):
        if self.is_external:
            return f"the {self.upstream_label} API"
        return self.tier.name if self.tier else "an unassigned tier"

    def permits(self, method, path):
        """Return (allowed, reason) for a proxied request by this app."""
        if self.is_external:
            return evaluate_rules(
                method,
                path,
                allowed_methods=self.allowed_methods,
                path_rules=self.path_rules,
                denied_patterns=[],
                label=f"this app's registration for {self.upstream_label}",
            )
        if not self.tier:
            return False, "This app has no access tier assigned."
        return self.tier.permits(method, path)

    # -- upstream credentials (external apps) -------------------------------

    @property
    def upstream_client_secret(self):
        return crypto.decrypt(self.upstream_client_secret_encrypted)

    @upstream_client_secret.setter
    def upstream_client_secret(self, value):
        self.upstream_client_secret_encrypted = crypto.encrypt(value or "")

    @property
    def has_upstream_credentials(self):
        return bool(self.upstream_client_id or self.upstream_client_secret_encrypted)

    def submit_for_review(self):
        self.status = AppStatus.PENDING
        self.submitted_at = timezone.now()
        self.reviewed_by = None
        self.reviewed_at = None

    def _record_decision(self, status, reviewer, notes):
        self.status = status
        self.reviewed_by = reviewer
        self.reviewed_at = timezone.now()
        self.review_notes = notes
        self.save(
            update_fields=["status", "reviewed_by", "reviewed_at", "review_notes", "updated_at"]
        )
        # Which origins may call from a browser follows approval status, so a
        # decision has to take effect now rather than when the cache expires.
        # Imported here because the CORS helper reads this model.
        from gateway.cors import forget_origins

        forget_origins()

    def approve(self, reviewer, notes=""):
        self._record_decision(AppStatus.APPROVED, reviewer, notes)

    def reject(self, reviewer, notes=""):
        self._record_decision(AppStatus.REJECTED, reviewer, notes)

    def suspend(self, reviewer, notes=""):
        """Stop the app immediately and cut off every grant it holds.

        Each grant is revoked individually rather than bulk-updated, so the
        tokens issued against it are revoked too and any Canvas token is handed
        back upstream. Suspension is meant to end the app's access everywhere,
        not just to stop this proxy honouring it.
        """
        self._record_decision(AppStatus.SUSPENDED, reviewer, notes)
        for grant in self.grants.filter(revoked_at__isnull=True).select_related("tier"):
            grant.revoke(at_canvas=True)

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
