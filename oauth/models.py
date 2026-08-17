"""Storage for the OAuth2 flow this proxy runs on behalf of registered apps.

Three kinds of credential live here:

* `CanvasGrant`  -- the real Canvas access/refresh pair, encrypted at rest.
  Never leaves the server.
* `AuthorizationCode` / `ProxyToken` -- credentials the proxy issues to an app.
  Only HMAC digests are stored, so a database leak does not yield usable tokens.
* `AuthorizationRequest` -- short-lived state held while the end user is away
  at Canvas granting consent.
"""

import base64
import hashlib
import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from canvasclient import client, crypto


class AuthorizationRequest(models.Model):
    """In-flight authorization: the app asked, the user is off at Canvas."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    app = models.ForeignKey(
        "registry.ProxyApp", on_delete=models.CASCADE, related_name="auth_requests"
    )
    redirect_uri = models.URLField(max_length=500)
    client_state = models.CharField(max_length=500, blank=True)
    proxy_state = models.CharField(max_length=128, unique=True)
    code_challenge = models.CharField(max_length=128, blank=True)
    code_challenge_method = models.CharField(max_length=10, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["expires_at"])]

    def __str__(self):
        return f"auth request for {self.app_id}"

    @property
    def is_live(self):
        return self.consumed_at is None and self.expires_at > timezone.now()

    @classmethod
    def start(cls, app, redirect_uri, client_state, code_challenge="", method=""):
        return cls.objects.create(
            app=app,
            redirect_uri=redirect_uri,
            client_state=client_state[:500],
            proxy_state=crypto.generate_token(32),
            code_challenge=code_challenge,
            code_challenge_method=method,
            expires_at=timezone.now()
            + timezone.timedelta(seconds=settings.AUTHORIZATION_REQUEST_TTL),
        )


class CanvasGrant(models.Model):
    """One end user's authorization of one app.

    For a Canvas app this holds the live Canvas token pair, encrypted. For an
    external app there is no Canvas token to hold -- Canvas is consulted only to
    establish who the user is, and that token is revoked immediately -- so the
    token fields stay empty and the row exists to bind proxy tokens to a
    known Canvas identity, and to be revocable.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    app = models.ForeignKey(
        "registry.ProxyApp", on_delete=models.CASCADE, related_name="grants"
    )
    tier = models.ForeignKey(
        "registry.AccessTier",
        on_delete=models.PROTECT,
        related_name="grants",
        null=True,
        blank=True,
        help_text="Canvas apps only; external apps have no developer key.",
    )
    canvas_user_id = models.CharField(max_length=64)
    canvas_user_name = models.CharField(max_length=255, blank=True)
    canvas_global_id = models.CharField(max_length=64, blank=True)

    access_token_encrypted = models.TextField(blank=True)
    refresh_token_encrypted = models.TextField(blank=True)
    access_token_expires_at = models.DateTimeField(null=True, blank=True)
    scopes = models.JSONField(default=list, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["app", "canvas_user_id"]),
            models.Index(fields=["revoked_at"]),
        ]

    def __str__(self):
        return f"{self.app.name} / canvas user {self.canvas_user_id}"

    @property
    def is_active(self):
        return self.revoked_at is None

    @property
    def holds_canvas_token(self):
        return bool(self.access_token_encrypted)

    @property
    def access_token(self):
        return crypto.decrypt(self.access_token_encrypted)

    @property
    def refresh_token(self):
        return crypto.decrypt(self.refresh_token_encrypted)

    def store_canvas_payload(self, payload):
        """Persist the token fields from a Canvas token response."""
        self.access_token_encrypted = crypto.encrypt(payload["access_token"])
        if payload.get("refresh_token"):
            # Canvas omits refresh_token on refresh responses; keep the old one.
            self.refresh_token_encrypted = crypto.encrypt(payload["refresh_token"])
        expires_in = payload.get("expires_in")
        self.access_token_expires_at = (
            timezone.now() + timezone.timedelta(seconds=int(expires_in))
            if expires_in
            else None
        )

    def needs_refresh(self, skew_seconds=120):
        if not self.access_token_expires_at:
            return False
        return timezone.now() >= self.access_token_expires_at - timezone.timedelta(
            seconds=skew_seconds
        )

    def refresh(self):
        """Mint a fresh Canvas access token. Raises CanvasError on failure."""
        if not self.refresh_token_encrypted:
            raise client.CanvasError("This grant has no Canvas refresh token.")
        payload = client.refresh_token(
            client_id=self.tier.canvas_client_id,
            client_secret=self.tier.canvas_client_secret,
            refresh_token_value=self.refresh_token,
        )
        self.store_canvas_payload(payload)
        self.save(
            update_fields=[
                "access_token_encrypted",
                "refresh_token_encrypted",
                "access_token_expires_at",
            ]
        )
        return self

    def usable_access_token(self):
        """The Canvas token to send upstream, refreshing it first if stale."""
        if self.needs_refresh():
            self.refresh()
        return self.access_token

    def revoke(self, at_canvas=True):
        # External-app grants never held a Canvas token, so there is nothing
        # upstream to revoke -- only the proxy tokens issued against this row.
        if at_canvas and self.access_token_encrypted:
            client.revoke(self.access_token)
        self.revoked_at = timezone.now()
        self.access_token_encrypted = ""
        self.refresh_token_encrypted = ""
        self.save(
            update_fields=[
                "revoked_at",
                "access_token_encrypted",
                "refresh_token_encrypted",
            ]
        )
        self.tokens.filter(revoked_at__isnull=True).update(revoked_at=timezone.now())


class AuthorizationCode(models.Model):
    """Single-use code handed back to the app's redirect_uri."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code_digest = models.CharField(max_length=64, unique=True)
    app = models.ForeignKey(
        "registry.ProxyApp", on_delete=models.CASCADE, related_name="auth_codes"
    )
    grant = models.ForeignKey(
        CanvasGrant, on_delete=models.CASCADE, related_name="auth_codes"
    )
    redirect_uri = models.URLField(max_length=500)
    code_challenge = models.CharField(max_length=128, blank=True)
    code_challenge_method = models.CharField(max_length=10, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    consumed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        indexes = [models.Index(fields=["expires_at"])]

    @classmethod
    def issue(cls, app, grant, redirect_uri, code_challenge="", method=""):
        raw = crypto.generate_token(32)
        cls.objects.create(
            code_digest=crypto.token_digest(raw),
            app=app,
            grant=grant,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=method,
            expires_at=timezone.now()
            + timezone.timedelta(seconds=settings.AUTHORIZATION_CODE_TTL),
        )
        return raw

    @property
    def is_live(self):
        return self.consumed_at is None and self.expires_at > timezone.now()

    def verify_pkce(self, verifier):
        """Check a PKCE verifier. No challenge stored means PKCE wasn't used."""
        if not self.code_challenge:
            return True
        if not verifier:
            return False
        if self.code_challenge_method.upper() == "S256":
            digest = hashlib.sha256(verifier.encode("ascii")).digest()
            computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        else:
            computed = verifier
        return crypto.constant_time_equals(computed, self.code_challenge)


class ProxyToken(models.Model):
    """An access/refresh pair the proxy issued to an app."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    grant = models.ForeignKey(
        CanvasGrant, on_delete=models.CASCADE, related_name="tokens"
    )
    access_token_digest = models.CharField(max_length=64, unique=True)
    refresh_token_digest = models.CharField(
        max_length=64, unique=True, null=True, blank=True
    )
    expires_at = models.DateTimeField()
    refresh_expires_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    replaced_by = models.ForeignKey(
        "self", null=True, blank=True, on_delete=models.SET_NULL, related_name="replaces"
    )

    class Meta:
        ordering = ("-created_at",)
        indexes = [models.Index(fields=["expires_at"])]

    def __str__(self):
        return f"token for {self.grant_id}"

    @classmethod
    def issue(cls, grant):
        """Create a token pair, returning (instance, access_raw, refresh_raw)."""
        access_raw = crypto.generate_token(40)
        refresh_raw = crypto.generate_token(40)
        now = timezone.now()
        token = cls.objects.create(
            grant=grant,
            access_token_digest=crypto.token_digest(access_raw),
            refresh_token_digest=crypto.token_digest(refresh_raw),
            expires_at=now + timezone.timedelta(seconds=settings.ACCESS_TOKEN_TTL),
            refresh_expires_at=now
            + timezone.timedelta(seconds=settings.REFRESH_TOKEN_TTL),
        )
        return token, access_raw, refresh_raw

    @property
    def is_live(self):
        return self.revoked_at is None and self.expires_at > timezone.now()

    @property
    def refresh_is_live(self):
        return self.revoked_at is None and (
            self.refresh_expires_at is None or self.refresh_expires_at > timezone.now()
        )

    def revoke(self):
        if self.revoked_at is None:
            self.revoked_at = timezone.now()
            self.save(update_fields=["revoked_at"])

    @classmethod
    def lookup_access(cls, raw):
        return (
            cls.objects.select_related("grant__app__tier")
            .filter(access_token_digest=crypto.token_digest(raw))
            .first()
        )

    @classmethod
    def lookup_refresh(cls, raw):
        return (
            cls.objects.select_related("grant__app__tier")
            .filter(refresh_token_digest=crypto.token_digest(raw))
            .first()
        )
