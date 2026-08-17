from django import forms
from django.core.exceptions import ValidationError

from gateway.netguard import normalize_api_base_url, validate_api_base_url

from .models import (
    AccessTier,
    AppKind,
    CredentialStyle,
    ProxyApp,
    validate_redirect_uri,
)


class RedirectURIsField(forms.CharField):
    """One redirect URI per line, stored as a JSON list."""

    widget = forms.Textarea(attrs={"rows": 4, "placeholder": "https://example.edu/oauth/callback"})

    def prepare_value(self, value):
        if isinstance(value, list):
            return "\n".join(value)
        return value

    def has_changed(self, initial, data):
        # The stored value is a list and the submitted value is text, so the
        # default comparison would report a change on every save.
        return self._as_list(initial) != self._as_list(data)

    @staticmethod
    def _as_list(value):
        if isinstance(value, list):
            return value
        return [line.strip() for line in (value or "").splitlines() if line.strip()]

    def clean(self, value):
        raw = super().clean(value)
        uris = [line.strip() for line in (raw or "").splitlines() if line.strip()]
        if not uris:
            raise ValidationError("Register at least one redirect URI.")
        if len(uris) > 10:
            raise ValidationError("At most 10 redirect URIs per app.")

        seen = []
        errors = []
        for uri in uris:
            try:
                validate_redirect_uri(uri)
            except ValidationError as exc:
                errors.extend(exc.messages)
                continue
            if uri in seen:
                errors.append(f"{uri}: listed more than once.")
                continue
            seen.append(uri)
        if errors:
            raise ValidationError(errors)
        return seen


REDIRECT_URI_HELP = (
    "Exact URLs users may be returned to. One per line. Matching is exact -- "
    "no wildcards, no trailing-slash forgiveness."
)

COMMON_FIELDS = ("name", "description", "homepage_url", "redirect_uris", "is_public_client")

COMMON_LABELS = {"is_public_client": "Public client (no secret, PKCE required)"}

COMMON_HELP = {
    "is_public_client": "Tick for single-page apps, mobile apps, and CLI tools "
    "that cannot keep a secret.",
}


class ProxyAppForm(forms.ModelForm):
    """Register an app against one of the operator's Canvas developer keys."""

    redirect_uris = RedirectURIsField(
        label="Redirect URIs", help_text=REDIRECT_URI_HELP
    )

    class Meta:
        model = ProxyApp
        fields = ("name", "description", "homepage_url", "tier", "redirect_uris", "is_public_client")
        widgets = {"description": forms.Textarea(attrs={"rows": 4})}
        labels = {"tier": "Access level", **COMMON_LABELS}
        help_texts = {
            "description": "What the app does, who uses it, and why it needs this "
            "level of access. Reviewers read this.",
            **COMMON_HELP,
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["tier"].queryset = AccessTier.objects.filter(is_active=True)
        self.fields["tier"].empty_label = None
        self.fields["tier"].required = True


HTTP_METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]


class ExternalAppForm(forms.ModelForm):
    """Register an app that proxies to a third-party API instead of Canvas."""

    redirect_uris = RedirectURIsField(
        label="Redirect URIs", help_text=REDIRECT_URI_HELP
    )
    allowed_methods = forms.MultipleChoiceField(
        choices=[(m, m) for m in HTTP_METHODS],
        widget=forms.CheckboxSelectMultiple,
        required=True,
        label="HTTP methods",
        help_text="Only the methods your app actually needs.",
    )
    upstream_client_secret = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False),
        label="API secret / key",
        help_text="Stored encrypted and never shown again. Leave blank to keep "
        "the stored value.",
    )

    class Meta:
        model = ProxyApp
        fields = (
            "name",
            "description",
            "homepage_url",
            "api_base_url",
            "redirect_uris",
            "allowed_methods",
            "credential_style",
            "credential_name",
            "upstream_client_id",
            "is_public_client",
        )
        widgets = {"description": forms.Textarea(attrs={"rows": 4})}
        labels = {
            "api_base_url": "API base URL",
            "credential_style": "How the API expects credentials",
            "credential_name": "Header or parameter name",
            "upstream_client_id": "API client id / username",
            **COMMON_LABELS,
        }
        help_texts = {
            "description": "What the app does, who uses it, and what the API is "
            "for. Reviewers read this.",
            "api_base_url": "Must be https. Requests to /ext/<path> are sent to "
            "this URL with <path> appended.",
            "credential_name": 'Only for the header and query styles, e.g. "X-Api-Key".',
            "upstream_client_id": "Optional. Only needed for HTTP Basic, or if the "
            "API pairs an id with the secret.",
            **COMMON_HELP,
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["api_base_url"].required = True
        if self.instance and self.instance.pk and self.instance.allowed_methods:
            self.fields["allowed_methods"].initial = self.instance.allowed_methods

    def clean_api_base_url(self):
        url = normalize_api_base_url(self.cleaned_data["api_base_url"])
        validate_api_base_url(url)
        return url

    def clean(self):
        data = super().clean()
        style = data.get("credential_style")
        name = (data.get("credential_name") or "").strip()
        secret = data.get("upstream_client_secret")

        if style in {CredentialStyle.HEADER, CredentialStyle.QUERY} and not name:
            self.add_error(
                "credential_name",
                "This credential style needs a header or parameter name.",
            )
        if style not in {CredentialStyle.HEADER, CredentialStyle.QUERY} and name:
            data["credential_name"] = ""

        needs_secret = style in {
            CredentialStyle.BEARER,
            CredentialStyle.BASIC,
            CredentialStyle.HEADER,
            CredentialStyle.QUERY,
        }
        stored = bool(self.instance and self.instance.upstream_client_secret_encrypted)
        if needs_secret and not secret and not stored:
            self.add_error(
                "upstream_client_secret",
                "This credential style needs a secret.",
            )
        if style == CredentialStyle.BASIC and not data.get("upstream_client_id"):
            self.add_error(
                "upstream_client_id", "HTTP Basic needs a client id or username."
            )
        return data

    def save(self, commit=True):
        app = super().save(commit=False)
        app.kind = AppKind.EXTERNAL
        app.tier = None
        app.allowed_methods = list(self.cleaned_data["allowed_methods"])
        secret = self.cleaned_data.get("upstream_client_secret")
        if secret:
            app.upstream_client_secret = secret
        if app.credential_style == CredentialStyle.NONE:
            app.upstream_client_secret = ""
            app.upstream_client_id = ""
        if commit:
            app.save()
        return app


class ReviewForm(forms.Form):
    DECISIONS = (
        ("approve", "Approve"),
        ("reject", "Reject"),
        ("suspend", "Suspend"),
    )
    decision = forms.ChoiceField(choices=DECISIONS, widget=forms.RadioSelect)
    notes = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 3}),
        label="Notes for the developer",
    )

    def clean(self):
        data = super().clean()
        if data.get("decision") in {"reject", "suspend"} and not data.get("notes"):
            raise ValidationError("Explain the decision so the developer can act on it.")
        return data
