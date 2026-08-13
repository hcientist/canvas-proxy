from django import forms
from django.core.exceptions import ValidationError

from .models import AccessTier, ProxyApp, validate_redirect_uri


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


class ProxyAppForm(forms.ModelForm):
    redirect_uris = RedirectURIsField(
        label="Redirect URIs",
        help_text="Exact URLs Canvas users may be returned to. One per line. "
        "Matching is exact -- no wildcards, no trailing-slash forgiveness.",
    )

    class Meta:
        model = ProxyApp
        fields = (
            "name",
            "description",
            "homepage_url",
            "tier",
            "redirect_uris",
            "is_public_client",
        )
        widgets = {
            "description": forms.Textarea(attrs={"rows": 4}),
        }
        labels = {
            "tier": "Access level",
            "is_public_client": "Public client (no secret, PKCE required)",
        }
        help_texts = {
            "description": "What the app does, who uses it, and why it needs this "
            "level of access. Reviewers read this.",
            "is_public_client": "Tick for single-page apps, mobile apps, and CLI "
            "tools that cannot keep a secret.",
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["tier"].queryset = AccessTier.objects.filter(is_active=True)
        self.fields["tier"].empty_label = None


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
