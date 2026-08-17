from django import forms
from django.contrib import admin, messages
from django.utils import timezone

from .models import AccessTier, AppStatus, ProxyApp


class AccessTierForm(forms.ModelForm):
    canvas_client_secret_input = forms.CharField(
        label="Canvas client secret",
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text="Leave blank to keep the stored secret. Stored encrypted; "
        "never displayed again.",
    )

    class Meta:
        model = AccessTier
        exclude = ("canvas_client_secret_encrypted",)

    def save(self, commit=True):
        tier = super().save(commit=False)
        secret = self.cleaned_data.get("canvas_client_secret_input")
        if secret:
            tier.canvas_client_secret = secret
        if commit:
            tier.save()
        return tier


@admin.register(AccessTier)
class AccessTierAdmin(admin.ModelAdmin):
    form = AccessTierForm
    list_display = (
        "name",
        "slug",
        "canvas_client_id",
        "secret_set",
        "allow_masquerade",
        "is_active",
        "app_count",
    )
    list_filter = ("is_active", "enforces_scopes", "allow_masquerade")
    search_fields = ("name", "slug", "canvas_client_id")
    prepopulated_fields = {"slug": ("name",)}

    @admin.display(boolean=True, description="Secret stored")
    def secret_set(self, obj):
        return bool(obj.canvas_client_secret_encrypted)

    @admin.display(description="Apps")
    def app_count(self, obj):
        return obj.apps.count()


class ProxyAppForm(forms.ModelForm):
    upstream_client_secret_input = forms.CharField(
        label="Upstream API secret",
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text="External apps only. Leave blank to keep the stored secret.",
    )

    class Meta:
        model = ProxyApp
        exclude = ("upstream_client_secret_encrypted",)

    def save(self, commit=True):
        app = super().save(commit=False)
        secret = self.cleaned_data.get("upstream_client_secret_input")
        if secret:
            app.upstream_client_secret = secret
        if commit:
            app.save()
        return app


@admin.register(ProxyApp)
class ProxyAppAdmin(admin.ModelAdmin):
    form = ProxyAppForm
    list_display = (
        "name",
        "owner",
        "kind",
        "upstream",
        "status",
        "is_public_client",
        "submitted_at",
        "reviewed_by",
    )
    list_filter = ("kind", "status", "tier", "is_public_client", "credential_style")
    search_fields = (
        "name",
        "client_id",
        "api_base_url",
        "owner__username",
        "owner__canvas_name",
    )
    readonly_fields = (
        "client_id",
        "client_secret_hash",
        "client_secret_hint",
        "secret_rotated_at",
        "created_at",
        "updated_at",
    )
    autocomplete_fields = ("owner",)

    @admin.display(description="Upstream")
    def upstream(self, obj):
        return obj.api_base_url if obj.is_external else (obj.tier.name if obj.tier else "—")
    actions = ("approve_selected", "reject_selected", "suspend_selected")

    @admin.action(description="Approve selected apps")
    def approve_selected(self, request, queryset):
        count = 0
        for app in queryset:
            app.approve(request.user, "Approved from the admin.")
            count += 1
        self.message_user(request, f"Approved {count} app(s).", messages.SUCCESS)

    @admin.action(description="Reject selected apps")
    def reject_selected(self, request, queryset):
        count = 0
        for app in queryset:
            app.reject(request.user, "Rejected from the admin.")
            count += 1
        self.message_user(request, f"Rejected {count} app(s).", messages.SUCCESS)

    @admin.action(description="Suspend selected apps (revokes their Canvas grants)")
    def suspend_selected(self, request, queryset):
        count = 0
        for app in queryset:
            app.suspend(request.user, "Suspended from the admin.")
            count += 1
        self.message_user(
            request,
            f"Suspended {count} app(s) and revoked their grants.",
            messages.WARNING,
        )
