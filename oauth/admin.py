from django.contrib import admin, messages

from .models import AuthorizationCode, AuthorizationRequest, CanvasGrant, ProxyToken


@admin.register(CanvasGrant)
class CanvasGrantAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "app",
        "canvas_user_id",
        "canvas_user_name",
        "created_at",
        "last_used_at",
        "revoked_at",
    )
    list_filter = ("tier", "app", "revoked_at")
    search_fields = ("canvas_user_id", "canvas_user_name", "app__name")
    readonly_fields = (
        "app",
        "tier",
        "canvas_user_id",
        "canvas_user_name",
        "canvas_global_id",
        "access_token_expires_at",
        "scopes",
        "created_at",
        "last_used_at",
        "revoked_at",
    )
    exclude = ("access_token_encrypted", "refresh_token_encrypted")
    actions = ("revoke_selected",)

    @admin.action(description="Revoke selected grants (also at Canvas)")
    def revoke_selected(self, request, queryset):
        count = 0
        for grant in queryset.filter(revoked_at__isnull=True):
            grant.revoke(at_canvas=True)
            count += 1
        self.message_user(request, f"Revoked {count} grant(s).", messages.WARNING)

    def has_add_permission(self, request):
        return False


@admin.register(ProxyToken)
class ProxyTokenAdmin(admin.ModelAdmin):
    list_display = ("id", "grant", "created_at", "expires_at", "last_used_at", "revoked_at")
    list_filter = ("revoked_at",)
    readonly_fields = tuple(
        f.name for f in ProxyToken._meta.fields if f.name != "revoked_at"
    )

    def has_add_permission(self, request):
        return False


@admin.register(AuthorizationRequest)
class AuthorizationRequestAdmin(admin.ModelAdmin):
    list_display = ("id", "app", "created_at", "expires_at", "consumed_at")
    readonly_fields = tuple(f.name for f in AuthorizationRequest._meta.fields)

    def has_add_permission(self, request):
        return False


@admin.register(AuthorizationCode)
class AuthorizationCodeAdmin(admin.ModelAdmin):
    list_display = ("id", "app", "created_at", "expires_at", "consumed_at")
    readonly_fields = tuple(f.name for f in AuthorizationCode._meta.fields)

    def has_add_permission(self, request):
        return False
