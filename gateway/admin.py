from django.contrib import admin

from .models import RequestLog


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = (
        "created_at",
        "app",
        "canvas_user_id",
        "method",
        "path",
        "status_code",
        "duration_ms",
        "denied_reason",
    )
    list_filter = ("method", "status_code", "app")
    search_fields = ("path", "canvas_user_id", "denied_reason")
    date_hierarchy = "created_at"
    readonly_fields = tuple(f.name for f in RequestLog._meta.fields)

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
