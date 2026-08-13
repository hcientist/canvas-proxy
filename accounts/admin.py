from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .models import User


@admin.register(User)
class CanvasUserAdmin(UserAdmin):
    list_display = (
        "username",
        "canvas_name",
        "canvas_login_id",
        "canvas_user_id",
        "is_staff",
        "last_canvas_login",
    )
    list_filter = ("is_staff", "is_superuser", "is_active")
    search_fields = ("username", "email", "canvas_name", "canvas_login_id", "canvas_user_id")
    readonly_fields = ("last_canvas_login",)
    fieldsets = UserAdmin.fieldsets + (
        (
            "Canvas identity",
            {
                "fields": (
                    "canvas_user_id",
                    "canvas_login_id",
                    "canvas_name",
                    "canvas_avatar_url",
                    "last_canvas_login",
                )
            },
        ),
    )
