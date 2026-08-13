from django.db import models


class RequestLog(models.Model):
    """One proxied call. The audit trail for who reached what, on whose behalf."""

    app = models.ForeignKey(
        "registry.ProxyApp",
        null=True,
        on_delete=models.SET_NULL,
        related_name="request_logs",
    )
    grant = models.ForeignKey(
        "oauth.CanvasGrant",
        null=True,
        on_delete=models.SET_NULL,
        related_name="request_logs",
    )
    canvas_user_id = models.CharField(max_length=64, blank=True)
    method = models.CharField(max_length=10)
    path = models.CharField(max_length=500)
    query = models.CharField(max_length=1000, blank=True)
    status_code = models.PositiveIntegerField(null=True)
    duration_ms = models.PositiveIntegerField(null=True)
    denied_reason = models.CharField(max_length=255, blank=True)
    client_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ("-created_at",)
        indexes = [
            models.Index(fields=["app", "-created_at"]),
            models.Index(fields=["-created_at"]),
        ]

    def __str__(self):
        return f"{self.method} {self.path} -> {self.status_code}"

    @property
    def was_denied(self):
        return bool(self.denied_reason)
