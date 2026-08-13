from django.conf import settings

from .models import AppStatus, ProxyApp


def site(request):
    context = {
        "proxy_base_url": settings.PROXY_BASE_URL,
        "canvas_base_url": settings.CANVAS_BASE_URL,
        "pending_review_count": 0,
    }
    user = getattr(request, "user", None)
    if user is not None and user.is_authenticated and user.is_staff:
        context["pending_review_count"] = ProxyApp.objects.filter(
            status=AppStatus.PENDING
        ).count()
    return context
