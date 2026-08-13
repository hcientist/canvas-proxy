"""Sign-in to the proxy's own dashboard, via Canvas OAuth.

This flow exists only to identify the developer using the dashboard. The Canvas
token it obtains is used for a single profile lookup and then revoked -- the
proxy never stores a token from a dashboard sign-in.
"""

import logging
import secrets

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, login, logout
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views.decorators.http import require_http_methods

from canvasclient import client
from registry.models import AccessTier

logger = logging.getLogger(__name__)
User = get_user_model()

SESSION_STATE_KEY = "canvas_login_state"
SESSION_NEXT_KEY = "canvas_login_next"

# Scopes needed purely to learn who is signing in. If your developer keys
# enforce scopes, the login tier's key must include these.
LOGIN_SCOPES = ["url:GET|/api/v1/users/:id/profile"]


def login_view(request):
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)
    return render(request, "accounts/login.html", {"next": request.GET.get("next", "")})


def _login_tier():
    return AccessTier.objects.filter(
        slug=settings.CANVAS_LOGIN_TIER, is_active=True
    ).first()


@require_http_methods(["POST"])
def canvas_login_start(request):
    tier = _login_tier()
    if not tier or not tier.is_configured:
        messages.error(
            request,
            "Canvas sign-in is not configured yet. Ask an administrator to set "
            f"up the '{settings.CANVAS_LOGIN_TIER}' tier's developer key.",
        )
        return redirect("accounts:login")

    state = secrets.token_urlsafe(32)
    request.session[SESSION_STATE_KEY] = state
    request.session[SESSION_NEXT_KEY] = _safe_next(request.POST.get("next", ""))

    return redirect(
        client.authorize_url(
            client_id=tier.canvas_client_id,
            redirect_uri=dashboard_redirect_uri(),
            state=state,
            scopes=LOGIN_SCOPES if tier.enforces_scopes else (),
        )
    )


def dashboard_redirect_uri():
    return f"{settings.PROXY_BASE_URL}/login/canvas/callback"


def _safe_next(value):
    """Only allow same-site relative redirects."""
    if value.startswith("/") and not value.startswith("//"):
        return value
    return ""


def canvas_login_callback(request):
    expected_state = request.session.pop(SESSION_STATE_KEY, None)
    next_url = request.session.pop(SESSION_NEXT_KEY, "")

    error = request.GET.get("error")
    if error:
        messages.error(request, f"Canvas declined the sign-in: {error}")
        return redirect("accounts:login")

    state = request.GET.get("state")
    code = request.GET.get("code")
    if not expected_state or not state or state != expected_state:
        messages.error(request, "Sign-in expired or was tampered with. Try again.")
        return redirect("accounts:login")
    if not code:
        messages.error(request, "Canvas did not return an authorization code.")
        return redirect("accounts:login")

    tier = _login_tier()
    if not tier or not tier.is_configured:
        messages.error(request, "Canvas sign-in is not configured.")
        return redirect("accounts:login")

    try:
        payload = client.exchange_code(
            client_id=tier.canvas_client_id,
            client_secret=tier.canvas_client_secret,
            redirect_uri=dashboard_redirect_uri(),
            code=code,
        )
    except client.CanvasError as exc:
        logger.warning("Dashboard sign-in token exchange failed: %s", exc)
        messages.error(request, f"Canvas sign-in failed: {exc}")
        return redirect("accounts:login")

    access_token = payload["access_token"]
    canvas_user = payload.get("user") or {}
    canvas_user_id = str(canvas_user.get("id") or "")
    if not canvas_user_id:
        messages.error(request, "Canvas did not identify the signed-in user.")
        return redirect("accounts:login")

    profile = {}
    try:
        profile = client.get_json("/api/v1/users/self/profile", access_token)
    except client.CanvasError as exc:
        # Not fatal: we already know who they are from the token response.
        logger.info("Could not read Canvas profile during sign-in: %s", exc)
    finally:
        client.revoke(access_token)

    user = _upsert_user(canvas_user_id, canvas_user, profile)
    login(request, user)
    messages.success(request, f"Signed in as {user.display_name}.")
    return redirect(next_url or settings.LOGIN_REDIRECT_URL)


def _upsert_user(canvas_user_id, canvas_user, profile):
    defaults = {
        "canvas_name": profile.get("name") or canvas_user.get("name") or "",
        "canvas_login_id": profile.get("login_id") or "",
        "canvas_avatar_url": (profile.get("avatar_url") or "")[:500],
        "email": profile.get("primary_email") or "",
        "last_canvas_login": timezone.now(),
    }
    user, created = User.objects.get_or_create(
        canvas_user_id=canvas_user_id,
        defaults={"username": f"canvas-{canvas_user_id}", **defaults},
    )
    if not created:
        for field, value in defaults.items():
            # Don't blank out a stored value when Canvas omits the field.
            if value:
                setattr(user, field, value)
        user.save(update_fields=[*defaults.keys()])
    return user


@require_http_methods(["POST"])
def logout_view(request):
    logout(request)
    messages.success(request, "Signed out.")
    return redirect(settings.LOGOUT_REDIRECT_URL)
