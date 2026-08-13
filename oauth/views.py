"""The OAuth2 endpoints third-party apps talk to.

The proxy is the authorization server from an app's point of view, and an OAuth
client from Canvas's point of view. The chain for one authorization is:

    app  -> GET  /oauth2/auth        (consent screen naming the app)
         -> Canvas /login/oauth2/auth (real Canvas consent, proxy's dev key)
         -> GET  /oauth2/canvas/callback
         -> app's redirect_uri?code=...
         -> POST /oauth2/token       (app swaps code for a proxy token)
"""

import base64
import binascii
import logging
from urllib.parse import urlencode, urlsplit, urlunsplit

from django.conf import settings
from django.db import transaction
from django.http import HttpResponseNotAllowed, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from canvasclient import client, crypto
from registry.models import AppStatus, ProxyApp

from .models import AuthorizationCode, AuthorizationRequest, CanvasGrant, ProxyToken

logger = logging.getLogger(__name__)

SUPPORTED_CHALLENGE_METHODS = {"S256", "plain"}


# --- helpers ----------------------------------------------------------------


def canvas_redirect_uri():
    """The single redirect URI every Canvas developer key must be given."""
    return f"{settings.PROXY_BASE_URL}/oauth2/canvas/callback"


def _error_page(request, message, status=400, detail=""):
    """Shown when we cannot safely bounce the error back to the app."""
    return render(
        request,
        "oauth/error.html",
        {"message": message, "detail": detail},
        status=status,
    )


def _redirect_with_error(redirect_uri, error, description="", state=""):
    params = {"error": error}
    if description:
        params["error_description"] = description
    if state:
        params["state"] = state
    return redirect(_append_query(redirect_uri, params))


def _append_query(url, params):
    parts = urlsplit(url)
    query = f"{parts.query}&{urlencode(params)}" if parts.query else urlencode(params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _json_error(error, description="", status=400):
    payload = {"error": error}
    if description:
        payload["error_description"] = description
    response = JsonResponse(payload, status=status)
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    if status == 401:
        response["WWW-Authenticate"] = 'Basic realm="canvas-proxy"'
    return response


# --- authorization endpoint -------------------------------------------------


@require_http_methods(["GET"])
def authorize(request):
    client_id = request.GET.get("client_id", "")
    redirect_uri = request.GET.get("redirect_uri", "")
    response_type = request.GET.get("response_type", "code")
    state = request.GET.get("state", "")
    code_challenge = request.GET.get("code_challenge", "")
    code_challenge_method = request.GET.get("code_challenge_method", "")

    app = (
        ProxyApp.objects.select_related("tier", "owner")
        .filter(client_id=client_id)
        .first()
    )

    # Until client_id and redirect_uri are both known-good we must not redirect
    # anywhere the request named -- that would be an open redirect.
    if not app:
        return _error_page(request, "Unknown client_id.", status=400)
    if not app.redirect_uri_allowed(redirect_uri):
        return _error_page(
            request,
            "That redirect_uri is not registered for this app.",
            status=400,
            detail="Redirect URIs must match a registered value exactly, "
            "character for character.",
        )

    if app.status != AppStatus.APPROVED:
        return _redirect_with_error(
            redirect_uri,
            "access_denied",
            f"This app is {app.get_status_display().lower()} and cannot request access.",
            state,
        )
    if not app.tier.is_active:
        return _redirect_with_error(
            redirect_uri, "temporarily_unavailable", "This access tier is disabled.", state
        )
    if not app.tier.is_configured:
        return _redirect_with_error(
            redirect_uri,
            "temporarily_unavailable",
            "This access tier has no Canvas developer key configured.",
            state,
        )
    if response_type != "code":
        return _redirect_with_error(
            redirect_uri,
            "unsupported_response_type",
            "Only response_type=code is supported.",
            state,
        )

    if code_challenge:
        method = (code_challenge_method or "plain").upper()
        if method == "PLAIN":
            method = "plain"
        if method not in SUPPORTED_CHALLENGE_METHODS:
            return _redirect_with_error(
                redirect_uri,
                "invalid_request",
                "code_challenge_method must be S256 or plain.",
                state,
            )
        code_challenge_method = method
    elif app.is_public_client:
        return _redirect_with_error(
            redirect_uri,
            "invalid_request",
            "This app is registered as a public client and must use PKCE.",
            state,
        )

    auth_request = AuthorizationRequest.start(
        app=app,
        redirect_uri=redirect_uri,
        client_state=state,
        code_challenge=code_challenge,
        method=code_challenge_method,
    )

    return render(
        request,
        "oauth/consent.html",
        {
            "app": app,
            "tier": app.tier,
            "auth_request": auth_request,
            "canvas_base_url": client.base_url(),
        },
    )


@require_http_methods(["POST"])
def authorize_confirm(request, request_id):
    auth_request = get_object_or_404(
        AuthorizationRequest.objects.select_related("app__tier"), pk=request_id
    )
    if not auth_request.is_live:
        return _error_page(
            request, "This authorization request has expired. Start again.", status=400
        )

    app = auth_request.app
    if request.POST.get("decision") != "allow":
        auth_request.consumed_at = timezone.now()
        auth_request.save(update_fields=["consumed_at"])
        return _redirect_with_error(
            auth_request.redirect_uri,
            "access_denied",
            "The user declined the request.",
            auth_request.client_state,
        )

    if app.status != AppStatus.APPROVED:
        return _redirect_with_error(
            auth_request.redirect_uri,
            "access_denied",
            "This app is no longer approved.",
            auth_request.client_state,
        )

    tier = app.tier
    return redirect(
        client.authorize_url(
            client_id=tier.canvas_client_id,
            redirect_uri=canvas_redirect_uri(),
            state=auth_request.proxy_state,
            scopes=tier.scopes if tier.enforces_scopes else (),
        )
    )


# --- Canvas callback --------------------------------------------------------


@require_http_methods(["GET"])
def canvas_callback(request):
    state = request.GET.get("state", "")
    auth_request = (
        AuthorizationRequest.objects.select_related("app__tier")
        .filter(proxy_state=state)
        .first()
    )
    if not auth_request:
        return _error_page(
            request,
            "This authorization could not be matched to a pending request.",
            status=400,
            detail="It may have expired, or already been completed.",
        )
    if not auth_request.is_live:
        return _error_page(
            request, "This authorization request has expired. Start again.", status=400
        )

    # From here on the redirect_uri is known-good, so errors go back to the app.
    error = request.GET.get("error")
    if error:
        _consume(auth_request)
        return _redirect_with_error(
            auth_request.redirect_uri,
            "access_denied",
            request.GET.get("error_description") or f"Canvas returned: {error}",
            auth_request.client_state,
        )

    code = request.GET.get("code")
    if not code:
        _consume(auth_request)
        return _redirect_with_error(
            auth_request.redirect_uri,
            "invalid_request",
            "Canvas did not return an authorization code.",
            auth_request.client_state,
        )

    app = auth_request.app
    tier = app.tier
    try:
        payload = client.exchange_code(
            client_id=tier.canvas_client_id,
            client_secret=tier.canvas_client_secret,
            redirect_uri=canvas_redirect_uri(),
            code=code,
        )
    except client.CanvasError as exc:
        _consume(auth_request)
        logger.warning("Canvas code exchange failed for app %s: %s", app.client_id, exc)
        return _redirect_with_error(
            auth_request.redirect_uri,
            "server_error",
            f"Canvas rejected the token exchange: {exc}",
            auth_request.client_state,
        )

    canvas_user = payload.get("user") or {}
    with transaction.atomic():
        grant = CanvasGrant(
            app=app,
            tier=tier,
            canvas_user_id=str(canvas_user.get("id") or ""),
            canvas_user_name=str(canvas_user.get("name") or "")[:255],
            canvas_global_id=str(canvas_user.get("global_id") or ""),
            scopes=list(tier.scopes or []),
        )
        grant.store_canvas_payload(payload)
        grant.save()

        raw_code = AuthorizationCode.issue(
            app=app,
            grant=grant,
            redirect_uri=auth_request.redirect_uri,
            code_challenge=auth_request.code_challenge,
            method=auth_request.code_challenge_method,
        )
        _consume(auth_request)

    params = {"code": raw_code}
    if auth_request.client_state:
        params["state"] = auth_request.client_state
    return redirect(_append_query(auth_request.redirect_uri, params))


def _consume(auth_request):
    auth_request.consumed_at = timezone.now()
    auth_request.save(update_fields=["consumed_at"])


# --- token endpoint ---------------------------------------------------------


@csrf_exempt
@require_http_methods(["POST"])
def token(request):
    grant_type = request.POST.get("grant_type", "")
    if grant_type == "authorization_code":
        return _token_authorization_code(request)
    if grant_type == "refresh_token":
        return _token_refresh(request)
    return _json_error(
        "unsupported_grant_type",
        "Supported grant types: authorization_code, refresh_token.",
    )


def _authenticate_client(request):
    """Resolve the calling app. Returns (app, error_response)."""
    client_id, client_secret = _client_credentials(request)
    if not client_id:
        return None, _json_error(
            "invalid_client", "No client_id supplied.", status=401
        )

    app = (
        ProxyApp.objects.select_related("tier", "owner")
        .filter(client_id=client_id)
        .first()
    )
    if not app:
        return None, _json_error("invalid_client", "Unknown client.", status=401)

    if app.is_public_client:
        # Public clients present no secret; PKCE is what binds the exchange.
        if client_secret:
            return None, _json_error(
                "invalid_client",
                "This app is registered as a public client and must not send a secret.",
                status=401,
            )
    elif not app.check_secret(client_secret):
        return None, _json_error("invalid_client", "Bad client credentials.", status=401)

    if app.status != AppStatus.APPROVED:
        return None, _json_error(
            "invalid_client",
            f"This app is {app.get_status_display().lower()}.",
            status=403,
        )
    if not app.tier.is_active:
        return None, _json_error(
            "invalid_client", "This access tier is disabled.", status=403
        )
    return app, None


def _client_credentials(request):
    """Read client credentials from HTTP Basic auth, falling back to the body."""
    header = request.META.get("HTTP_AUTHORIZATION", "")
    if header.startswith("Basic "):
        try:
            decoded = base64.b64decode(header[6:].strip()).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return "", ""
        client_id, _, client_secret = decoded.partition(":")
        return client_id, client_secret
    return request.POST.get("client_id", ""), request.POST.get("client_secret", "")


def _token_authorization_code(request):
    app, error = _authenticate_client(request)
    if error:
        return error

    raw_code = request.POST.get("code", "")
    if not raw_code:
        return _json_error("invalid_request", "Missing code.")

    auth_code = (
        AuthorizationCode.objects.select_related("grant", "app")
        .filter(code_digest=crypto.token_digest(raw_code))
        .first()
    )
    if not auth_code or auth_code.app_id != app.id:
        return _json_error("invalid_grant", "Unknown authorization code.")

    if auth_code.consumed_at is not None:
        # Replay: assume the code leaked and tear down what it produced.
        logger.warning(
            "Authorization code replay for app %s; revoking grant %s",
            app.client_id,
            auth_code.grant_id,
        )
        auth_code.grant.revoke()
        return _json_error("invalid_grant", "This code has already been used.")
    if auth_code.expires_at <= timezone.now():
        return _json_error("invalid_grant", "This code has expired.")

    redirect_uri = request.POST.get("redirect_uri", "")
    if redirect_uri and not crypto.constant_time_equals(
        redirect_uri, auth_code.redirect_uri
    ):
        return _json_error(
            "invalid_grant", "redirect_uri does not match the authorization request."
        )

    if not auth_code.verify_pkce(request.POST.get("code_verifier", "")):
        return _json_error("invalid_grant", "PKCE verification failed.")

    with transaction.atomic():
        auth_code.consumed_at = timezone.now()
        auth_code.save(update_fields=["consumed_at"])
        proxy_token, access_raw, refresh_raw = ProxyToken.issue(auth_code.grant)

    return _token_response(proxy_token, access_raw, refresh_raw, auth_code.grant)


def _token_refresh(request):
    app, error = _authenticate_client(request)
    if error:
        return error

    raw_refresh = request.POST.get("refresh_token", "")
    if not raw_refresh:
        return _json_error("invalid_request", "Missing refresh_token.")

    existing = ProxyToken.lookup_refresh(raw_refresh)
    if not existing or existing.grant.app_id != app.id:
        return _json_error("invalid_grant", "Unknown refresh token.")
    if not existing.grant.is_active:
        return _json_error("invalid_grant", "The underlying Canvas grant was revoked.")

    if existing.revoked_at is not None:
        # A revoked refresh token being presented means the old value leaked;
        # kill the whole grant rather than issue more tokens on it.
        logger.warning(
            "Refresh token reuse for app %s; revoking grant %s",
            app.client_id,
            existing.grant_id,
        )
        existing.grant.revoke()
        return _json_error("invalid_grant", "This refresh token was already used.")
    if not existing.refresh_is_live:
        return _json_error("invalid_grant", "This refresh token has expired.")

    with transaction.atomic():
        proxy_token, access_raw, refresh_raw = ProxyToken.issue(existing.grant)
        existing.revoked_at = timezone.now()
        existing.replaced_by = proxy_token
        existing.save(update_fields=["revoked_at", "replaced_by"])

    return _token_response(proxy_token, access_raw, refresh_raw, existing.grant)


def _token_response(proxy_token, access_raw, refresh_raw, grant):
    expires_in = int((proxy_token.expires_at - timezone.now()).total_seconds())
    payload = {
        "access_token": access_raw,
        "token_type": "Bearer",
        "expires_in": max(expires_in, 0),
        "refresh_token": refresh_raw,
        "scope": " ".join(grant.scopes or []),
        # Mirrors Canvas's own token response so existing clients can read it.
        "user": {
            "id": _maybe_int(grant.canvas_user_id),
            "name": grant.canvas_user_name,
            "global_id": grant.canvas_global_id,
        },
    }
    response = JsonResponse(payload)
    response["Cache-Control"] = "no-store"
    response["Pragma"] = "no-cache"
    return response


def _maybe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


# --- revocation -------------------------------------------------------------


@csrf_exempt
@require_http_methods(["POST", "DELETE"])
def revoke(request):
    """Revoke a proxy token, and the Canvas grant behind it.

    Accepts an RFC 7009 style POST (`token=...`) or a Canvas style
    `DELETE` carrying the token as a bearer credential.
    """
    raw = request.POST.get("token", "") if request.method == "POST" else ""
    if not raw:
        header = request.META.get("HTTP_AUTHORIZATION", "")
        if header.startswith("Bearer "):
            raw = header[7:].strip()
    if not raw:
        return _json_error("invalid_request", "No token supplied.")

    proxy_token = ProxyToken.lookup_access(raw) or ProxyToken.lookup_refresh(raw)
    if proxy_token:
        proxy_token.revoke()
        expire_sessions = request.POST.get("expire_sessions") in {"1", "true", "yes"}
        if proxy_token.grant.is_active:
            proxy_token.grant.revoke(at_canvas=True)
            if expire_sessions:
                logger.info("Grant %s revoked with session expiry requested", proxy_token.grant_id)

    # RFC 7009: unknown tokens still return 200 so callers cannot probe.
    response = JsonResponse({})
    response["Cache-Control"] = "no-store"
    return response


# --- metadata ---------------------------------------------------------------


@require_http_methods(["GET"])
def metadata(request):
    base = settings.PROXY_BASE_URL
    return JsonResponse(
        {
            "issuer": base,
            "authorization_endpoint": f"{base}/oauth2/auth",
            "token_endpoint": f"{base}/oauth2/token",
            "revocation_endpoint": f"{base}/oauth2/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": sorted(SUPPORTED_CHALLENGE_METHODS),
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "canvas_base_url": settings.CANVAS_BASE_URL,
            "api_base_url": f"{base}/api",
        }
    )


# --- Canvas-shaped aliases --------------------------------------------------


@require_http_methods(["GET"])
def canvas_style_authorize(request):
    """Alias for /login/oauth2/auth so Canvas SDKs work unmodified."""
    return authorize(request)


@csrf_exempt
def canvas_style_token(request):
    """Alias for /login/oauth2/token: POST exchanges, DELETE revokes."""
    if request.method == "POST":
        return token(request)
    if request.method == "DELETE":
        return revoke(request)
    return HttpResponseNotAllowed(["POST", "DELETE"])
