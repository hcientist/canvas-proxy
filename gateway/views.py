"""The proxy itself: authenticated app requests forwarded to Canvas.

Anything under /api/ is passed through to the same path on the Canvas host,
using the Canvas token stored for the caller's grant. The app's own bearer
token never reaches Canvas and the Canvas token never reaches the app.
"""

import base64
import logging
import re
import time

import requests
from django.conf import settings
from django.http import JsonResponse, StreamingHttpResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from canvasclient import client
from oauth.models import ProxyToken
from registry.models import AppStatus, CredentialStyle, ProxyApp

from .cors import allowed_origins, origin_of
from .models import RequestLog
from .netguard import check_upstream_url
from .ratelimit import check_rate_limit

logger = logging.getLogger(__name__)

# Headers that describe a single hop and must not be copied across the proxy.
HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

# Request headers we refuse to forward even though they are end-to-end.
STRIPPED_REQUEST_HEADERS = HOP_BY_HOP | {
    "authorization",
    "host",
    "cookie",
    "content-length",
    # The proxy streams the response without decompressing it, and strips
    # content-encoding on the way back.  If the upstream compressed the body,
    # the browser would receive raw gzip bytes it has no reason to decompress.
    # Dropping accept-encoding tells the upstream not to compress, avoiding
    # the mismatch entirely.
    "accept-encoding",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
}

STRIPPED_RESPONSE_HEADERS = HOP_BY_HOP | {
    "content-length",
    "content-encoding",
    "set-cookie",
    "strict-transport-security",
    # Upstream APIs (Giphy, etc.) may send their own CORS headers.  Letting
    # them through would conflict with the proxy's CorsMiddleware -- e.g. an
    # upstream Access-Control-Allow-Credentials: true makes browsers reject a
    # response whose Allow-Origin was set by us.  Strip them all so only the
    # proxy's own CORS headers survive.
    "access-control-allow-origin",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-allow-credentials",
    "access-control-expose-headers",
    "access-control-max-age",
}

# Canvas never needs these from us, and they can escalate privilege.
BLOCKED_QUERY_PARAMS = {"access_token", "as_user_id"}

LINK_URL_RE = re.compile(r"<([^>]+)>")


@csrf_exempt
def proxy(request, upstream_path=""):
    """Forward to the Canvas API. Canvas-kind apps only."""
    return _proxy(request, "/api/" + upstream_path.lstrip("/"), external=False)


@csrf_exempt
def external_proxy(request, upstream_path=""):
    """Forward to an external app's registered API."""
    return _proxy(request, "/" + upstream_path.lstrip("/"), external=True)


@csrf_exempt
def anonymous_external_proxy(request, client_id, upstream_path=""):
    """Forward to an external app's API without a bearer token.

    The app must have allow_anonymous=True.  Instead of a bearer token, the
    request is gated by Origin: only origins derived from the app's registered
    redirect URIs are accepted.  This keeps the upstream credentials server-side
    while letting a static frontend call the API without an OAuth flow.
    """
    path = "/" + upstream_path.lstrip("/")
    started = time.monotonic()

    try:
        app = ProxyApp.objects.get(client_id=client_id)
    except ProxyApp.DoesNotExist:
        return _anon_deny(request, path, None, "Unknown app", 404, "not_found")

    if not app.is_external or not app.allow_anonymous:
        return _anon_deny(
            request, path, app, "Not configured for anonymous access",
            403, "access_denied",
            description="This app does not allow anonymous requests.",
        )
    if not app.is_usable:
        return _anon_deny(
            request, path, app,
            f"App is {app.get_status_display().lower()}",
            403, "access_denied",
            description=f"This app is {app.get_status_display().lower()}.",
        )

    origin = request.META.get("HTTP_ORIGIN", "")
    app_origins = {origin_of(uri) for uri in (app.redirect_uris or [])}
    app_origins.discard("")
    if not origin or origin not in app_origins:
        return _anon_deny(
            request, path, app, "Origin not allowed",
            403, "access_denied",
            description="This origin is not registered for this app.",
        )

    allowed, reason = app.permits(request.method, path)
    if not allowed:
        return _anon_deny(
            request, path, app, reason, 403, "insufficient_scope", description=reason,
        )

    blocked = _blocked_params(request, app)
    if blocked:
        reason = f"Query parameter '{blocked}' is not permitted."
        return _anon_deny(
            request, path, app, reason, 403, "access_denied", description=reason,
        )

    within_limit, retry_after = check_rate_limit(app)
    if not within_limit:
        response = _anon_deny(
            request, path, app, "Rate limited", 429, "rate_limited",
            description="Too many requests through this app. Slow down.",
        )
        response["Retry-After"] = str(retry_after)
        return response

    upstream_url = f"{app.api_base_url}{path}"
    safe, reason = check_upstream_url(upstream_url)
    if not safe:
        logger.warning(
            "Refusing upstream %s for app %s: %s",
            app.api_base_url, app.client_id, reason,
        )
        return _anon_deny(
            request, path, app, "Unsafe upstream host", 502, "upstream_error",
            description=reason,
        )

    headers = _forwardable_headers(request, None)
    params = _forwardable_query(request)
    _apply_upstream_credentials(app, headers, params)

    try:
        upstream = requests.request(
            method=request.method,
            url=upstream_url,
            params=params,
            data=request.body if request.body else None,
            headers=headers,
            timeout=(settings.CANVAS_CONNECT_TIMEOUT, settings.CANVAS_TIMEOUT),
            allow_redirects=False,
            stream=True,
        )
    except requests.Timeout:
        return _anon_deny(
            request, path, app, "Upstream timeout", 504, "upstream_timeout",
            description=f"Could not reach {app.upstream_label} in time.",
        )
    except requests.RequestException as exc:
        logger.warning("Upstream request to %s failed: %s", path, exc)
        return _anon_deny(
            request, path, app, "Upstream error", 502, "upstream_error",
            description=f"Could not reach {app.upstream_label}.",
        )

    duration_ms = int((time.monotonic() - started) * 1000)
    _anon_log(request, path, app, upstream.status_code, duration_ms)
    return _relay(upstream, app)


def _proxy(request, path, external):
    started = time.monotonic()

    token_value = _bearer_token(request)
    if not token_value:
        return _deny(
            request,
            path,
            None,
            "Missing bearer token",
            status=401,
            error="invalid_request",
            description="Send the proxy access token as 'Authorization: Bearer <token>'.",
        )

    proxy_token = ProxyToken.lookup_access(token_value)
    if not proxy_token:
        return _deny(
            request, path, None, "Unknown token", status=401, error="invalid_token"
        )
    if proxy_token.revoked_at is not None:
        return _deny(
            request,
            path,
            proxy_token,
            "Token revoked",
            status=401,
            error="invalid_token",
            description="This token has been revoked.",
        )
    if proxy_token.expires_at <= timezone.now():
        return _deny(
            request,
            path,
            proxy_token,
            "Token expired",
            status=401,
            error="invalid_token",
            description="This token has expired; use the refresh token.",
        )

    grant = proxy_token.grant
    app = grant.app
    if not grant.is_active:
        return _deny(
            request, path, proxy_token, "Grant revoked", status=401, error="invalid_token"
        )
    if not app.is_usable:
        return _deny(
            request,
            path,
            proxy_token,
            f"App is {app.get_status_display().lower()}",
            status=403,
            error="access_denied",
            description=f"This app is {app.get_status_display().lower()}.",
        )

    # The two prefixes are not interchangeable: a Canvas token must not be
    # spendable against an arbitrary third-party host, and vice versa.
    if app.is_external != external:
        wanted = "/ext/" if app.is_external else "/api/"
        return _deny(
            request,
            path,
            proxy_token,
            "Wrong proxy prefix for this app kind",
            status=404,
            error="not_found",
            description=f"This app proxies through {wanted}, not this prefix.",
        )

    allowed, reason = app.permits(request.method, path)
    if not allowed:
        return _deny(
            request,
            path,
            proxy_token,
            reason,
            status=403,
            error="insufficient_scope",
            description=reason,
        )

    blocked = _blocked_params(request, app)
    if blocked:
        reason = f"Query parameter '{blocked}' is not permitted."
        return _deny(
            request,
            path,
            proxy_token,
            reason,
            status=403,
            error="access_denied",
            description=reason,
        )

    within_limit, retry_after = check_rate_limit(app)
    if not within_limit:
        response = _deny(
            request,
            path,
            proxy_token,
            "Rate limited",
            status=429,
            error="rate_limited",
            description="Too many requests through this app. Slow down.",
        )
        response["Retry-After"] = str(retry_after)
        return response

    content_length = int(request.META.get("CONTENT_LENGTH") or 0)
    if content_length > settings.CANVAS_MAX_BODY_BYTES:
        return _deny(
            request,
            path,
            proxy_token,
            "Request body too large",
            status=413,
            error="payload_too_large",
        )

    if external:
        upstream_url = f"{app.api_base_url}{path}"
        # Re-checked here, not just at registration: the address behind a
        # hostname can change after a reviewer has approved it.
        safe, reason = check_upstream_url(upstream_url)
        if not safe:
            logger.warning(
                "Refusing upstream %s for app %s: %s",
                app.api_base_url,
                app.client_id,
                reason,
            )
            return _deny(
                request,
                path,
                proxy_token,
                "Unsafe upstream host",
                status=502,
                error="upstream_error",
                description=reason,
            )
        headers = _forwardable_headers(request, None)
        params = _forwardable_query(request)
        _apply_upstream_credentials(app, headers, params)
    else:
        try:
            canvas_token = grant.usable_access_token()
        except client.CanvasError as exc:
            logger.warning(
                "Could not refresh Canvas token for grant %s: %s", grant.id, exc
            )
            return _deny(
                request,
                path,
                proxy_token,
                "Canvas token refresh failed",
                status=502,
                error="upstream_error",
                description=f"Could not renew the Canvas token: {exc}",
            )
        upstream_url = f"{client.base_url()}{path}"
        headers = _forwardable_headers(request, canvas_token)
        params = _forwardable_query(request)

    try:
        upstream = requests.request(
            method=request.method,
            url=upstream_url,
            params=params,
            data=request.body if request.body else None,
            headers=headers,
            timeout=(settings.CANVAS_CONNECT_TIMEOUT, settings.CANVAS_TIMEOUT),
            allow_redirects=False,
            stream=True,
        )
    except requests.Timeout:
        return _deny(
            request,
            path,
            proxy_token,
            "Upstream timeout",
            status=504,
            error="upstream_timeout",
            description="Canvas did not respond in time.",
        )
    except requests.RequestException as exc:
        logger.warning("Upstream request to %s failed: %s", path, exc)
        return _deny(
            request,
            path,
            proxy_token,
            "Upstream error",
            status=502,
            error="upstream_error",
            description=(
                f"Could not reach {app.upstream_label}."
                if external
                else "Could not reach Canvas."
            ),
        )

    duration_ms = int((time.monotonic() - started) * 1000)
    _touch(proxy_token, grant)
    _log(
        request,
        path,
        proxy_token,
        status_code=upstream.status_code,
        duration_ms=duration_ms,
    )

    return _relay(upstream, app if external else None)


def _relay(upstream, external_app=None):
    response = StreamingHttpResponse(
        upstream.iter_content(chunk_size=64 * 1024),
        status=upstream.status_code,
        content_type=upstream.headers.get("Content-Type"),
    )
    for name, value in upstream.headers.items():
        lowered = name.lower()
        if lowered in STRIPPED_RESPONSE_HEADERS or lowered == "content-type":
            continue
        if lowered == "link":
            value = _rewrite_link_header(value, external_app)
        elif lowered == "location":
            value = _rewrite_url(value, external_app)
        response[name] = value
    return response


def _bearer_token(request):
    header = request.META.get("HTTP_AUTHORIZATION", "")
    if header.startswith("Bearer "):
        return header[7:].strip()
    return ""


def _blocked_params(request, app):
    """Query parameters the caller may not set.

    For an external app that authenticates by query parameter, the caller must
    not be able to supply that parameter itself -- it would either override the
    stored credential or, with a repeated key, let the caller see which value
    the upstream accepted.
    """
    credential_param = ""
    if app.is_external and app.credential_style == CredentialStyle.QUERY:
        credential_param = (app.credential_name or "").lower()

    for name in request.GET:
        lowered = name.lower()
        if credential_param and lowered == credential_param:
            return name
        if app.is_external:
            # as_user_id is a Canvas concept; upstream APIs get the raw query.
            if lowered == "access_token":
                return name
            continue
        if lowered == "as_user_id" and app.tier and app.tier.allow_masquerade:
            continue
        if lowered in BLOCKED_QUERY_PARAMS:
            return name
    return ""


def _apply_upstream_credentials(app, headers, params):
    """Attach the app's registered credentials for its third-party API."""
    style = app.credential_style
    secret = app.upstream_client_secret

    if style == CredentialStyle.BEARER:
        headers["Authorization"] = f"Bearer {secret}"
    elif style == CredentialStyle.BASIC:
        raw = f"{app.upstream_client_id}:{secret}".encode()
        headers["Authorization"] = f"Basic {base64.b64encode(raw).decode()}"
    elif style == CredentialStyle.HEADER and app.credential_name:
        headers[app.credential_name] = secret
    elif style == CredentialStyle.QUERY and app.credential_name:
        params.append((app.credential_name, secret))


def _forwardable_query(request):
    """Rebuild the query string, preserving repeated keys like include[]=.

    `_blocked_params` has already rejected anything on the blocklist, so the
    filter here is belt-and-braces: an inline access_token must never reach
    Canvas, where it would take precedence over our Authorization header.
    """
    params = []
    for name, values in request.GET.lists():
        if name.lower() == "access_token":
            continue
        params.extend((name, value) for value in values)
    return params


def _forwardable_headers(request, canvas_token):
    """Copy the caller's headers, minus anything hop-by-hop or privileged.

    `canvas_token` is None for external apps; their credentials are attached
    afterwards by `_apply_upstream_credentials`.
    """
    headers = {}
    if canvas_token:
        headers["Authorization"] = f"Bearer {canvas_token}"
    for key, value in request.META.items():
        if not key.startswith("HTTP_"):
            continue
        name = key[5:].replace("_", "-").lower()
        if name in STRIPPED_REQUEST_HEADERS:
            continue
        headers[name] = value
    if request.META.get("CONTENT_TYPE"):
        headers["content-type"] = request.META["CONTENT_TYPE"]
    # Let the upstream's own logs show that traffic arrived through this proxy.
    headers["user-agent"] = request.META.get("HTTP_USER_AGENT", "canvas-proxy")
    headers["x-canvas-proxy"] = "1"
    return headers


def _rewrite_link_header(value, external_app=None):
    """Point RFC 5988 pagination links back at the proxy, not the upstream."""
    return LINK_URL_RE.sub(
        lambda m: f"<{_rewrite_url(m.group(1), external_app)}>", value
    )


def _rewrite_url(url, external_app=None):
    """Swap the upstream origin for the proxy origin on API URLs only.

    File downloads redirect to presigned storage hosts; those must pass through
    untouched or the signature breaks.
    """
    if external_app is not None:
        base = external_app.api_base_url
        if base and url.startswith(base):
            return f"{settings.PROXY_BASE_URL}/ext{url[len(base):]}"
        return url

    canvas = client.base_url()
    if url.startswith(canvas + "/api/"):
        return settings.PROXY_BASE_URL + url[len(canvas) :]
    return url


def _touch(proxy_token, grant):
    now = timezone.now()
    ProxyToken.objects.filter(pk=proxy_token.pk).update(last_used_at=now)
    type(grant).objects.filter(pk=grant.pk).update(last_used_at=now)


def _deny(request, path, proxy_token, reason, status, error, description=""):
    _log(request, path, proxy_token, status_code=status, denied_reason=reason)
    payload = {"error": error}
    if description:
        payload["error_description"] = description
    payload["errors"] = [{"message": description or reason}]
    response = JsonResponse(payload, status=status)
    if status == 401:
        response["WWW-Authenticate"] = (
            f'Bearer realm="canvas-proxy", error="{error}"'
        )
    return response


def _log(request, path, proxy_token, status_code=None, duration_ms=None, denied_reason=""):
    grant = proxy_token.grant if proxy_token else None
    try:
        RequestLog.objects.create(
            app=grant.app if grant else None,
            grant=grant,
            canvas_user_id=grant.canvas_user_id if grant else "",
            method=request.method,
            path=path[:500],
            query=request.META.get("QUERY_STRING", "")[:1000],
            status_code=status_code,
            duration_ms=duration_ms,
            denied_reason=denied_reason[:255],
            client_ip=_client_ip(request),
        )
    except Exception:  # noqa: BLE001 - auditing must never break a request
        logger.exception("Failed to write request log for %s %s", request.method, path)


def _anon_deny(request, path, app, reason, status, error, description=""):
    _anon_log(request, path, app, status, denied_reason=reason)
    payload = {"error": error}
    if description:
        payload["error_description"] = description
    payload["errors"] = [{"message": description or reason}]
    return JsonResponse(payload, status=status)


def _anon_log(request, path, app, status_code=None, duration_ms=None, denied_reason=""):
    try:
        RequestLog.objects.create(
            app=app,
            grant=None,
            canvas_user_id="",
            method=request.method,
            path=path[:500],
            query=request.META.get("QUERY_STRING", "")[:1000],
            status_code=status_code,
            duration_ms=duration_ms,
            denied_reason=(denied_reason or "")[:255],
            client_ip=_client_ip(request),
        )
    except Exception:  # noqa: BLE001 - auditing must never break a request
        logger.exception("Failed to write request log for %s %s", request.method, path)


def _client_ip(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        candidate = forwarded.split(",")[0].strip()
        if candidate:
            return candidate
    return request.META.get("REMOTE_ADDR") or None
