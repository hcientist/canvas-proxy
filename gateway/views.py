"""The proxy itself: authenticated app requests forwarded to Canvas.

Anything under /api/ is passed through to the same path on the Canvas host,
using the Canvas token stored for the caller's grant. The app's own bearer
token never reaches Canvas and the Canvas token never reaches the app.
"""

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

from .models import RequestLog
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
}

# Canvas never needs these from us, and they can escalate privilege.
BLOCKED_QUERY_PARAMS = {"access_token", "as_user_id"}

LINK_URL_RE = re.compile(r"<([^>]+)>")


@csrf_exempt
def proxy(request, upstream_path=""):
    started = time.monotonic()
    path = "/api/" + upstream_path.lstrip("/")

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

    allowed, reason = app.tier.permits(request.method, path)
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

    blocked = _blocked_params(request, app.tier)
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

    try:
        canvas_token = grant.usable_access_token()
    except client.CanvasError as exc:
        logger.warning("Could not refresh Canvas token for grant %s: %s", grant.id, exc)
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
    try:
        upstream = requests.request(
            method=request.method,
            url=upstream_url,
            params=_forwardable_query(request),
            data=request.body if request.body else None,
            headers=_forwardable_headers(request, canvas_token),
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
            description="Could not reach Canvas.",
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

    return _relay(upstream)


def _relay(upstream):
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
            value = _rewrite_link_header(value)
        elif lowered == "location":
            value = _rewrite_url(value)
        response[name] = value
    return response


def _bearer_token(request):
    header = request.META.get("HTTP_AUTHORIZATION", "")
    if header.startswith("Bearer "):
        return header[7:].strip()
    return ""


def _blocked_params(request, tier):
    for name in request.GET:
        lowered = name.lower()
        if lowered == "as_user_id" and tier.allow_masquerade:
            continue
        if lowered in BLOCKED_QUERY_PARAMS:
            return name
    return ""


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
    headers = {"Authorization": f"Bearer {canvas_token}"}
    for key, value in request.META.items():
        if not key.startswith("HTTP_"):
            continue
        name = key[5:].replace("_", "-").lower()
        if name in STRIPPED_REQUEST_HEADERS:
            continue
        headers[name] = value
    if request.META.get("CONTENT_TYPE"):
        headers["content-type"] = request.META["CONTENT_TYPE"]
    # Let Canvas's own logs show that traffic arrived through this proxy.
    headers["user-agent"] = request.META.get("HTTP_USER_AGENT", "canvas-proxy")
    headers["x-canvas-proxy"] = "1"
    return headers


def _rewrite_link_header(value):
    """Point RFC 5988 pagination links back at the proxy, not Canvas."""
    return LINK_URL_RE.sub(lambda m: f"<{_rewrite_url(m.group(1))}>", value)


def _rewrite_url(url):
    """Swap the Canvas origin for the proxy origin on API URLs only.

    File downloads redirect to presigned storage hosts; those must pass through
    untouched or the signature breaks.
    """
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


def _client_ip(request):
    forwarded = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded:
        candidate = forwarded.split(",")[0].strip()
        if candidate:
            return candidate
    return request.META.get("REMOTE_ADDR") or None
