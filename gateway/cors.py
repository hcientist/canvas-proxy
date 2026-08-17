"""Cross-origin access for browser frontends.

An app's frontend runs somewhere other than this host, so without CORS headers
the browser discards every response and the proxy is unusable from client-side
JavaScript -- which is most of what students build.

The allowed origins are not configured separately. They are derived from the
redirect URIs of approved apps, which are already exact, already reviewed by a
staff member, and already the addresses this proxy is willing to send an
authorization code to. Anything good enough to receive a code is good enough to
read a response.

CORS is not an access control here. The bearer token is what authorizes a
request; these headers only decide whether a browser will hand the result to
the page that asked.
"""

import logging
from urllib.parse import urlsplit

from django.core.cache import cache
from django.http import HttpResponse

from registry.models import AppStatus, ProxyApp

logger = logging.getLogger(__name__)

# Only the machine-facing surface. The dashboard and consent screens are
# deliberately excluded -- they are meant to be visited, not scripted.
CORS_PATHS = (
    "/ext/",
    "/api/",
    "/oauth2/token",
    "/oauth2/revoke",
    "/oauth2/metadata",
)

ALLOWED_METHODS = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"

# Without this a browser cannot read pagination or rate-limit information even
# though it arrived.
EXPOSED_HEADERS = "Link, Retry-After, X-Rate-Limit-Remaining, X-Request-Cost"

DEFAULT_ALLOWED_HEADERS = "Authorization, Content-Type"

ORIGIN_CACHE_KEY = "cors:allowed-origins"
ORIGIN_CACHE_SECONDS = 30


def origin_of(url):
    """scheme://host[:port] for a redirect URI, or "" if it has no host."""
    parts = urlsplit(url)
    if not parts.scheme or not parts.netloc:
        return ""
    return f"{parts.scheme}://{parts.netloc}"


def allowed_origins():
    """Origins of every approved app's registered redirect URIs."""
    try:
        cached = cache.get(ORIGIN_CACHE_KEY)
    except Exception:  # noqa: BLE001 - a cache outage must not break CORS
        cached = None
    if cached is not None:
        return cached

    origins = set()
    for uris in ProxyApp.objects.filter(status=AppStatus.APPROVED).values_list(
        "redirect_uris", flat=True
    ):
        for uri in uris or []:
            origin = origin_of(uri)
            if origin:
                origins.add(origin)

    try:
        cache.set(ORIGIN_CACHE_KEY, origins, ORIGIN_CACHE_SECONDS)
    except Exception:  # noqa: BLE001
        logger.warning("Could not cache CORS origins", exc_info=True)
    return origins


def forget_origins():
    """Drop the cached set, so an approval takes effect immediately."""
    try:
        cache.delete(ORIGIN_CACHE_KEY)
    except Exception:  # noqa: BLE001
        pass


class CorsMiddleware:
    """Answers preflights and marks up responses on the API surface."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        origin = request.META.get("HTTP_ORIGIN", "")
        covered = origin and _is_cors_path(request.path)
        permitted = bool(covered) and origin in allowed_origins()

        # A preflight must never reach the proxy view: that would forward an
        # OPTIONS upstream, or reject it for having no bearer token, and the
        # browser would report a CORS failure either way.
        if (
            covered
            and request.method == "OPTIONS"
            and "HTTP_ACCESS_CONTROL_REQUEST_METHOD" in request.META
        ):
            response = HttpResponse(status=204 if permitted else 403)
            self._decorate(request, response, origin, permitted)
            return response

        response = self.get_response(request)
        if covered:
            self._decorate(request, response, origin, permitted)
        return response

    def _decorate(self, request, response, origin, permitted):
        # Vary regardless of the outcome: the answer depends on Origin, so a
        # cache must not serve one origin's response to another.
        existing = response.get("Vary", "")
        if "origin" not in existing.lower():
            response["Vary"] = f"{existing}, Origin" if existing else "Origin"

        if not permitted:
            return

        response["Access-Control-Allow-Origin"] = origin
        response["Access-Control-Allow-Methods"] = ALLOWED_METHODS
        response["Access-Control-Expose-Headers"] = EXPOSED_HEADERS
        response["Access-Control-Max-Age"] = "600"
        requested = request.META.get("HTTP_ACCESS_CONTROL_REQUEST_HEADERS")
        response["Access-Control-Allow-Headers"] = requested or DEFAULT_ALLOWED_HEADERS
        # Deliberately no Access-Control-Allow-Credentials: authorization is by
        # bearer token, and allowing cookies cross-origin would expose the
        # dashboard session to any approved app's origin.


def _is_cors_path(path):
    return any(path.startswith(prefix) for prefix in CORS_PATHS)
