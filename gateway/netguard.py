"""Guards against pointing the proxy at things it should not reach.

An external app's base URL is chosen by a student, so without this the proxy
would be a general-purpose SSRF tool with a Canvas login on the front: it runs
inside a private Docker network, so `http://postgres:5432`, `http://127.0.0.1`
or the cloud metadata address `http://169.254.169.254/` would all be reachable
from it and from nowhere else the student can get to.

Names are checked twice -- once when the app is registered, and again on every
proxied request, because the address behind a name can change after approval.
"""

import ipaddress
import socket
from urllib.parse import urlsplit

from django.core.exceptions import ValidationError

# Ports that are almost never a public HTTP API and often are something
# sensitive listening on an internal network.
BLOCKED_PORTS = {22, 23, 25, 445, 465, 587, 3306, 5432, 6379, 9200, 11211, 27017}


class UnsafeUpstream(Exception):
    """The requested upstream host is not one this proxy will talk to."""


def validate_api_base_url(value):
    """Validate a third-party API base URL at registration time.

    Raises ValidationError so it can be used directly as a form/model validator.
    """
    parts = urlsplit(value)

    if parts.scheme != "https":
        raise ValidationError(
            "The API base URL must use https. Credentials and student data "
            "would otherwise cross the network in the clear."
        )
    if not parts.hostname:
        raise ValidationError("The API base URL is missing a host.")
    if parts.username or parts.password:
        raise ValidationError(
            "Put credentials in the client id/secret fields, not in the URL."
        )
    if parts.fragment:
        raise ValidationError("The API base URL must not contain a fragment (#...).")
    if parts.query:
        raise ValidationError(
            "The API base URL must not contain a query string; the proxy "
            "forwards the caller's own query parameters."
        )
    if parts.port in BLOCKED_PORTS:
        raise ValidationError(f"Port {parts.port} is not allowed for an upstream API.")

    try:
        assert_safe_host(parts.hostname)
    except UnsafeUpstream as exc:
        raise ValidationError(str(exc)) from exc

    return value


def normalize_api_base_url(value):
    """Strip a trailing slash so joining a path never doubles it."""
    return (value or "").strip().rstrip("/")


def assert_safe_host(hostname):
    """Resolve `hostname` and refuse it unless every address is public.

    Checking every returned address matters: a name with both a public and a
    private record would otherwise pass while still being usable to reach the
    private one.
    """
    try:
        results = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise UnsafeUpstream(f"Could not resolve {hostname}: {exc}") from exc

    if not results:
        raise UnsafeUpstream(f"{hostname} did not resolve to any address.")

    for result in results:
        address = result[4][0]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            raise UnsafeUpstream(f"{hostname} resolved to an unusable address.")
        if not ip.is_global:
            raise UnsafeUpstream(
                f"{hostname} resolves to {ip}, which is a private or reserved "
                "address. The proxy only forwards to public hosts."
            )
    return True


def check_upstream_url(url):
    """Request-time check. Returns (ok, reason)."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        return False, "The upstream API must be reached over https."
    if parts.port in BLOCKED_PORTS:
        return False, f"Port {parts.port} is not allowed for an upstream API."
    try:
        assert_safe_host(parts.hostname or "")
    except UnsafeUpstream as exc:
        return False, str(exc)
    return True, ""
