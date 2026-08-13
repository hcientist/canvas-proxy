"""Thin wrapper over the Canvas OAuth2 and REST endpoints."""

import logging
from urllib.parse import urlencode

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

AUTHORIZE_PATH = "/login/oauth2/auth"
TOKEN_PATH = "/login/oauth2/token"


class CanvasError(Exception):
    """An upstream Canvas call failed."""

    def __init__(self, message, status=None, payload=None):
        super().__init__(message)
        self.status = status
        self.payload = payload or {}


def base_url():
    return settings.CANVAS_BASE_URL.rstrip("/")


def _timeout():
    return (settings.CANVAS_CONNECT_TIMEOUT, settings.CANVAS_TIMEOUT)


def authorize_url(client_id, redirect_uri, state, scopes=(), force_login=False):
    """Build the Canvas consent URL the end user is sent to."""
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "state": state,
    }
    if scopes:
        params["scope"] = " ".join(scopes)
    if force_login:
        params["force_login"] = "1"
    return f"{base_url()}{AUTHORIZE_PATH}?{urlencode(params)}"


def _token_request(data):
    url = f"{base_url()}{TOKEN_PATH}"
    try:
        response = requests.post(url, data=data, timeout=_timeout())
    except requests.RequestException as exc:
        raise CanvasError(f"Could not reach Canvas: {exc}") from exc

    try:
        payload = response.json()
    except ValueError:
        payload = {}

    if response.status_code >= 400:
        message = (
            payload.get("error_description")
            or payload.get("error")
            or payload.get("message")
            or f"Canvas returned HTTP {response.status_code}"
        )
        # Never log `data` -- it carries the client secret and the grant code.
        logger.warning("Canvas token endpoint rejected request: %s", message)
        raise CanvasError(message, status=response.status_code, payload=payload)

    if not payload.get("access_token"):
        raise CanvasError("Canvas response contained no access_token")
    return payload


def exchange_code(client_id, client_secret, redirect_uri, code):
    """Trade an authorization code for an access/refresh token pair.

    Returns the raw Canvas payload: access_token, refresh_token, expires_in,
    token_type and a `user` block.
    """
    return _token_request(
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "code": code,
        }
    )


def refresh_token(client_id, client_secret, refresh_token_value):
    """Mint a new access token. Canvas does not rotate the refresh token."""
    return _token_request(
        {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token_value,
        }
    )


def revoke(access_token, expire_sessions=False):
    """Ask Canvas to invalidate a token. Best effort; failures are logged."""
    params = {"expire_sessions": "1"} if expire_sessions else {}
    try:
        response = requests.delete(
            f"{base_url()}{TOKEN_PATH}",
            headers={"Authorization": f"Bearer {access_token}"},
            params=params,
            timeout=_timeout(),
        )
    except requests.RequestException as exc:
        logger.warning("Canvas token revocation failed: %s", exc)
        return False
    if response.status_code >= 400:
        logger.warning(
            "Canvas token revocation returned HTTP %s", response.status_code
        )
        return False
    return True


def get_json(path, access_token, params=None):
    """GET a Canvas API path and return decoded JSON."""
    url = f"{base_url()}{path}"
    try:
        response = requests.get(
            url,
            headers={"Authorization": f"Bearer {access_token}"},
            params=params or {},
            timeout=_timeout(),
        )
    except requests.RequestException as exc:
        raise CanvasError(f"Could not reach Canvas: {exc}") from exc

    if response.status_code >= 400:
        raise CanvasError(
            f"Canvas returned HTTP {response.status_code} for {path}",
            status=response.status_code,
        )
    try:
        return response.json()
    except ValueError as exc:
        raise CanvasError(f"Canvas returned non-JSON for {path}") from exc
