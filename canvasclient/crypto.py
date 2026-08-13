"""Encryption for Canvas credentials held at rest.

Canvas access/refresh tokens have to be decryptable to be usable, so they are
encrypted with Fernet rather than hashed. Tokens the *proxy* issues are never
stored in a recoverable form -- see `token_digest`.
"""

import base64
import hashlib
import hmac
import secrets

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

_fernet_cache = {}


def _fernet():
    key = (settings.TOKEN_ENCRYPTION_KEY or "").strip()
    if not key:
        if not settings.DEBUG:
            raise ImproperlyConfigured(
                "TOKEN_ENCRYPTION_KEY must be set. Generate one with:\n"
                '  python -c "from cryptography.fernet import Fernet; '
                'print(Fernet.generate_key().decode())"'
            )
        # Development fallback: derive a stable key from SECRET_KEY so a dev
        # database keeps working across restarts.
        digest = hashlib.sha256(settings.SECRET_KEY.encode()).digest()
        key = base64.urlsafe_b64encode(digest).decode()

    if key not in _fernet_cache:
        try:
            _fernet_cache[key] = Fernet(key.encode())
        except (ValueError, TypeError) as exc:
            raise ImproperlyConfigured(
                "TOKEN_ENCRYPTION_KEY is not a valid Fernet key"
            ) from exc
    return _fernet_cache[key]


def encrypt(plaintext):
    """Encrypt a string for storage. Empty values round-trip as empty."""
    if not plaintext:
        return ""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext):
    """Decrypt a stored string, returning "" if it cannot be read.

    A failure here means the encryption key was rotated or the row was
    tampered with; callers treat that the same as "no token".
    """
    if not ciphertext:
        return ""
    try:
        return _fernet().decrypt(ciphertext.encode()).decode()
    except InvalidToken:
        return ""


def generate_token(nbytes=32):
    """A URL-safe random secret for proxy-issued tokens and client secrets."""
    return secrets.token_urlsafe(nbytes)


def token_digest(token):
    """Stable lookup digest for a proxy-issued token.

    Keyed with SECRET_KEY so a leaked database alone does not let an attacker
    confirm guesses offline, and constant-length so lookups stay indexable.
    """
    return hmac.new(
        settings.SECRET_KEY.encode(), token.encode(), hashlib.sha256
    ).hexdigest()


def constant_time_equals(a, b):
    return hmac.compare_digest(str(a), str(b))
