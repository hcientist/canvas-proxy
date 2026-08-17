"""Settings for the Canvas API proxy.

Configuration comes from the environment; see .env.example for the full list.
"""

import os
import sys
from pathlib import Path

import environ
import os

env = environ.Env(
    # set casting, default value
    DEBUG=(bool, False)
)

# Set the project base directory
BASE_DIR = Path(__file__).resolve().parent.parent

# Take environment variables from .env file
environ.Env.read_env(os.path.join(BASE_DIR, '.env'))

# False if not in os.environ because of casting above
DEBUG = env('DEBUG')
TESTING = "test" in sys.argv or bool(os.environ.get("PYTEST_CURRENT_TEST"))


def env(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


def env_bool(name, default=False):
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_list(name, default=()):
    raw = os.environ.get(name)
    if not raw:
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


# --- Core -------------------------------------------------------------------

SECRET_KEY = env("DJANGO_SECRET_KEY", "insecure-dev-key-do-not-use-in-production")
ALLOWED_HOSTS = env_list("DJANGO_ALLOWED_HOSTS", ["localhost", "127.0.0.1"])

# The container healthcheck dials the app on loopback, so loopback always has to
# be accepted or the container can never report healthy. This costs nothing
# here: every absolute URL the app emits is built from PROXY_BASE_URL, never
# from the request's Host header, so ALLOWED_HOSTS is defence in depth rather
# than the thing keeping redirect targets honest.
for _loopback in ("127.0.0.1", "localhost"):
    if _loopback not in ALLOWED_HOSTS:
        ALLOWED_HOSTS.append(_loopback)

# Public origin of this proxy. Every Canvas developer key must list
# {PROXY_BASE_URL}/accounts/canvas/login/callback/ as a redirect URI, which is
# the only one needed -- sign-in and app authorization share that callback.
PROXY_BASE_URL = env("PROXY_BASE_URL", "http://localhost:8000").rstrip("/")

CSRF_TRUSTED_ORIGINS = env_list("CSRF_TRUSTED_ORIGINS", [PROXY_BASE_URL])

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "accounts",
    "registry",
    "oauth",
    "gateway",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # Always loaded, including under DEBUG. Only `runserver` serves static files
    # itself, so making this conditional on DEBUG means a DEBUG=1 deployment
    # under gunicorn returns 404 HTML for every asset -- which the browser
    # reports as a confusing MIME-type error rather than a missing file.
    # WhiteNoise falls through to Django for anything it has not collected, so
    # `runserver` still behaves normally with it in place.
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "registry.context_processors.site",
            ],
        },
    },
]

# --- Database ---------------------------------------------------------------

if env("DATABASE_URL"):
    # postgres://user:pass@host:port/name
    from urllib.parse import urlparse, unquote

    url = urlparse(env("DATABASE_URL"))
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": url.path.lstrip("/"),
            "USER": unquote(url.username or ""),
            "PASSWORD": unquote(url.password or ""),
            "HOST": url.hostname or "",
            "PORT": str(url.port or ""),
            "CONN_MAX_AGE": 60,
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": env("SQLITE_PATH", BASE_DIR / "db.sqlite3"),
        }
    }

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
AUTH_USER_MODEL = "accounts.User"
LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/apps/"
LOGOUT_REDIRECT_URL = "/"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = env("TIME_ZONE", "UTC")
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"

STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        # Hashed filenames, so the admin's CSS can be cached indefinitely.
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"
        if not (DEBUG or TESTING)
        else "django.contrib.staticfiles.storage.StaticFilesStorage"
    },
}

CACHES = {
    "default": {
        "BACKEND": env(
            "CACHE_BACKEND", "django.core.cache.backends.locmem.LocMemCache"
        ),
        "LOCATION": env("CACHE_LOCATION", "canvas-proxy"),
    }
}

# --- Security ---------------------------------------------------------------

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"

if not DEBUG and not TESTING:
    # SECURE_COOKIES and SECURE_SSL_REDIRECT both answer "is there TLS in front
    # of this app?", so set them together. Leaving cookies marked Secure while
    # actually serving plain http means the browser never sends the CSRF cookie
    # back, and every form POST -- sign-in, the consent screen, the whole
    # dashboard -- fails with an opaque 403.
    secure_cookies = env_bool("SECURE_COOKIES", True)
    SESSION_COOKIE_SECURE = secure_cookies
    CSRF_COOKIE_SECURE = secure_cookies
    SECURE_SSL_REDIRECT = env_bool("SECURE_SSL_REDIRECT", True)
    # The healthcheck probes over plain http on loopback; bouncing it to https
    # would make the container's health depend on TLS it never speaks.
    SECURE_REDIRECT_EXEMPT = [r"^healthz$"]
    SECURE_HSTS_SECONDS = int(env("SECURE_HSTS_SECONDS", "31536000"))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = env_bool("SECURE_HSTS_PRELOAD", True)
    if env_bool("BEHIND_TLS_PROXY", True):
        SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# --- Canvas -----------------------------------------------------------------

# Base URL of the Canvas instance this proxy fronts, e.g. https://school.instructure.com
CANVAS_BASE_URL = env("CANVAS_BASE_URL", "https://canvas.instructure.com").rstrip("/")

# Tier slug whose developer key is used to sign users in to this proxy itself.
# Sign-in requests the narrowest scopes and the resulting token is discarded.
CANVAS_LOGIN_TIER = env("CANVAS_LOGIN_TIER", "read_basic")

# Fernet key used to encrypt Canvas tokens at rest.
# Generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
TOKEN_ENCRYPTION_KEY = env("TOKEN_ENCRYPTION_KEY", "")
if TESTING and not TOKEN_ENCRYPTION_KEY:
    # A throwaway key so the suite runs without operator configuration.
    TOKEN_ENCRYPTION_KEY = "sBUxvDvRMWkxOMlErEd2E9M5pUemPZ6iaWuo7yDLZ0w="

# Upstream request behaviour.
CANVAS_TIMEOUT = float(env("CANVAS_TIMEOUT", "30"))
CANVAS_CONNECT_TIMEOUT = float(env("CANVAS_CONNECT_TIMEOUT", "10"))
CANVAS_MAX_BODY_BYTES = int(env("CANVAS_MAX_BODY_BYTES", str(25 * 1024 * 1024)))

# --- Proxy-issued token lifetimes (seconds) ---------------------------------

AUTHORIZATION_REQUEST_TTL = int(env("AUTHORIZATION_REQUEST_TTL", "600"))
AUTHORIZATION_CODE_TTL = int(env("AUTHORIZATION_CODE_TTL", "60"))
ACCESS_TOKEN_TTL = int(env("ACCESS_TOKEN_TTL", "3600"))
REFRESH_TOKEN_TTL = int(env("REFRESH_TOKEN_TTL", str(90 * 24 * 3600)))

# Per-app request ceiling applied on top of whatever Canvas enforces.
RATE_LIMIT_PER_MINUTE = int(env("RATE_LIMIT_PER_MINUTE", "600"))

# Retain proxied-request audit rows for this many days (see prune_logs command).
REQUEST_LOG_RETENTION_DAYS = int(env("REQUEST_LOG_RETENTION_DAYS", "90"))

# --- Logging ----------------------------------------------------------------

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"},
    },
    "handlers": {
        "console": {"class": "logging.StreamHandler", "formatter": "standard"},
    },
    "root": {"handlers": ["console"], "level": env("LOG_LEVEL", "INFO")},
    "loggers": {
        "django.request": {"handlers": ["console"], "level": "WARNING", "propagate": False},
    },
}
