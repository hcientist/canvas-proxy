"""A per-app request ceiling, applied on top of whatever Canvas enforces."""

import time

from django.conf import settings
from django.core.cache import cache


def check_rate_limit(app):
    """Return (allowed, retry_after_seconds) for one request by `app`."""
    limit = settings.RATE_LIMIT_PER_MINUTE
    if limit <= 0:
        return True, 0

    window = int(time.time() // 60)
    key = f"ratelimit:app:{app.pk}:{window}"

    # add() only succeeds on the first request in the window, which is what
    # gives the counter its expiry without a separate call.
    if cache.add(key, 1, timeout=120):
        return True, 0

    try:
        count = cache.incr(key)
    except ValueError:
        # The key expired between add() and incr(); treat this as a fresh window.
        cache.set(key, 1, timeout=120)
        return True, 0

    if count > limit:
        return False, 60 - int(time.time() % 60)
    return True, 0
