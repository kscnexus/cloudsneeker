"""``CACHES`` for ``config/django/base.py`` (``cloudsneeker-hook``).

``default`` stays Django's per-process memory cache, which upstream code
already assumes. ``cloudsneeker-shared`` is a Valkey database every API
worker sees, for state that must not be split per worker (the sign-in
lockout). Short socket timeouts keep a Valkey outage from stalling a request;
callers fail open.

Imported while settings load, so it must not touch Django models or apps.
"""

from __future__ import annotations

from urllib.parse import quote

from config.env import env
from config.settings.celery import (
    VALKEY_HOST,
    VALKEY_PASSWORD,
    VALKEY_PORT,
    VALKEY_SCHEME,
    VALKEY_USERNAME,
)

SHARED_CACHE_ALIAS = "cloudsneeker-shared"


def shared_cache_url(db: int) -> str:
    auth = ""
    if VALKEY_USERNAME or VALKEY_PASSWORD:
        user = quote(VALKEY_USERNAME, safe="")
        password = quote(VALKEY_PASSWORD, safe="")
        auth = f"{user}:{password}@" if password else f"{user}@"
    return f"{VALKEY_SCHEME}://{auth}{VALKEY_HOST}:{VALKEY_PORT}/{db}"


def shared_cache_settings() -> dict:
    return {
        "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
        SHARED_CACHE_ALIAS: {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": shared_cache_url(
                env.int("CLOUDSNEEKER_CACHE_VALKEY_DB", default=3)
            ),
            "KEY_PREFIX": "cloudsneeker",
            "OPTIONS": {"socket_connect_timeout": 0.5, "socket_timeout": 0.5},
        },
    }
