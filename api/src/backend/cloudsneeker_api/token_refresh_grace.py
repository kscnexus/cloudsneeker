"""Grace window for refresh-token rotation on ``POST /api/v1/tokens/refresh``.

Upstream rotates refresh tokens and blacklists the old one at once
(``ROTATE_REFRESH_TOKENS`` and ``BLACKLIST_AFTER_ROTATION``). The web app
runs on several serverless instances, and a page load sends several requests
in parallel; when the access token expires, two of them can refresh with the
same refresh token. The first rotates it, the second gets 401 "Token is
blacklisted", and the web app stores that failure: the user is signed out
mid-session. The API log showed 68 failed refreshes beside 2 good ones.

This middleware makes a refresh idempotent for a short window:

* the first request for a refresh token takes a lock and runs the upstream
  view; a 200 response is kept for ``CLOUDSNEEKER_REFRESH_GRACE_SECONDS``
  (60 by default, 0 turns the window off) under a SHA-256 of the token;
* a request with the same token inside the window gets that same response
  (the same new access and refresh token), not a failure;
* a request that arrives while the first is still running waits for its
  result (up to ``WAIT_SECONDS``) instead of racing it.

After the window the old token is refused as before, so replay protection
stays. Results live in the ``cloudsneeker-shared`` cache (Valkey) so every API
worker sees them; when the cache is down the middleware steps aside and the
upstream behaviour applies. Registered in ``config/django/base.py``
(``cloudsneeker-hook``).
"""

from __future__ import annotations

import hashlib
import json
import logging
import time

from cloudsneeker_api.subscriptions import api_path
from config.env import env
from django.http import HttpResponse

logger = logging.getLogger(__name__)

REFRESH_PATH = "tokens/refresh"
CACHE_ALIAS = "cloudsneeker-shared"
KEY_PREFIX = "refresh-grace"
LOCK_SECONDS = 10
WAIT_SECONDS = 5.0
POLL_SECONDS = 0.1


def grace_seconds() -> int:
    return max(0, env.int("CLOUDSNEEKER_REFRESH_GRACE_SECONDS", default=60))


def _cache():
    from django.core.cache import caches

    return caches[CACHE_ALIAS]


def refresh_token_of(body: bytes) -> str:
    """The refresh token of a JSON or JSON:API refresh request, or ""."""
    try:
        data = json.loads(body or b"{}")
    except (ValueError, UnicodeDecodeError):
        return ""
    if not isinstance(data, dict):
        return ""
    resource = data.get("data")
    if isinstance(resource, dict) and isinstance(resource.get("attributes"), dict):
        data = resource["attributes"]
    token = data.get("refresh")
    return token.strip() if isinstance(token, str) else ""


def result_key(token: str) -> str:
    return f"{KEY_PREFIX}:result:{hashlib.sha256(token.encode()).hexdigest()}"


def lock_key(token: str) -> str:
    return f"{KEY_PREFIX}:lock:{hashlib.sha256(token.encode()).hexdigest()}"


def _replay(cached: dict) -> HttpResponse:
    response = HttpResponse(
        cached["content"].encode(),
        status=200,
        content_type=cached["content_type"],
    )
    response["X-Cloudsneeker-Refresh-Grace"] = "replayed"
    return response


def _wait_for_result(cache, key: str) -> dict | None:
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        cached = cache.get(key)
        if cached:
            return cached
        time.sleep(POLL_SECONDS)
    return None


class RefreshGraceMiddleware:
    """Idempotent refresh for a short window; see the module docstring."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.method != "POST" or api_path(request) != REFRESH_PATH:
            return self.get_response(request)
        window = grace_seconds()
        if not window:
            return self.get_response(request)
        # Reading ``request.body`` keeps a copy for the view (Django re-wraps
        # the stream), so the upstream serializer still sees the payload.
        token = refresh_token_of(request.body)
        if not token:
            return self.get_response(request)

        key = result_key(token)
        try:
            cache = _cache()
            cached = cache.get(key)
            if cached:
                return _replay(cached)
            owner = cache.add(lock_key(token), 1, timeout=LOCK_SECONDS)
            if not owner:
                cached = _wait_for_result(cache, key)
                if cached:
                    return _replay(cached)
        except Exception:  # noqa: BLE001 - never block a refresh on the cache
            logger.exception("Refresh grace cache unavailable; using upstream refresh")
            return self.get_response(request)

        response = self.get_response(request)
        if owner:
            try:
                if response.status_code == 200:
                    content = response.content
                    cache.set(
                        key,
                        {
                            "content": content.decode(),
                            "content_type": response.get(
                                "Content-Type", "application/vnd.api+json"
                            ),
                        },
                        timeout=window,
                    )
                cache.delete(lock_key(token))
            except Exception:  # noqa: BLE001
                logger.exception("Refresh grace result not stored")
        return response
