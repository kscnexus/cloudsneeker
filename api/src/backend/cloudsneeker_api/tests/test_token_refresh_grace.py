"""Grace window for refresh-token rotation (``token_refresh_grace``)."""

from __future__ import annotations

import json
import threading
import time

import pytest
from cloudsneeker_api import token_refresh_grace as grace
from django.core.cache import caches
from django.http import HttpResponse
from django.test import RequestFactory, override_settings

LOCAL_CACHES = {
    "default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"},
    grace.CACHE_ALIAS: {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "refresh-grace-tests",
    },
}
REFRESH_URL = "/api/v1/tokens/refresh"


@pytest.fixture(autouse=True)
def _local_cache(monkeypatch):
    monkeypatch.setenv("CLOUDSNEEKER_REFRESH_GRACE_SECONDS", "60")
    with override_settings(CACHES=LOCAL_CACHES):
        caches[grace.CACHE_ALIAS].clear()
        yield
        caches[grace.CACHE_ALIAS].clear()


def _request(token="refresh-1", path=REFRESH_URL, method="post"):
    body = json.dumps(
        {"data": {"type": "tokens-refresh", "attributes": {"refresh": token}}}
    )
    return getattr(RequestFactory(), method)(
        path, data=body, content_type="application/vnd.api+json"
    )


class _Upstream:
    """Stands in for the upstream refresh view: rotates once, then refuses."""

    def __init__(self, delay=0.0):
        self.calls = 0
        self.delay = delay
        self.lock = threading.Lock()

    def __call__(self, request):
        with self.lock:
            self.calls += 1
            first = self.calls == 1
        time.sleep(self.delay)
        if first:
            return HttpResponse(
                json.dumps({"data": {"attributes": {"access": "a2", "refresh": "r2"}}}),
                status=200,
                content_type="application/vnd.api+json",
            )
        return HttpResponse(
            b'{"errors":[{"detail":"Token is blacklisted"}]}', status=401
        )


class TestRefreshTokenOf:
    def test_reads_json_api_and_plain_json(self):
        assert grace.refresh_token_of(b'{"refresh":" r1 "}') == "r1"
        assert (
            grace.refresh_token_of(b'{"data":{"attributes":{"refresh":"r1"}}}') == "r1"
        )

    @pytest.mark.parametrize("body", [b"", b"not json", b"[]", b'{"refresh": 3}'])
    def test_ignores_other_bodies(self, body):
        assert grace.refresh_token_of(body) == ""


class TestRefreshGraceMiddleware:
    def test_second_refresh_with_the_same_token_gets_the_same_tokens(self):
        upstream = _Upstream()
        middleware = grace.RefreshGraceMiddleware(upstream)

        first = middleware(_request())
        second = middleware(_request())

        assert first.status_code == 200
        assert second.status_code == 200
        assert second.content == first.content
        assert second["X-Cloudsneeker-Refresh-Grace"] == "replayed"
        assert upstream.calls == 1

    def test_concurrent_refreshes_wait_for_the_first(self):
        upstream = _Upstream(delay=0.3)
        middleware = grace.RefreshGraceMiddleware(upstream)
        results = []

        def call():
            results.append(middleware(_request()))

        threads = [threading.Thread(target=call) for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert [response.status_code for response in results] == [200, 200, 200]
        assert upstream.calls == 1

    def test_failed_refresh_is_not_cached(self):
        def refuse(request):
            return HttpResponse(b"{}", status=401)

        middleware = grace.RefreshGraceMiddleware(refuse)
        assert middleware(_request()).status_code == 401
        assert caches[grace.CACHE_ALIAS].get(grace.result_key("refresh-1")) is None
        assert caches[grace.CACHE_ALIAS].get(grace.lock_key("refresh-1")) is None

    def test_other_tokens_and_paths_are_not_affected(self):
        upstream = _Upstream()
        middleware = grace.RefreshGraceMiddleware(upstream)
        middleware(_request("refresh-1"))
        assert middleware(_request("refresh-2")).status_code == 401
        assert middleware(_request(path="/api/v1/tokens")).status_code == 401
        assert upstream.calls == 3

    def test_window_is_off_unless_configured(self, monkeypatch):
        # Upstream expects a rotated refresh token to fail at once.
        monkeypatch.delenv("CLOUDSNEEKER_REFRESH_GRACE_SECONDS", raising=False)
        assert grace.grace_seconds() == 0
        upstream = _Upstream()
        middleware = grace.RefreshGraceMiddleware(upstream)
        middleware(_request())
        assert middleware(_request()).status_code == 401

    def test_window_off(self, monkeypatch):
        monkeypatch.setenv("CLOUDSNEEKER_REFRESH_GRACE_SECONDS", "0")
        upstream = _Upstream()
        middleware = grace.RefreshGraceMiddleware(upstream)
        middleware(_request())
        assert middleware(_request()).status_code == 401

    def test_cache_outage_falls_back_to_upstream(self, monkeypatch):
        def broken():
            raise ConnectionError("valkey down")

        monkeypatch.setattr(grace, "_cache", broken)
        upstream = _Upstream()
        middleware = grace.RefreshGraceMiddleware(upstream)
        assert middleware(_request()).status_code == 200
        assert middleware(_request()).status_code == 401


@pytest.mark.django_db
class TestRefreshGraceEndToEnd:
    def test_same_refresh_token_twice_keeps_the_session(self, tenants_fixture):
        from conftest import TEST_PASSWORD, TEST_USER
        from django.urls import reverse
        from rest_framework.test import APIClient

        client = APIClient()
        signed_in = client.post(
            reverse("token-obtain"),
            data={
                "data": {
                    "type": "tokens",
                    "attributes": {"email": TEST_USER, "password": TEST_PASSWORD},
                }
            },
            format="vnd.api+json",
        )
        assert signed_in.status_code == 200, signed_in.content
        refresh = signed_in.json()["data"]["attributes"]["refresh"]
        body = {"data": {"type": "tokens-refresh", "attributes": {"refresh": refresh}}}

        first = client.post(reverse("token-refresh"), data=body, format="vnd.api+json")
        second = client.post(reverse("token-refresh"), data=body, format="vnd.api+json")

        assert first.status_code == 200, first.content
        assert second.status_code == 200, second.content
        assert second.json() == first.json()
        rotated = first.json()["data"]["attributes"]["refresh"]
        assert rotated != refresh
