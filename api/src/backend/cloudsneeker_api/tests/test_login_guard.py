"""Per-account sign-in lockout on ``POST /api/v1/tokens``."""

from __future__ import annotations

from unittest.mock import patch

import pytest
from cloudsneeker_api import login_guard
from cloudsneeker_api.cache_settings import shared_cache_settings
from conftest import TEST_PASSWORD, TEST_USER
from django.core.cache import caches
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

MAX_FAILURES = 3


@pytest.fixture(autouse=True)
def _guard(monkeypatch):
    monkeypatch.setenv("CLOUDSNEEKER_LOGIN_MAX_FAILURES", str(MAX_FAILURES))
    monkeypatch.setenv("CLOUDSNEEKER_LOGIN_LOCKOUT_SECONDS", "600")
    caches[login_guard.CACHE_ALIAS].clear()
    with override_settings(CLOUDSNEEKER_LOGIN_GUARD_ENABLED=True):
        yield
    caches[login_guard.CACHE_ALIAS].clear()


def _sign_in(email=TEST_USER, password=TEST_PASSWORD):
    return APIClient().post(
        reverse("token-obtain"),
        data={
            "data": {
                "type": "tokens",
                "attributes": {"email": email, "password": password},
            }
        },
        format="vnd.api+json",
    )


def _fail(times: int, email=TEST_USER):
    for _ in range(times):
        assert _sign_in(email=email, password="wrong-password").status_code == 401


@pytest.mark.django_db
class TestLoginGuard:
    def test_locks_account_after_max_failures(self, create_test_user):
        _fail(MAX_FAILURES)

        response = _sign_in()

        assert response.status_code == status.HTTP_429_TOO_MANY_REQUESTS
        assert response.json()["errors"][0]["code"] == login_guard.CODE_LOCKED
        assert response["Retry-After"] == "600"
        assert "access" not in response.content.decode()

    def test_wrong_passwords_below_limit_still_sign_in(self, create_test_user):
        _fail(MAX_FAILURES - 1)

        assert _sign_in().status_code == status.HTTP_200_OK

    def test_success_clears_failures(self, create_test_user):
        _fail(MAX_FAILURES - 1)
        assert _sign_in().status_code == status.HTTP_200_OK

        _fail(MAX_FAILURES - 1)

        assert _sign_in().status_code == status.HTTP_200_OK

    def test_email_is_case_insensitive(self, create_test_user):
        _fail(MAX_FAILURES, email=TEST_USER.upper())

        assert _sign_in().status_code == status.HTTP_429_TOO_MANY_REQUESTS

    def test_lock_is_per_account(self, create_test_user):
        _fail(MAX_FAILURES, email="someone-else@example.com")

        assert _sign_in().status_code == status.HTTP_200_OK

    def test_unknown_accounts_lock_too(self, create_test_user):
        email = "nobody@example.com"
        _fail(MAX_FAILURES, email=email)

        assert _sign_in(email=email).status_code == 429

    def test_disabled_guard_never_locks(self, create_test_user):
        with override_settings(CLOUDSNEEKER_LOGIN_GUARD_ENABLED=False):
            _fail(MAX_FAILURES + 1)
            assert _sign_in().status_code == status.HTTP_200_OK

    def test_cache_outage_fails_open(self, create_test_user):
        with patch.object(login_guard, "failures", side_effect=ConnectionError):
            assert _sign_in().status_code == status.HTTP_200_OK

    def test_other_endpoints_untouched(self, authenticated_client):
        assert authenticated_client.get(reverse("user-me")).status_code == 200


def test_shared_cache_points_at_valkey():
    caches_config = shared_cache_settings()

    assert caches_config["default"]["BACKEND"].endswith("LocMemCache")
    shared = caches_config["cloudsneeker-shared"]
    assert shared["BACKEND"].endswith("RedisCache")
    assert shared["LOCATION"].endswith("/3")
    assert shared["OPTIONS"]["socket_timeout"] <= 1


def test_wrong_mfa_code_counts_for_the_account():
    """MfaMiddleware swaps in its own 401, so the email comes off the request."""
    from django.http import JsonResponse
    from django.test import RequestFactory

    request = RequestFactory().post("/api/v1/tokens")
    request.cloudsneeker_sign_in_email = "mfa-user@example.com"

    login_guard.guard_token_response(request, JsonResponse({}, status=401))

    assert login_guard.failures("MFA-user@example.com") == 1
