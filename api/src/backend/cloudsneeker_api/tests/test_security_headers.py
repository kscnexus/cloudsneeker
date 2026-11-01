"""HSTS on HTTPS stacks (EB-015)."""

from __future__ import annotations

import pytest
from django.urls import reverse

HSTS = "Strict-Transport-Security"
ONE_YEAR = 31_536_000


@pytest.fixture
def hsts_on(settings):
    settings.SECURE_HSTS_SECONDS = ONE_YEAR
    settings.SECURE_HSTS_INCLUDE_SUBDOMAINS = True


@pytest.mark.django_db
class TestHsts:
    def test_sent_on_https_behind_the_load_balancer(self, client, hsts_on):
        # The ALB terminates TLS and forwards X-Forwarded-Proto.
        response = client.get(
            reverse("cloudsneeker-brand"), HTTP_X_FORWARDED_PROTO="https"
        )
        assert response[HSTS] == f"max-age={ONE_YEAR}; includeSubDomains"

    def test_not_sent_over_plain_http(self, client, hsts_on):
        response = client.get(reverse("cloudsneeker-brand"))
        assert HSTS not in response

    def test_off_by_default(self, client, settings):
        assert settings.SECURE_HSTS_SECONDS == 0
        response = client.get(
            reverse("cloudsneeker-brand"), HTTP_X_FORWARDED_PROTO="https"
        )
        assert HSTS not in response

    def test_cookies_stay_secure(self, settings):
        assert settings.CSRF_COOKIE_SECURE is True
        assert settings.SESSION_COOKIE_SECURE is True
