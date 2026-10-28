"""IaC provider ``username`` reaches both the scan and the connection test."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from api.models import Provider
from api.utils import get_prowler_provider_kwargs, prowler_provider_connection_test
from api.v1.serializers import IacProviderSecret
from prowler.providers.common.models import Connection

REPO_URL = "https://bitbucket.org/acme/app.git"


def _iac_provider(secret: dict) -> MagicMock:
    provider = MagicMock()
    provider.provider = Provider.ProviderChoices.IAC.value
    provider.uid = REPO_URL
    provider.secret.secret = secret
    return provider


class TestIacUsernameHooks:
    def test_scan_kwargs_carry_username(self):
        kwargs = get_prowler_provider_kwargs(
            _iac_provider({"access_token": "app-pass", "username": "jane"})
        )
        assert kwargs == {
            "scan_repository_url": REPO_URL,
            "oauth_app_token": "app-pass",
            "username": "jane",
        }

    def test_blank_username_is_not_passed(self):
        kwargs = get_prowler_provider_kwargs(
            _iac_provider({"access_token": "tok", "username": ""})
        )
        assert "username" not in kwargs

    def test_connection_test_carries_username(self):
        with patch(
            "prowler.providers.iac.iac_provider.IacProvider.test_connection",
            return_value=Connection(is_connected=True),
        ) as mock_test:
            prowler_provider_connection_test(
                _iac_provider({"access_token": "app-pass", "username": "jane"})
            )
        mock_test.assert_called_once_with(
            scan_repository_url=REPO_URL,
            raise_on_exception=False,
            access_token="app-pass",
            username="jane",
        )

    def test_connection_test_without_username_is_unchanged(self):
        with patch(
            "prowler.providers.iac.iac_provider.IacProvider.test_connection",
            return_value=Connection(is_connected=True),
        ) as mock_test:
            prowler_provider_connection_test(_iac_provider({"access_token": "tok"}))
        mock_test.assert_called_once_with(
            scan_repository_url=REPO_URL,
            raise_on_exception=False,
            access_token="tok",
        )


class TestIacProviderSecretUsername:
    def test_accepts_optional_username(self):
        serializer = IacProviderSecret(
            data={
                "repository_url": REPO_URL,
                "access_token": "app-pass",
                "username": "jane",
            }
        )
        assert serializer.is_valid(), serializer.errors
        assert serializer.validated_data["username"] == "jane"

    def test_username_may_be_blank_or_missing(self):
        assert IacProviderSecret(
            data={"repository_url": REPO_URL, "username": ""}
        ).is_valid()
        assert IacProviderSecret(data={"repository_url": REPO_URL}).is_valid()
