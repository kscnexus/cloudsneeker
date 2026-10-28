"""Amazon ECR credentials minted at scan and connection-test time."""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest
from api.models import Provider
from api.utils import get_prowler_provider_kwargs, prowler_provider_connection_test
from api.v1.serializers import ImageProviderSecret
from botocore.exceptions import ClientError, NoCredentialsError
from cloudsneeker_api.ecr_auth import (
    EcrAuthError,
    apply_ecr_auth,
    ecr_connection_kwargs,
    ecr_host_parts,
    ecr_registry_host,
    mint_ecr_credentials,
)
from prowler.providers.common.models import Connection

ECR_HOST = "123456789012.dkr.ecr.eu-west-1.amazonaws.com"
ECR_PASSWORD = "minted-ecr-password"
ROLE_ARN = "arn:aws:iam::123456789012:role/EcrPull"


def _ecr_client(password: str = ECR_PASSWORD) -> MagicMock:
    client = MagicMock()
    token = base64.b64encode(f"AWS:{password}".encode()).decode()
    client.get_authorization_token.return_value = {
        "authorizationData": [{"authorizationToken": token}]
    }
    return client


def _sts_client() -> MagicMock:
    client = MagicMock()
    client.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIAEXAMPLE",
            "SecretAccessKey": "assumed-secret",
            "SessionToken": "assumed-session",
        }
    }
    return client


def _patch_boto(ecr: MagicMock, sts: MagicMock | None = None):
    clients = {"ecr": ecr, "sts": sts or _sts_client()}
    return patch(
        "cloudsneeker_api.ecr_auth.boto3.client",
        side_effect=lambda service, **_kwargs: clients[service],
    )


def _client_error(code: str) -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "nope"}}, "Op")


class TestEcrRegistryHost:
    @pytest.mark.parametrize(
        "uid",
        [
            ECR_HOST,
            f"https://{ECR_HOST}",
            f"{ECR_HOST}/team/app:1.0",
            f"{ECR_HOST}/app@sha256:abc",
            "123456789012.dkr.ecr.cn-north-1.amazonaws.com.cn/app",
            "123456789012.dkr.ecr-fips.us-east-1.amazonaws.com",
        ],
    )
    def test_detects_ecr(self, uid: str):
        assert ecr_registry_host(uid)

    @pytest.mark.parametrize(
        "uid",
        ["docker.io/acme", "ghcr.io/acme/app:1", "alpine:3.18", "", None],
    )
    def test_ignores_other_registries(self, uid):
        assert ecr_registry_host(uid) is None

    def test_host_parts(self):
        assert ecr_host_parts(ECR_HOST) == ("123456789012", "eu-west-1")
        with pytest.raises(EcrAuthError):
            ecr_host_parts("docker.io")


class TestMintEcrCredentials:
    def test_uses_ambient_credentials(self):
        ecr = _ecr_client()
        with _patch_boto(ecr) as mock_client:
            assert mint_ecr_credentials(ECR_HOST) == ("AWS", ECR_PASSWORD)
        mock_client.assert_called_once_with("ecr", region_name="eu-west-1")
        ecr.get_authorization_token.assert_called_once_with(
            registryIds=["123456789012"]
        )

    def test_assumes_role_with_external_id(self):
        ecr = _ecr_client()
        sts = _sts_client()
        with _patch_boto(ecr, sts) as mock_client:
            mint_ecr_credentials(ECR_HOST, ROLE_ARN, "ext-1")
        sts.assume_role.assert_called_once()
        assume_kwargs = sts.assume_role.call_args.kwargs
        assert assume_kwargs["RoleArn"] == ROLE_ARN
        assert assume_kwargs["ExternalId"] == "ext-1"
        mock_client.assert_any_call(
            "ecr",
            region_name="eu-west-1",
            aws_access_key_id="AKIAEXAMPLE",
            aws_secret_access_key="assumed-secret",
            aws_session_token="assumed-session",
        )

    def test_assume_role_without_external_id(self):
        sts = _sts_client()
        with _patch_boto(_ecr_client(), sts):
            mint_ecr_credentials(ECR_HOST, ROLE_ARN)
        assert "ExternalId" not in sts.assume_role.call_args.kwargs

    def test_assume_role_failure_is_clear(self):
        sts = _sts_client()
        sts.assume_role.side_effect = _client_error("AccessDenied")
        with _patch_boto(_ecr_client(), sts):
            with pytest.raises(EcrAuthError, match="AccessDenied") as exc_info:
                mint_ecr_credentials(ECR_HOST, ROLE_ARN, "ext-secret")
        assert "ext-secret" not in str(exc_info.value)

    def test_ecr_failure_is_clear(self):
        ecr = _ecr_client()
        ecr.get_authorization_token.side_effect = NoCredentialsError()
        with _patch_boto(ecr):
            with pytest.raises(EcrAuthError, match="NoCredentials"):
                mint_ecr_credentials(ECR_HOST)

    def test_unreadable_token(self):
        ecr = MagicMock()
        ecr.get_authorization_token.return_value = {"authorizationData": []}
        with _patch_boto(ecr):
            with pytest.raises(EcrAuthError, match="unreadable"):
                mint_ecr_credentials(ECR_HOST)


class TestApplyEcrAuth:
    def test_mints_for_ecr_without_static_credentials(self):
        secret = {"ecr_role_arn": ROLE_ARN, "ecr_external_id": "x", "image_filter": "a"}
        with _patch_boto(_ecr_client()):
            result = apply_ecr_auth(ECR_HOST, secret)
        assert result == {
            "image_filter": "a",
            "registry_username": "AWS",
            "registry_password": ECR_PASSWORD,
        }
        assert "ecr_role_arn" in secret  # input not mutated

    @pytest.mark.parametrize(
        "static",
        [
            {"registry_username": "u", "registry_password": "p"},
            {"registry_token": "t"},
        ],
    )
    def test_static_credentials_win(self, static):
        with patch("cloudsneeker_api.ecr_auth.boto3.client") as mock_client:
            result = apply_ecr_auth(ECR_HOST, {**static, "ecr_role_arn": ROLE_ARN})
        mock_client.assert_not_called()
        assert result == static

    def test_non_ecr_only_strips_ecr_keys(self):
        with patch("cloudsneeker_api.ecr_auth.boto3.client") as mock_client:
            result = apply_ecr_auth(
                "docker.io/acme", {"ecr_role_arn": "", "ecr_external_id": ""}
            )
        mock_client.assert_not_called()
        assert result == {}

    def test_connection_kwargs_reports_failure(self):
        ecr = _ecr_client()
        ecr.get_authorization_token.side_effect = _client_error("AccessDenied")
        with _patch_boto(ecr):
            failure, kwargs = ecr_connection_kwargs(ECR_HOST, {})
        assert isinstance(failure, Connection)
        assert not failure.is_connected
        assert "AccessDenied" in failure.error
        assert kwargs == {}

    def test_connection_kwargs_success(self):
        with _patch_boto(_ecr_client()):
            failure, kwargs = ecr_connection_kwargs(ECR_HOST, {})
        assert failure is None
        assert kwargs["registry_password"] == ECR_PASSWORD


def _image_provider(uid: str, secret: dict) -> MagicMock:
    provider = MagicMock()
    provider.provider = Provider.ProviderChoices.IMAGE.value
    provider.uid = uid
    provider.secret.secret = secret
    return provider


class TestUpstreamHooks:
    def test_scan_kwargs_get_minted_credentials(self):
        provider = _image_provider(
            ECR_HOST, {"ecr_role_arn": ROLE_ARN, "registry_insecure": True}
        )
        with _patch_boto(_ecr_client()):
            kwargs = get_prowler_provider_kwargs(provider)
        assert kwargs == {
            "registry": ECR_HOST,
            "registry_insecure": True,
            "registry_username": "AWS",
            "registry_password": ECR_PASSWORD,
        }

    def test_scan_kwargs_raise_clear_error(self):
        ecr = _ecr_client()
        ecr.get_authorization_token.side_effect = _client_error("AccessDenied")
        with _patch_boto(ecr):
            with pytest.raises(EcrAuthError):
                get_prowler_provider_kwargs(_image_provider(ECR_HOST, {}))

    def test_non_ecr_scan_kwargs_unchanged(self):
        provider = _image_provider(
            "docker.io/acme/app:1", {"registry_token": "t", "registry_insecure": False}
        )
        kwargs = get_prowler_provider_kwargs(provider)
        assert kwargs == {"images": ["docker.io/acme/app:1"], "registry_token": "t"}

    def test_connection_test_gets_minted_credentials(self):
        provider = _image_provider(ECR_HOST, {})
        with (
            _patch_boto(_ecr_client()),
            patch(
                "prowler.providers.image.image_provider.ImageProvider.test_connection",
                return_value=Connection(is_connected=True),
            ) as mock_test,
        ):
            result = prowler_provider_connection_test(provider)
        assert result.is_connected
        mock_test.assert_called_once_with(
            image=ECR_HOST,
            raise_on_exception=False,
            registry_username="AWS",
            registry_password=ECR_PASSWORD,
        )

    def test_connection_test_reports_mint_failure(self):
        ecr = _ecr_client()
        ecr.get_authorization_token.side_effect = _client_error("AccessDenied")
        with (
            _patch_boto(ecr),
            patch(
                "prowler.providers.image.image_provider.ImageProvider.test_connection"
            ) as mock_test,
        ):
            result = prowler_provider_connection_test(_image_provider(ECR_HOST, {}))
        assert not result.is_connected
        assert "AccessDenied" in result.error
        mock_test.assert_not_called()


class TestImageProviderSecretFields:
    def test_accepts_ecr_fields(self):
        serializer = ImageProviderSecret(
            data={
                "ecr_role_arn": ROLE_ARN,
                "ecr_external_id": "ext",
                "registry_insecure": True,
            }
        )
        assert serializer.is_valid(), serializer.errors
        assert serializer.validated_data["ecr_role_arn"] == ROLE_ARN
        assert serializer.validated_data["registry_insecure"] is True

    def test_registry_insecure_defaults_false(self):
        serializer = ImageProviderSecret(data={})
        assert serializer.is_valid(), serializer.errors
        assert serializer.validated_data["registry_insecure"] is False

    def test_rejects_malformed_role_arn(self):
        serializer = ImageProviderSecret(data={"ecr_role_arn": "not-an-arn"})
        assert not serializer.is_valid()
        assert "ecr_role_arn" in serializer.errors
