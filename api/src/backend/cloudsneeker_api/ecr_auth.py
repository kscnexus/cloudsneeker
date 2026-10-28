"""Amazon ECR registry credentials minted at scan time.

ECR passwords from ``get-login-password`` expire after 12 hours, so a static
password saved on an image provider breaks every scheduled scan after that.
When the provider points at an ECR registry and no static registry
credentials are stored, :func:`apply_ecr_auth` mints a fresh token with
``ecr:GetAuthorizationToken``:

* with ``ecr_role_arn`` on the secret, the worker first assumes that role
  (``ecr_external_id`` is sent as ``ExternalId`` when set);
* without it, the worker's own AWS credentials are used.

``ecr_role_arn`` and ``ecr_external_id`` never reach ``ImageProvider``, which
does not accept them. Error messages carry only the AWS error code, never a
token or password.
"""

from __future__ import annotations

import base64
import re
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from prowler.providers.common.models import Connection

ECR_SECRET_KEYS = ("ecr_role_arn", "ecr_external_id")
STATIC_CREDENTIAL_KEYS = ("registry_username", "registry_password", "registry_token")
ECR_ROLE_SESSION_NAME = "cloudsneeker-ecr-auth"
ECR_ROLE_ARN_REGEX = r"^arn:aws(?:-cn|-us-gov)?:iam::\d{12}:role/[\w+=,.@/-]+$"

ECR_HOST_RE = re.compile(
    r"^(?P<account>\d{12})\.dkr\.ecr(?:-fips)?\.(?P<region>[a-z0-9-]+)"
    r"\.amazonaws\.com(?:\.cn)?$"
)


class EcrAuthError(Exception):
    """Raised when an ECR authorization token cannot be minted."""


def ecr_registry_host(provider_uid: str | None) -> str | None:
    """Return the ECR registry host of an image provider uid.

    Args:
        provider_uid: Registry URL or image reference, with or without scheme,
            for example ``123456789012.dkr.ecr.us-east-1.amazonaws.com/app:1``.

    Returns:
        The lower-cased ECR host, or ``None`` when the uid is not ECR.
    """
    if not provider_uid:
        return None
    value = str(provider_uid).strip()
    for scheme in ("https://", "http://", "oci://"):
        if value.lower().startswith(scheme):
            value = value[len(scheme) :]
            break
    host = value.split("/", 1)[0].split("@", 1)[0].split(":", 1)[0].lower()
    return host if ECR_HOST_RE.match(host) else None


def ecr_host_parts(host: str) -> tuple[str, str]:
    """Return ``(account_id, region)`` for an ECR host.

    Args:
        host: Host accepted by :func:`ecr_registry_host`.

    Returns:
        The registry account ID and region.

    Raises:
        EcrAuthError: When ``host`` is not an ECR host.
    """
    match = ECR_HOST_RE.match(host or "")
    if not match:
        raise EcrAuthError("Registry host is not an Amazon ECR registry.")
    return match.group("account"), match.group("region")


def _error_code(error: Exception) -> str:
    if isinstance(error, ClientError):
        return str(error.response.get("Error", {}).get("Code") or "ClientError")
    if isinstance(error, NoCredentialsError):
        return "NoCredentials"
    return error.__class__.__name__


def mint_ecr_credentials(
    host: str, role_arn: str | None = None, external_id: str | None = None
) -> tuple[str, str]:
    """Mint a 12-hour ECR username and password for ``host``.

    Args:
        host: ECR registry host, ``<account>.dkr.ecr.<region>.amazonaws.com``.
        role_arn: Optional IAM role to assume before calling ECR.
        external_id: Optional ``ExternalId`` for the role assumption.

    Returns:
        ``(username, password)``; the username is ``AWS``.

    Raises:
        EcrAuthError: When the role cannot be assumed or ECR refuses the token.
    """
    account_id, region = ecr_host_parts(host)
    session_kwargs: dict[str, Any] = {"region_name": region}

    if role_arn:
        assume_kwargs: dict[str, Any] = {
            "RoleArn": role_arn,
            "RoleSessionName": ECR_ROLE_SESSION_NAME,
        }
        if external_id:
            assume_kwargs["ExternalId"] = external_id
        try:
            sts = boto3.client("sts", region_name=region)
            credentials = sts.assume_role(**assume_kwargs)["Credentials"]
        except (BotoCoreError, ClientError) as error:
            raise EcrAuthError(
                f"Could not assume the ECR role for {host} ({_error_code(error)}). "
                "Check the role ARN, external ID, and the role's trust policy."
            ) from None
        session_kwargs.update(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )

    try:
        ecr = boto3.client("ecr", **session_kwargs)
        response = ecr.get_authorization_token(registryIds=[account_id])
        token = response["authorizationData"][0]["authorizationToken"]
        username, password = base64.b64decode(token).decode("utf-8").split(":", 1)
    except (BotoCoreError, ClientError) as error:
        raise EcrAuthError(
            f"Could not get an Amazon ECR token for {host} ({_error_code(error)}). "
            "Grant ecr:GetAuthorizationToken to the worker or the ECR role."
        ) from None
    except (KeyError, IndexError, ValueError):
        raise EcrAuthError(
            f"Amazon ECR returned an unreadable authorization token for {host}."
        ) from None
    return username, password


def apply_ecr_auth(provider_uid: str | None, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Return image provider kwargs with ECR credentials minted when needed.

    ``ecr_role_arn`` and ``ecr_external_id`` are always removed. Credentials
    are minted only for an ECR uid with no static ``registry_username``,
    ``registry_password`` or ``registry_token``.

    Args:
        provider_uid: Image provider uid (registry URL or image reference).
        kwargs: Provider secret or ``ImageProvider`` kwargs; not mutated.

    Returns:
        A new kwargs mapping.

    Raises:
        EcrAuthError: When minting is required and fails.
    """
    result = dict(kwargs or {})
    role_arn = str(result.pop("ecr_role_arn", "") or "").strip() or None
    external_id = str(result.pop("ecr_external_id", "") or "").strip() or None

    host = ecr_registry_host(provider_uid)
    if not host or any(result.get(key) for key in STATIC_CREDENTIAL_KEYS):
        return result

    username, password = mint_ecr_credentials(host, role_arn, external_id)
    result["registry_username"] = username
    result["registry_password"] = password
    return result


def ecr_connection_kwargs(
    provider_uid: str | None, kwargs: dict[str, Any]
) -> tuple[Connection | None, dict[str, Any]]:
    """Connection-test variant of :func:`apply_ecr_auth`.

    Args:
        provider_uid: Image provider uid.
        kwargs: Provider secret mapping.

    Returns:
        ``(None, kwargs_with_credentials)`` on success, or
        ``(failed_connection, kwargs)`` when minting fails so the caller can
        report it instead of raising.
    """
    try:
        return None, apply_ecr_auth(provider_uid, kwargs)
    except EcrAuthError as error:
        return Connection(is_connected=False, error=str(error)), dict(kwargs or {})
