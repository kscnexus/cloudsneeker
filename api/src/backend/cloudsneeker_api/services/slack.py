"""Slack OAuth, channel listing, connection checks, and alert posts."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlencode
from uuid import uuid4

import requests
from api.db_utils import rls_transaction
from api.models import Integration
from django.conf import settings
from django.core.cache import cache
from prowler.providers.common.models import Connection
from rest_framework.exceptions import ValidationError

logger = logging.getLogger(__name__)

SLACK_API = "https://slack.com/api"
SLACK_AUTHORIZE = "https://slack.com/oauth/v2/authorize"
SLACK_OAUTH_SCOPES = "channels:read,groups:read,chat:write,channels:join"
OAUTH_STATE_TTL_SECONDS = 600
OAUTH_STATE_PREFIX = "cloudsneeker:slack:oauth:"
CONFIRMATION_MESSAGE = (
    "✅ Cloudsneeker connection verified. Notifications will be delivered to this channel."
)


@dataclass
class SlackConnectionResult(Connection):
    """Connection check result that may name a failing channel."""

    failed_channel_id: str | None = None


def _usable_credential(value: str | None) -> str:
    text = (value or "").strip()
    if not text or text in {"unconfigured", "none"}:
        return ""
    return text


def get_slack_app_credentials(tenant_id: str | None = None) -> tuple[str, str] | None:
    """Return Slack app Client ID/Secret for OAuth.

    Prefers the tenant's in-app configuration; falls back to deploy env when set.
    """
    if tenant_id:
        from cloudsneeker_api.models import SlackAppConfig

        with rls_transaction(tenant_id):
            config = (
                SlackAppConfig.objects.filter(tenant_id=tenant_id, enabled=True)
                .order_by("-updated_at")
                .first()
            )
        if config:
            client_id = _usable_credential(config.client_id)
            client_secret = _usable_credential(config.client_secret)
            if client_id and client_secret:
                return client_id, client_secret

    client_id = _usable_credential(settings.SLACK_CLIENT_ID)
    client_secret = _usable_credential(settings.SLACK_CLIENT_SECRET)
    if client_id and client_secret:
        return client_id, client_secret
    return None


def slack_app_configured(tenant_id: str | None = None) -> bool:
    """True when Slack app client id and secret are present for this tenant."""
    return get_slack_app_credentials(tenant_id) is not None


def slack_redirect_uri() -> str:
    """OAuth redirect URI served by the UI callback route."""
    base = settings.UI_BASE_URL.rstrip("/")
    return f"{base}/integrations/slack/callback"


def _error_detail(response: requests.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        return response.text[:200] or response.reason
    return (
        payload.get("error")
        or payload.get("detail")
        or response.reason
        or "slack_error"
    )


def _slack_api(
    method: str,
    *,
    token: str | None = None,
    params: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    headers = {"Content-Type": "application/json; charset=utf-8"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.post(
        f"{SLACK_API}/{method}",
        headers=headers,
        params=params,
        data=data,
        json=json_body,
        timeout=30,
    )
    if response.status_code == 429:
        retry_after = response.headers.get("Retry-After")
        raise ValidationError(
            {
                "detail": "Slack rate limited this request.",
                "code": "rate_limited",
                "retry_after": retry_after,
            }
        )
    if response.status_code >= 500:
        raise ValidationError(
            {"detail": "Slack upstream error.", "code": "slack_upstream"}
        )
    payload = response.json()
    if not payload.get("ok"):
        raise ValidationError(
            {
                "detail": payload.get("error") or "Slack request failed.",
                "code": payload.get("error") or "slack_error",
            }
        )
    return payload


def mint_oauth_state(tenant_id: str, user_id: str) -> str:
    """Store a short-lived OAuth state and return the opaque token."""
    state = secrets.token_urlsafe(32)
    cache.set(
        f"{OAUTH_STATE_PREFIX}{state}",
        {"tenant_id": str(tenant_id), "user_id": str(user_id)},
        timeout=OAUTH_STATE_TTL_SECONDS,
    )
    return state


def consume_oauth_state(state: str, tenant_id: str) -> dict[str, str]:
    """Validate and consume a one-time OAuth state for the tenant."""
    key = f"{OAUTH_STATE_PREFIX}{state}"
    payload = cache.get(key)
    cache.delete(key)
    if not payload or str(payload.get("tenant_id")) != str(tenant_id):
        raise ValidationError(
            {"detail": "Invalid or expired OAuth state.", "code": "invalid_oauth_state"}
        )
    return payload


def build_authorize_url(tenant_id: str, user_id: str) -> str:
    """Return Slack's consent URL for this tenant."""
    credentials = get_slack_app_credentials(tenant_id)
    if credentials is None:
        raise ValidationError(
            {"detail": "Slack is not configured for this tenant."}
        )
    client_id, _client_secret = credentials
    state = mint_oauth_state(tenant_id, user_id)
    query = urlencode(
        {
            "client_id": client_id,
            "scope": SLACK_OAUTH_SCOPES,
            "redirect_uri": slack_redirect_uri(),
            "state": state,
        }
    )
    return f"{SLACK_AUTHORIZE}?{query}"


def empty_verification() -> dict[str, Any]:
    return {"task_id": None, "started_at": None, "finished_at": None}


def public_configuration(configuration: dict[str, Any]) -> dict[str, Any]:
    """Shape stored configuration for JSON:API responses."""
    verification = configuration.get("verification") or empty_verification()
    channels = configuration.get("channels") or []
    return {
        "team_id": configuration.get("team_id"),
        "team_name": configuration.get("team_name"),
        "bot_user_id": configuration.get("bot_user_id"),
        "channels": [
            {
                "id": channel.get("id"),
                "name": channel.get("name"),
                "is_private": bool(channel.get("is_private")),
                "confirmation_sent_at": channel.get("confirmation_sent_at"),
            }
            for channel in channels
            if channel.get("id")
        ],
        "verification": {
            "task_id": verification.get("task_id"),
            "started_at": verification.get("started_at"),
            "finished_at": verification.get("finished_at"),
        },
    }


def exchange_oauth_code(*, tenant_id: str, user_id: str, code: str, state: str) -> Integration:
    """Exchange an OAuth code and upsert the tenant Slack integration."""
    credentials = get_slack_app_credentials(tenant_id)
    if credentials is None:
        raise ValidationError(
            {"detail": "Slack is not configured for this tenant."}
        )
    client_id, client_secret = credentials
    consume_oauth_state(state, tenant_id)

    response = requests.post(
        f"{SLACK_API}/oauth.v2.access",
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": slack_redirect_uri(),
        },
        timeout=30,
    )
    if response.status_code >= 500:
        raise ValidationError(
            {"detail": "Slack upstream error.", "code": "slack_upstream"}
        )
    payload = response.json()
    if not payload.get("ok"):
        raise ValidationError(
            {
                "detail": payload.get("error") or "invalid_code",
                "code": payload.get("error") or "invalid_code",
            }
        )

    team = payload.get("team") or {}
    team_id = team.get("id")
    bot_token = (payload.get("access_token") or "").strip()
    bot_user_id = (payload.get("bot_user_id") or "").strip()
    if not team_id or not bot_token:
        raise ValidationError({"detail": "Slack did not return a bot token."})

    with rls_transaction(tenant_id):
        existing = (
            Integration.objects.filter(
                tenant_id=tenant_id,
                integration_type=Integration.IntegrationChoices.SLACK,
            )
            .order_by("-inserted_at")
            .first()
        )
        if existing and existing.configuration.get("team_id") not in (None, team_id):
            raise ValidationError(
                {
                    "detail": "A different Slack workspace is already connected.",
                    "code": "workspace_conflict",
                }
            )

        previous_channels = []
        if existing:
            previous_channels = [
                {**channel, "confirmation_sent_at": None}
                for channel in (existing.configuration.get("channels") or [])
            ]

        configuration = {
            "team_id": team_id,
            "team_name": team.get("name") or "",
            "bot_user_id": bot_user_id,
            "channels": previous_channels,
            "verification": empty_verification(),
        }
        credentials = {"token": bot_token}

        if existing:
            existing.credentials = credentials
            existing.configuration = configuration
            existing.enabled = True
            existing.connected = None
            existing.connection_last_checked_at = None
            existing.save()
            return existing

        integration = Integration(
            id=uuid4(),
            tenant_id=tenant_id,
            integration_type=Integration.IntegrationChoices.SLACK,
            enabled=True,
            connected=None,
            configuration=configuration,
        )
        integration.credentials = credentials
        integration.save()
        return integration


def get_tenant_slack_integration(tenant_id: str) -> Integration | None:
    with rls_transaction(tenant_id):
        return (
            Integration.objects.filter(
                tenant_id=tenant_id,
                integration_type=Integration.IntegrationChoices.SLACK,
                enabled=True,
            )
            .order_by("-inserted_at")
            .first()
        )


def list_channels(
    integration: Integration, *, cursor: str | None = None, limit: int = 200
) -> tuple[list[dict[str, Any]], str | None]:
    """Return one page of Slack conversations and the next cursor."""
    token = integration.credentials.get("token")
    if not token:
        raise ValidationError({"detail": "Slack bot token is missing."})

    params: dict[str, Any] = {
        "types": "public_channel,private_channel",
        "exclude_archived": True,
        "limit": min(max(limit, 1), 200),
    }
    if cursor:
        params["cursor"] = cursor

    payload = _slack_api("conversations.list", token=token, params=params)
    channels = [
        {
            "id": channel["id"],
            "name": channel.get("name") or channel["id"],
            "is_private": bool(channel.get("is_private")),
        }
        for channel in payload.get("channels") or []
        if channel.get("id")
    ]
    next_cursor = (
        (payload.get("response_metadata") or {}).get("next_cursor") or None
    )
    if next_cursor == "":
        next_cursor = None
    return channels, next_cursor


def resolve_authorized_channels(
    integration: Integration, requested_ids: list[str]
) -> list[dict[str, Any]]:
    """Validate channel ids against Slack and retain prior confirmations."""
    unique_ids = list(dict.fromkeys(requested_ids))
    if not unique_ids:
        return []

    listed: dict[str, dict[str, Any]] = {}
    cursor: str | None = None
    while True:
        page, cursor = list_channels(integration, cursor=cursor, limit=200)
        for channel in page:
            listed[channel["id"]] = channel
        if not cursor:
            break
        if len(listed) > 5000:
            break

    missing = [channel_id for channel_id in unique_ids if channel_id not in listed]
    if missing:
        raise ValidationError(
            {"detail": "One or more channels are unknown to Slack."}
        )

    previous = {
        channel["id"]: channel
        for channel in (integration.configuration.get("channels") or [])
        if channel.get("id")
    }
    return [
        {
            "id": channel_id,
            "name": listed[channel_id]["name"],
            "is_private": listed[channel_id]["is_private"],
            "confirmation_sent_at": (previous.get(channel_id) or {}).get(
                "confirmation_sent_at"
            ),
        }
        for channel_id in unique_ids
    ]


def apply_channel_update(
    integration: Integration, channels: list[dict[str, Any]]
) -> Integration:
    """Replace authorized channels and reset connection when the set changes."""
    previous_ids = [
        channel.get("id")
        for channel in (integration.configuration.get("channels") or [])
        if channel.get("id")
    ]
    new_ids = [channel["id"] for channel in channels]
    configuration = {
        **integration.configuration,
        "channels": channels,
    }
    if set(previous_ids) != set(new_ids):
        configuration["verification"] = empty_verification()
        integration.connected = None
        integration.connection_last_checked_at = None
    integration.configuration = configuration
    integration.save()
    return integration


def validate_slack_connection_request(integration: Integration) -> str | None:
    """Return an error detail when a connection check must not start."""
    if integration.integration_type != Integration.IntegrationChoices.SLACK:
        return None
    channels = integration.configuration.get("channels") or []
    if not channels:
        return "Authorize at least one Slack channel before testing the connection."
    return None


def begin_verification(integration: Integration, task_id: str) -> None:
    configuration = {
        **integration.configuration,
        "verification": {
            "task_id": str(task_id),
            "started_at": None,
            "finished_at": None,
        },
    }
    integration.configuration = configuration
    integration.save(update_fields=["configuration", "updated_at"])


def test_slack_connection(integration: Integration) -> SlackConnectionResult:
    """auth.test plus a confirmation post to every authorized channel."""
    channels = list(integration.configuration.get("channels") or [])
    if not channels:
        return SlackConnectionResult(
            is_connected=False,
            error=Exception("No authorized Slack channels."),
        )

    token = (integration.credentials or {}).get("token")
    if not token:
        return SlackConnectionResult(
            is_connected=False,
            error=Exception("Slack bot token is missing."),
        )

    now = datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
    verification = dict(integration.configuration.get("verification") or {})
    verification["started_at"] = now
    integration.configuration = {
        **integration.configuration,
        "verification": verification,
    }
    integration.save(update_fields=["configuration", "updated_at"])

    try:
        _slack_api("auth.test", token=token)
    except ValidationError as exc:
        detail = ""
        if hasattr(exc, "detail"):
            detail = str(exc.detail)
        integration.connected = False
        integration.connection_last_checked_at = datetime.now(tz=UTC)
        verification["finished_at"] = datetime.now(tz=UTC).isoformat().replace(
            "+00:00", "Z"
        )
        integration.configuration = {
            **integration.configuration,
            "verification": verification,
        }
        integration.save()
        return SlackConnectionResult(
            is_connected=False, error=Exception(detail or "auth.test failed")
        )

    updated_channels = []
    for channel in channels:
        channel_id = channel.get("id")
        try:
            if channel.get("confirmation_sent_at") is None:
                _slack_api(
                    "chat.postMessage",
                    token=token,
                    json_body={"channel": channel_id, "text": CONFIRMATION_MESSAGE},
                )
                updated_channels.append(
                    {**channel, "confirmation_sent_at": now}
                )
            else:
                updated_channels.append(channel)
        except ValidationError as exc:
            detail = ""
            if hasattr(exc, "detail"):
                detail = str(exc.detail)
            verification["finished_at"] = datetime.now(tz=UTC).isoformat().replace(
                "+00:00", "Z"
            )
            integration.configuration = {
                **integration.configuration,
                "channels": updated_channels
                + [
                    c
                    for c in channels
                    if c.get("id") not in {u.get("id") for u in updated_channels}
                ],
                "verification": verification,
            }
            integration.connected = False
            integration.connection_last_checked_at = datetime.now(tz=UTC)
            integration.save()
            return SlackConnectionResult(
                is_connected=False,
                error=Exception(detail or "chat.postMessage failed"),
                failed_channel_id=channel_id,
            )

    finished = datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")
    verification["finished_at"] = finished
    integration.configuration = {
        **integration.configuration,
        "channels": updated_channels,
        "verification": verification,
    }
    integration.connected = True
    integration.connection_last_checked_at = datetime.now(tz=UTC)
    integration.save()
    return SlackConnectionResult(is_connected=True, error=None)


def post_alert_to_channels(
    *, tenant_id: str, channel_ids: list[str], text: str
) -> int:
    """Post an alert body to selected authorized Slack channels."""
    if not channel_ids:
        return 0
    integration = get_tenant_slack_integration(tenant_id)
    if integration is None:
        logger.error("No Slack integration for tenant=%s", tenant_id)
        return 0

    authorized = {
        channel.get("id")
        for channel in (integration.configuration.get("channels") or [])
        if channel.get("id")
    }
    token = (integration.credentials or {}).get("token")
    if not token:
        logger.error("Slack token missing for tenant=%s", tenant_id)
        return 0

    posted = 0
    for channel_id in channel_ids:
        if channel_id not in authorized:
            logger.warning(
                "Skipping unauthorized Slack channel %s for tenant=%s",
                channel_id,
                tenant_id,
            )
            continue
        try:
            _slack_api(
                "chat.postMessage",
                token=token,
                json_body={"channel": channel_id, "text": text},
            )
            posted += 1
        except Exception:
            logger.exception(
                "Failed Slack alert post tenant=%s channel=%s",
                tenant_id,
                channel_id,
            )
    return posted


def revoke_slack_token(integration: Integration) -> bool | None:
    """Best-effort auth.revoke; None when revocation could not be confirmed."""
    token = (integration.credentials or {}).get("token")
    if not token:
        return None
    try:
        response = requests.post(
            f"{SLACK_API}/auth.revoke",
            headers={"Authorization": f"Bearer {token}"},
            timeout=15,
        )
        payload = response.json()
        if payload.get("ok"):
            return bool(payload.get("revoked", True))
        return False
    except Exception:
        logger.exception("Slack auth.revoke failed for integration=%s", integration.id)
        return None
