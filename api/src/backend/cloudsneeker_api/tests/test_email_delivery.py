"""Unit tests for per-tenant SMTP email delivery and Slack helpers."""

from unittest.mock import MagicMock, patch

import pytest
from cloudsneeker_api.models import EmailDeliveryConfig
from cloudsneeker_api.services.email_delivery import send_with_tenant_smtp
from cloudsneeker_api.services.slack import (
    build_authorize_url,
    post_alert_to_channels,
    public_configuration,
    slack_app_configured,
)
from django.test import override_settings


class TestEmailDeliveryPasswordProperty:
    def test_password_encrypts_and_decrypts(self):
        config = EmailDeliveryConfig(
            host="smtp.example.com",
            port=587,
            from_email="alerts@example.com",
        )
        config.password = "s3cret"
        assert config._password is not None
        assert config.password == "s3cret"

    def test_blank_password_clears_secret(self):
        config = EmailDeliveryConfig(
            host="smtp.example.com",
            port=587,
            from_email="alerts@example.com",
        )
        config.password = "s3cret"
        config.password = ""
        assert config._password is None
        assert config.password == ""


class TestSendWithTenantSmtp:
    def test_raises_when_not_configured(self):
        with patch(
            "cloudsneeker_api.services.email_delivery.get_email_delivery_config",
            return_value=None,
        ):
            with pytest.raises(ValueError, match="not configured"):
                send_with_tenant_smtp(
                    tenant_id="11111111-1111-1111-1111-111111111111",
                    subject="s",
                    message="m",
                    recipient_list=["a@example.com"],
                )

    def test_sends_via_starttls(self):
        config = MagicMock()
        config.host = "smtp.example.com"
        config.port = 587
        config.use_ssl = False
        config.use_tls = True
        config.username = "user"
        config.password = "pass"
        config.from_email = "from@example.com"

        smtp = MagicMock()
        smtp.__enter__ = MagicMock(return_value=smtp)
        smtp.__exit__ = MagicMock(return_value=False)
        smtp.sendmail.return_value = {}

        with patch(
            "cloudsneeker_api.services.email_delivery.SMTP", return_value=smtp
        ) as smtp_cls:
            sent = send_with_tenant_smtp(
                tenant_id="11111111-1111-1111-1111-111111111111",
                subject="Hello",
                message="Body",
                recipient_list=["to@example.com"],
                config=config,
            )

        assert sent == 1
        smtp_cls.assert_called_once()
        smtp.starttls.assert_called_once()
        smtp.login.assert_called_once_with("user", "pass")
        smtp.sendmail.assert_called_once()


class TestSlackHelpers:
    def test_public_configuration_shape(self):
        shaped = public_configuration(
            {
                "team_id": "T1",
                "team_name": "Acme",
                "bot_user_id": "U1",
                "channels": [
                    {
                        "id": "C1",
                        "name": "alerts",
                        "is_private": False,
                        "confirmation_sent_at": None,
                    }
                ],
            }
        )
        assert shaped["team_id"] == "T1"
        assert shaped["channels"][0]["id"] == "C1"
        assert shaped["verification"]["task_id"] is None

    @override_settings(SLACK_CLIENT_ID="", SLACK_CLIENT_SECRET="")
    def test_unconfigured_without_credentials(self):
        assert slack_app_configured() is False

    @pytest.mark.django_db
    @override_settings(
        SLACK_CLIENT_ID="client",
        SLACK_CLIENT_SECRET="secret",
        UI_BASE_URL="https://app.example.com",
    )
    def test_builds_slack_consent_url(self):
        url = build_authorize_url(
            tenant_id="11111111-1111-1111-1111-111111111111",
            user_id="22222222-2222-2222-2222-222222222222",
        )
        assert url.startswith("https://slack.com/oauth/v2/authorize?")
        assert "client_id=client" in url
        assert "redirect_uri=" in url

    def test_tenant_credentials_preferred_over_settings(self):
        from cloudsneeker_api.services.slack import get_slack_app_credentials

        config = MagicMock()
        config.client_id = "tenant-client"
        config.client_secret = "tenant-secret"
        objects = MagicMock()
        objects.filter.return_value.order_by.return_value.first.return_value = (
            config
        )
        model = MagicMock()
        model.objects = objects
        with (
            patch(
                "cloudsneeker_api.services.slack.rls_transaction",
                MagicMock(),
            ),
            patch(
                "cloudsneeker_api.models.SlackAppConfig",
                model,
            ),
            override_settings(
                SLACK_CLIENT_ID="deploy-client",
                SLACK_CLIENT_SECRET="deploy-secret",
            ),
        ):
            assert get_slack_app_credentials(
                "11111111-1111-1111-1111-111111111111"
            ) == ("tenant-client", "tenant-secret")

    def test_post_alert_skips_without_integration(self):
        with patch(
            "cloudsneeker_api.services.slack.get_tenant_slack_integration",
            return_value=None,
        ):
            assert (
                post_alert_to_channels(
                    tenant_id="11111111-1111-1111-1111-111111111111",
                    channel_ids=["C1"],
                    text="hello",
                )
                == 0
            )


class TestFeatureRoutesIncludeEmailAndSlack:
    def test_email_delivery_route_resolves(self):
        from django.urls import resolve

        match = resolve("/api/v1/email-delivery-config")
        assert match.url_name == "email-delivery-config-list"

    def test_slack_oauth_routes_resolve(self):
        from django.urls import resolve

        assert (
            resolve("/api/v1/integrations/slack/oauth/authorize-url").url_name
            == "slack-oauth-authorize-url"
        )
        assert (
            resolve("/api/v1/integrations/slack/oauth/exchange").url_name
            == "slack-oauth-exchange"
        )
