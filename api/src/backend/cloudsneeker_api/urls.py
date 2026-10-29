"""Cloudsneeker routes.

Mounted under ``/api/v1/`` by a single hook in ``config/urls.py``.

* Product brand stays under ``cloudsneeker/`` so it never collides with
  upstream paths.
* Alerts, scan-configurations, and ingestions use the contracts the existing
  UI already calls. Those paths are absent from the open-source API tree; when
  upstream adds them, re-point these ViewSets or drop the Cloudsneeker copies.
"""

from cloudsneeker_api.views import BrandView
from cloudsneeker_api.views_reports import (
    ReportRunViewSet,
    ReportScheduleViewSet,
    ReportShareLinkViewSet,
    ReportTypeViewSet,
    SharedReportView,
)
from cloudsneeker_api.views_email import EmailDeliveryConfigViewSet
from cloudsneeker_api.views_slack_app import SlackAppConfigViewSet
from cloudsneeker_api.views_features import (
    AlertRecipientConfirmView,
    AlertRecipientUnsubscribeView,
    AlertRecipientViewSet,
    AlertRuleViewSet,
    AlertSlackChannelsView,
    CustodianPolicyViewSet,
    CustodianRunViewSet,
    IngestionViewSet,
    ScanConfigurationViewSet,
)
from cloudsneeker_api.views_slack import (
    SlackChannelsView,
    SlackOAuthAuthorizeUrlView,
    SlackOAuthExchangeView,
)
from cloudsneeker_api.views_trivy import TrivyRunViewSet, TrivyTargetViewSet
from django.urls import include, path
from rest_framework_nested import routers

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"scan-configurations", ScanConfigurationViewSet, basename="scan-configurations")
router.register(r"alerts/rules", AlertRuleViewSet, basename="alert-rules")
router.register(r"alerts/recipients", AlertRecipientViewSet, basename="alert-recipients")
router.register(r"ingestions", IngestionViewSet, basename="ingestions")
router.register(
    r"email-delivery-config",
    EmailDeliveryConfigViewSet,
    basename="email-delivery-config",
)
router.register(
    r"slack-app-config",
    SlackAppConfigViewSet,
    basename="slack-app-config",
)
router.register(
    r"custodian-policies", CustodianPolicyViewSet, basename="custodian-policies"
)
router.register(r"custodian-runs", CustodianRunViewSet, basename="custodian-runs")
router.register(r"trivy-targets", TrivyTargetViewSet, basename="trivy-targets")
router.register(r"trivy-runs", TrivyRunViewSet, basename="trivy-runs")
router.register(r"report-types", ReportTypeViewSet, basename="report-types")
router.register(r"report-runs", ReportRunViewSet, basename="report-runs")
router.register(
    r"report-schedules", ReportScheduleViewSet, basename="report-schedules"
)
router.register(
    r"report-share-links", ReportShareLinkViewSet, basename="report-share-links"
)

urlpatterns = [
    path("cloudsneeker/brand", BrandView.as_view(), name="cloudsneeker-brand"),
    path(
        "alerts/slack-channels",
        AlertSlackChannelsView.as_view(),
        name="alert-slack-channels",
    ),
    path(
        "alerts/recipients/confirm",
        AlertRecipientConfirmView.as_view(),
        name="alert-recipient-confirm",
    ),
    path(
        "alerts/recipients/unsubscribe",
        AlertRecipientUnsubscribeView.as_view(),
        name="alert-recipient-unsubscribe",
    ),
    path(
        "integrations/slack/oauth/authorize-url",
        SlackOAuthAuthorizeUrlView.as_view(),
        name="slack-oauth-authorize-url",
    ),
    path(
        "integrations/slack/oauth/exchange",
        SlackOAuthExchangeView.as_view(),
        name="slack-oauth-exchange",
    ),
    path(
        "integrations/<uuid:integration_id>/slack/channels",
        SlackChannelsView.as_view(),
        name="slack-channels",
    ),
    path(
        "shared-reports/<str:token>",
        SharedReportView.as_view(),
        name="shared-report",
    ),
    path("", include(router.urls)),
]
