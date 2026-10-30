"""Cloudsneeker routes.

Mounted under ``/api/v1/`` by a single hook in ``config/urls.py``.

* Product brand stays under ``cloudsneeker/`` so it never collides with
  upstream paths.
* Alerts, scan-configurations, and ingestions use the contracts the existing
  UI already calls. Those paths are absent from the open-source API tree; when
  upstream adds them, re-point these ViewSets or drop the Cloudsneeker copies.
"""

from cloudsneeker_api.views import BrandView
from cloudsneeker_api.views_audit import AuditEventViewSet  # Audit log (EB-007)
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
from cloudsneeker_api.views_triage import FindingTriageViewSet  # Finding triage (EB-010)
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

# --- Audit log (EB-007) ---
router.register(r"audit-events", AuditEventViewSet, basename="audit-events")

# --- Finding triage (EB-010) ---
router.register(r"finding-triages", FindingTriageViewSet, basename="finding-triages")

# Paths keyed by the finding UID that the inherited findings UI calls. ``path``
# accepts UIDs with ``/`` (the UI URL-encodes them; Django decodes before
# matching). Upstream ``findings/{pk}`` routes never match: their pk excludes
# ``/`` and ``.``.
finding_triage_urlpatterns = [
    path(
        "findings/<path:finding_uid>/triage/notes/<uuid:note_id>",
        FindingTriageViewSet.as_view(
            {"patch": "uid_note_detail", "delete": "uid_note_detail"}
        ),
        name="finding-uid-triage-note-detail",
    ),
    path(
        "findings/<path:finding_uid>/triage/notes",
        FindingTriageViewSet.as_view({"get": "uid_notes", "post": "uid_notes"}),
        name="finding-uid-triage-notes",
    ),
    path(
        "findings/<path:finding_uid>/triage",
        FindingTriageViewSet.as_view({"get": "uid_retrieve", "patch": "uid_update"}),
        name="finding-uid-triage",
    ),
]
# --- End finding triage (EB-010) ---

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
    *finding_triage_urlpatterns,  # Finding triage (EB-010)
    path("", include(router.urls)),
]
