"""Cloudsneeker routes.

Mounted under ``/api/v1/`` by a single hook in ``config/urls.py``.

* Product brand stays under ``cloudsneeker/`` so it never collides with
  upstream paths.
* Alerts, scan-configurations, and ingestions use the contracts the existing
  UI already calls. Those paths are absent from the open-source API tree; when
  upstream adds them, re-point these ViewSets or drop the Cloudsneeker copies.
"""

from cloudsneeker_api.views import BrandView
from cloudsneeker_api.views_features import (
    AlertRecipientConfirmView,
    AlertRecipientUnsubscribeView,
    AlertRecipientViewSet,
    AlertRuleViewSet,
    AlertSlackChannelsView,
    IngestionViewSet,
    ScanConfigurationViewSet,
)
from django.urls import include, path
from rest_framework_nested import routers

router = routers.DefaultRouter(trailing_slash=False)
router.register(r"scan-configurations", ScanConfigurationViewSet, basename="scan-configurations")
router.register(r"alerts/rules", AlertRuleViewSet, basename="alert-rules")
router.register(r"alerts/recipients", AlertRecipientViewSet, basename="alert-recipients")
router.register(r"ingestions", IngestionViewSet, basename="ingestions")

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
    path("", include(router.urls)),
]
