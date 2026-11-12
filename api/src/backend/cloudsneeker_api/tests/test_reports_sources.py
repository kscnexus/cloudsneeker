"""Report sources: the API rejects providers a report does not read."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from api.db_utils import rls_transaction
from api.models import Provider
from cloudsneeker_api.models import JSON_API_TYPE_PREFIX, ReportRun, ReportSchedule
from cloudsneeker_api.reports.catalog import ReportParamsError
from cloudsneeker_api.reports.runs import enqueue_report_run
from cloudsneeker_api.reports.sources import (
    check_source_scope,
    drop_inapplicable_sources,
)
from django.urls import reverse

JSONAPI = "application/vnd.api+json"


def _body(resource: str, attributes: dict, resource_id: str | None = None) -> str:
    data = {"type": f"{JSON_API_TYPE_PREFIX}{resource}", "attributes": attributes}
    if resource_id:
        data["id"] = resource_id
    return json.dumps({"data": data})


@pytest.fixture
def mixed_providers(provider_factory):
    return (
        provider_factory(Provider.ProviderChoices.AWS.value),
        provider_factory(Provider.ProviderChoices.IAC.value),
        provider_factory(Provider.ProviderChoices.IMAGE.value),
    )


@pytest.mark.django_db
class TestSourceScopeRules:
    def test_check_rejects_and_accepts(self, tenants_fixture, mixed_providers):
        tenant_id = str(tenants_fixture[0].id)
        aws, iac, image = (str(item.id) for item in mixed_providers)
        check_source_scope(tenant_id, "cloud_posture", {"provider_ids": [aws]})
        check_source_scope(tenant_id, "sca", {"provider_ids": [iac, image]})
        check_source_scope(tenant_id, "executive", {"provider_ids": [aws, iac]})
        with pytest.raises(ReportParamsError, match="cloud and SaaS accounts"):
            check_source_scope(tenant_id, "cloud_posture", {"provider_ids": [aws, iac]})
        with pytest.raises(ReportParamsError, match=iac):
            check_source_scope(tenant_id, "container", {"provider_ids": [iac]})

    def test_drop_keeps_applicable_sources(self, tenants_fixture, mixed_providers):
        tenant_id = str(tenants_fixture[0].id)
        aws, iac, _ = (str(item.id) for item in mixed_providers)
        params = {"provider_ids": [aws, iac]}
        assert drop_inapplicable_sources(tenant_id, "cloud_posture", params) == {
            "provider_ids": [aws]
        }
        # Nothing applicable left: the list stays (never widened to "all").
        only_code = {"provider_ids": [iac]}
        assert drop_inapplicable_sources(tenant_id, "cloud_posture", only_code) == only_code


@pytest.mark.django_db
class TestSourceScopeApi:
    def test_run_with_inapplicable_source_is_400(self, authenticated_client, mixed_providers):
        _, iac, _ = mixed_providers
        response = authenticated_client.post(
            reverse("report-runs-list"),
            data=_body(
                "report-runs",
                {"report_type": "cloud_posture", "params": {"provider_ids": [str(iac.id)]}},
            ),
            content_type=JSONAPI,
        )
        assert response.status_code == 400
        assert "cloud and SaaS accounts" in response.content.decode()

    def test_run_with_applicable_source_is_accepted(
        self, authenticated_client, mixed_providers
    ):
        _, iac, image = mixed_providers
        with patch("cloudsneeker_api.reports.runs.transaction.on_commit"):
            response = authenticated_client.post(
                reverse("report-runs-list"),
                data=_body(
                    "report-runs",
                    {
                        "report_type": "sca",
                        "params": {"provider_ids": [str(iac.id), str(image.id)]},
                    },
                ),
                content_type=JSONAPI,
            )
        assert response.status_code == 202, response.content

    def test_schedule_with_inapplicable_source_is_400(
        self, authenticated_client, mixed_providers
    ):
        aws, _, _ = mixed_providers
        response = authenticated_client.post(
            reverse("report-schedules-list"),
            data=_body(
                "report-schedules",
                {
                    "name": "Weekly code",
                    "report_type": "iac",
                    "params": {"provider_ids": [str(aws.id)]},
                    "formats": ["pdf"],
                    "schedule_cron": "0 8 * * 1",
                },
            ),
            content_type=JSONAPI,
        )
        assert response.status_code == 400

    def test_stored_schedule_still_pauses_and_runs(
        self, authenticated_client, tenants_fixture, mixed_providers
    ):
        tenant = tenants_fixture[0]
        aws, iac, _ = mixed_providers
        created = authenticated_client.post(
            reverse("report-schedules-list"),
            data=_body(
                "report-schedules",
                {
                    "name": "Old mixed schedule",
                    "report_type": "executive",
                    "params": {"provider_ids": [str(aws.id), str(iac.id)]},
                    "formats": ["pdf"],
                    "schedule_cron": "0 8 * * 1",
                },
            ),
            content_type=JSONAPI,
        )
        assert created.status_code == 201, created.content
        schedule_id = created.json()["data"]["id"]
        # A schedule stored before the rule existed: cloud report, code source.
        with rls_transaction(str(tenant.id)):
            ReportSchedule.objects.filter(id=schedule_id).update(
                report_type="cloud_posture"
            )
        paused = authenticated_client.patch(
            reverse("report-schedules-detail", kwargs={"pk": schedule_id}),
            data=_body("report-schedules", {"enabled": False}, schedule_id),
            content_type=JSONAPI,
        )
        assert paused.status_code == 200, paused.content

        with patch("cloudsneeker_api.reports.runs.transaction.on_commit"):
            run = enqueue_report_run(
                tenant_id=str(tenant.id),
                report_type="cloud_posture",
                params={"provider_ids": [str(aws.id), str(iac.id)]},
                formats=["pdf"],
                schedule_id=schedule_id,
            )
        with rls_transaction(str(tenant.id)):
            stored = ReportRun.objects.get(id=run.id)
        assert stored.params["provider_ids"] == [str(aws.id)]
