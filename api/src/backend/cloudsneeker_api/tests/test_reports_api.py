"""Reporting API: catalog, runs, downloads, visibility, share links, schedules."""

from __future__ import annotations

import json
from datetime import timedelta
from unittest.mock import patch

import pytest
from api.db_utils import rls_transaction
from api.models import (
    ProviderGroup,
    ProviderGroupMembership,
    Role,
    RoleProviderGroupRelationship,
)
from cloudsneeker_api.models import (
    JSON_API_TYPE_PREFIX,
    ReportRun,
    ReportSchedule,
    ReportShareLink,
)
from cloudsneeker_api.reports.runs import enqueue_report_run, process_report_run
from cloudsneeker_api.reports.schedule import PERIODIC_TASK_PREFIX
from cloudsneeker_api.views_reports import ReportRunViewSet, SharedReportView
from django.test import Client, override_settings
from django.urls import reverse
from django.utils import timezone
from django_celery_beat.models import PeriodicTask

JSONAPI = "application/vnd.api+json"


def _body(resource: str, attributes: dict, resource_id: str | None = None) -> str:
    data = {"type": f"{JSON_API_TYPE_PREFIX}{resource}", "attributes": attributes}
    if resource_id:
        data["id"] = resource_id
    return json.dumps({"data": data})


@pytest.fixture
def report_dir(tmp_path):
    with override_settings(DJANGO_TMP_OUTPUT_DIRECTORY=str(tmp_path)):
        yield tmp_path


def _completed_run(tenant, *, params=None, created_by=None):
    with patch("cloudsneeker_api.reports.runs.transaction.on_commit"):
        run = enqueue_report_run(
            tenant_id=str(tenant.id),
            report_type="executive",
            params=params or {},
            formats=["pdf", "xlsx", "csv"],
            created_by_id=str(created_by.id) if created_by else None,
        )
    process_report_run(tenant_id=str(tenant.id), run_id=str(run.id))
    with rls_transaction(str(tenant.id)):
        return ReportRun.objects.get(id=run.id)


def _grant_provider(tenant, user, provider):
    """Give the limited role of ``user`` visibility over ``provider``."""
    with rls_transaction(str(tenant.id)):
        role = Role.objects.get(tenant_id=tenant.id, name="limited")
        group = ProviderGroup.objects.create(tenant_id=tenant.id, name="report-group")
        ProviderGroupMembership.objects.create(
            tenant_id=tenant.id, provider_group=group, provider=provider
        )
        RoleProviderGroupRelationship.objects.create(
            tenant_id=tenant.id, role=role, provider_group=group
        )
    return role


@pytest.mark.django_db
class TestReportTypes:
    def test_list(self, authenticated_client):
        response = authenticated_client.get(reverse("report-types-list"))
        assert response.status_code == 200
        data = response.json()["data"]
        assert {item["id"] for item in data} >= {"executive", "sast", "governance"}
        assert data[0]["type"] == f"{JSON_API_TYPE_PREFIX}report-types"
        assert "attributes" in data[0] and "data" not in data[0]["attributes"]

    def test_retrieve_and_unknown(self, authenticated_client):
        response = authenticated_client.get(
            reverse("report-types-detail", kwargs={"pk": "compliance"})
        )
        assert response.status_code == 200
        assert response.json()["data"]["attributes"]["parameters"]["required"] == [
            "compliance_id"
        ]
        missing = authenticated_client.get(
            reverse("report-types-detail", kwargs={"pk": "nope"})
        )
        assert missing.status_code == 404

    def test_requires_authentication(self, client):
        assert client.get(reverse("report-types-list")).status_code == 401


@pytest.mark.django_db
class TestReportRunsApi:
    def test_create_enqueues(self, authenticated_client, tenants_fixture):
        with patch("cloudsneeker_api.reports.runs.transaction.on_commit") as on_commit:
            response = authenticated_client.post(
                reverse("report-runs-list"),
                data=_body(
                    "report-runs",
                    {
                        "report_type": "cloud_posture",
                        "params": {"severity_floor": "high"},
                        "formats": ["pdf", "csv"],
                    },
                ),
                content_type=JSONAPI,
            )
        assert response.status_code == 202, response.content
        document = response.json()["data"]
        assert document["type"] == f"{JSON_API_TYPE_PREFIX}report-runs"
        assert document["attributes"]["status"] == "pending"
        assert document["attributes"]["formats"] == ["pdf", "csv", "json"]
        on_commit.assert_called_once()

    @pytest.mark.parametrize(
        "attributes",
        [
            {"report_type": "nope"},
            {"report_type": "compliance", "params": {}},
            {"report_type": "sca", "formats": ["docx"]},
            {"report_type": "sca", "params": {"severity_floor": "urgent"}},
        ],
    )
    def test_create_validates(self, authenticated_client, attributes):
        response = authenticated_client.post(
            reverse("report-runs-list"),
            data=_body("report-runs", attributes),
            content_type=JSONAPI,
        )
        assert response.status_code == 400

    def test_list_retrieve_download_and_data(self, authenticated_client, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        run = _completed_run(tenant)

        listing = authenticated_client.get(reverse("report-runs-list"))
        assert listing.status_code == 200
        assert [item["id"] for item in listing.json()["data"]] == [str(run.id)]

        detail = authenticated_client.get(reverse("report-runs-detail", kwargs={"pk": run.id}))
        attributes = detail.json()["data"]["attributes"]
        assert attributes["available_formats"] == ["csv", "json", "pdf", "xlsx"]
        assert attributes["report_name"] == "Executive summary"

        url = reverse("report-runs-download", kwargs={"pk": run.id})
        for fmt, content_type, magic in (
            ("pdf", "application/pdf", b"%PDF"),
            (
                "xlsx",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                b"PK",
            ),
            ("csv", "text/csv", b"\xef\xbb\xbf"),
        ):
            response = authenticated_client.get(f"{url}?format={fmt}")
            assert response.status_code == 200, (fmt, response.content[:200])
            assert response["Content-Type"] == content_type
            disposition = response["Content-Disposition"]
            assert "attachment" in disposition
            assert f".{fmt}" in disposition and "cloudsneeker-executive-" in disposition
            assert b"".join(response.streaming_content).startswith(magic)

        assert authenticated_client.get(f"{url}?format=docx").status_code == 400

        data = authenticated_client.get(reverse("report-runs-data", kwargs={"pk": run.id}))
        assert data.status_code == 200
        document = data.json()["data"]
        assert document["id"] == str(run.id)
        assert document["attributes"]["report_type"] == "executive"
        assert "data" not in document["attributes"]

    def test_download_before_ready(self, authenticated_client, tenants_fixture):
        tenant = tenants_fixture[0]
        with patch("cloudsneeker_api.reports.runs.transaction.on_commit"):
            run = enqueue_report_run(
                tenant_id=str(tenant.id), report_type="sca", params={}, formats=None
            )
        response = authenticated_client.get(
            reverse("report-runs-download", kwargs={"pk": run.id}) + "?format=pdf"
        )
        assert response.status_code == 404

    def test_delete_removes_artifacts(self, authenticated_client, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        run = _completed_run(tenant)
        response = authenticated_client.delete(reverse("report-runs-detail", kwargs={"pk": run.id}))
        assert response.status_code == 204
        assert not (report_dir / "cloudsneeker-reports" / str(tenant.id) / str(run.id)).exists()

    def test_viewset_forces_negotiation_for_download(self):
        assert ReportRunViewSet.download.url_path == "download"
        assert SharedReportView.authentication_classes == []
        assert SharedReportView.resource_name is False


@pytest.mark.django_db
class TestVisibility:
    def test_limited_role_without_providers_cannot_generate(
        self, authenticated_client_no_permissions_rbac
    ):
        response = authenticated_client_no_permissions_rbac.post(
            reverse("report-runs-list"),
            data=_body("report-runs", {"report_type": "executive"}),
            content_type=JSONAPI,
        )
        assert response.status_code == 403

    def test_limited_role_is_pinned_to_visible_providers(
        self, authenticated_client_no_permissions_rbac, tenants_fixture, aws_provider_pair
    ):
        client = authenticated_client_no_permissions_rbac
        tenant = tenants_fixture[0]
        allowed, denied = aws_provider_pair
        _grant_provider(tenant, client.user, allowed)

        with patch("cloudsneeker_api.reports.runs.transaction.on_commit"):
            response = client.post(
                reverse("report-runs-list"),
                data=_body("report-runs", {"report_type": "cloud_posture"}),
                content_type=JSONAPI,
            )
        assert response.status_code == 202, response.content
        assert response.json()["data"]["attributes"]["params"]["provider_ids"] == [
            str(allowed.id)
        ]

        denied_response = client.post(
            reverse("report-runs-list"),
            data=_body(
                "report-runs",
                {"report_type": "cloud_posture", "params": {"provider_ids": [str(denied.id)]}},
            ),
            content_type=JSONAPI,
        )
        assert denied_response.status_code == 403

    def test_limited_role_only_lists_visible_runs(
        self,
        authenticated_client_no_permissions_rbac,
        tenants_fixture,
        aws_provider_pair,
        report_dir,
    ):
        client = authenticated_client_no_permissions_rbac
        tenant = tenants_fixture[0]
        allowed, denied = aws_provider_pair
        _grant_provider(tenant, client.user, allowed)
        visible = _completed_run(tenant, params={"provider_ids": [str(allowed.id)]})
        own = _completed_run(
            tenant, params={"provider_ids": [str(denied.id)]}, created_by=client.user
        )
        hidden_mixed = _completed_run(
            tenant, params={"provider_ids": [str(allowed.id), str(denied.id)]}
        )
        hidden_all = _completed_run(tenant)

        ids = {item["id"] for item in client.get(reverse("report-runs-list")).json()["data"]}
        assert ids == {str(visible.id), str(own.id)}
        for run in (hidden_mixed, hidden_all):
            assert (
                client.get(reverse("report-runs-detail", kwargs={"pk": run.id})).status_code
                == 404
            )
            assert (
                client.get(
                    reverse("report-runs-download", kwargs={"pk": run.id}) + "?format=pdf"
                ).status_code
                == 404
            )

    def test_share_requires_manage_scans(
        self, authenticated_client_no_permissions_rbac, tenants_fixture, report_dir
    ):
        client = authenticated_client_no_permissions_rbac
        tenant = tenants_fixture[0]
        run = _completed_run(tenant, created_by=client.user)
        response = client.post(
            reverse("report-runs-shares", kwargs={"pk": run.id}),
            data=_body("report-share-links", {"expires_in_hours": 1}),
            content_type=JSONAPI,
        )
        assert response.status_code == 403
        schedules = client.get(reverse("report-schedules-list"))
        assert schedules.status_code == 403


@pytest.mark.django_db
class TestShareLinksApi:
    def test_create_resolve_revoke(self, authenticated_client, tenants_fixture, report_dir):
        anonymous = Client()
        tenant = tenants_fixture[0]
        run = _completed_run(tenant)
        created = authenticated_client.post(
            reverse("report-runs-shares", kwargs={"pk": run.id}),
            data=_body("report-share-links", {"expires_in_hours": 2}),
            content_type=JSONAPI,
        )
        assert created.status_code == 201, created.content
        document = created.json()["data"]
        token = document["attributes"]["token"]
        assert document["attributes"]["state"] == "active"
        with rls_transaction(str(tenant.id)):
            link = ReportShareLink.objects.get(id=document["id"])
        assert link.token_hash != token

        listing = authenticated_client.get(reverse("report-runs-shares", kwargs={"pk": run.id}))
        assert listing.status_code == 200
        assert "token" not in listing.json()["data"][0]["attributes"]

        public = anonymous.get(reverse("shared-report", kwargs={"token": token}))
        assert public.status_code == 200
        payload = public.json()["data"]
        assert payload["type"] == f"{JSON_API_TYPE_PREFIX}shared-reports"
        assert payload["attributes"]["report_type"] == "executive"
        assert public["Cache-Control"] == "no-store"
        assert str(tenant.id) not in public.content.decode()

        revoked = authenticated_client.post(
            reverse("report-share-links-revoke", kwargs={"pk": link.id}),
            data=_body("report-share-links", {}, str(link.id)),
            content_type=JSONAPI,
        )
        assert revoked.status_code == 200, revoked.content
        assert revoked.json()["data"]["attributes"]["state"] == "revoked"
        assert anonymous.get(reverse("shared-report", kwargs={"token": token})).status_code == 410

    def test_public_endpoint_unknown_and_expired(self, client, tenants_fixture, report_dir):
        assert client.get(reverse("shared-report", kwargs={"token": "nope"})).status_code == 404
        tenant = tenants_fixture[0]
        run = _completed_run(tenant)
        from cloudsneeker_api.reports.share import create_share_link

        link, token = create_share_link(tenant_id=str(tenant.id), run=run)
        with rls_transaction(str(tenant.id)):
            ReportShareLink.objects.filter(id=link.id).update(
                expires_at=timezone.now() - timedelta(seconds=1)
            )
        response = client.get(reverse("shared-report", kwargs={"token": token}))
        assert response.status_code == 410
        assert response.json()["errors"][0]["code"] == "expired"

    def test_cannot_share_pending_run(self, authenticated_client, tenants_fixture):
        tenant = tenants_fixture[0]
        with patch("cloudsneeker_api.reports.runs.transaction.on_commit"):
            run = enqueue_report_run(
                tenant_id=str(tenant.id), report_type="sca", params={}, formats=None
            )
        response = authenticated_client.post(
            reverse("report-runs-shares", kwargs={"pk": run.id}),
            data=_body("report-share-links", {}),
            content_type=JSONAPI,
        )
        assert response.status_code == 400
        assert response.json()["errors"][0]["code"] == "not_ready"


@pytest.mark.django_db
class TestReportSchedulesApi:
    def _create(self, client, **overrides):
        attributes = {
            "name": "Weekly exec",
            "report_type": "executive",
            "formats": ["pdf"],
            "schedule_cron": "0 8 * * 1",
            "schedule_timezone": "Europe/London",
            "recipients": ["CISO@Example.com", "ciso@example.com", "cto@example.com"],
            **overrides,
        }
        return client.post(
            reverse("report-schedules-list"),
            data=_body("report-schedules", attributes),
            content_type=JSONAPI,
        )

    def test_crud_syncs_beat(self, authenticated_client):
        created = self._create(authenticated_client)
        assert created.status_code == 201, created.content
        document = created.json()["data"]
        attributes = document["attributes"]
        assert attributes["recipients"] == ["ciso@example.com", "cto@example.com"]
        assert attributes["next_run_at"] is not None
        task = PeriodicTask.objects.get(name=f"{PERIODIC_TASK_PREFIX}{document['id']}")
        assert task.enabled is True
        assert task.task == "cloudsneeker-scheduled-report"
        assert str(task.crontab.timezone) == "Europe/London"

        updated = authenticated_client.patch(
            reverse("report-schedules-detail", kwargs={"pk": document["id"]}),
            data=_body("report-schedules", {"enabled": False}, document["id"]),
            content_type=JSONAPI,
        )
        assert updated.status_code == 200, updated.content
        assert updated.json()["data"]["attributes"]["next_run_at"] is None
        task.refresh_from_db()
        assert task.enabled is False

        deleted = authenticated_client.delete(
            reverse("report-schedules-detail", kwargs={"pk": document["id"]})
        )
        assert deleted.status_code == 204
        assert not PeriodicTask.objects.filter(name=task.name).exists()

    @pytest.mark.parametrize(
        "overrides",
        [
            {"schedule_cron": "every monday"},
            {"schedule_timezone": "Mars/Base"},
            {"recipients": ["not-an-email"]},
            {"report_type": "compliance"},
            {"report_type": "unknown"},
        ],
    )
    def test_validation(self, authenticated_client, overrides):
        assert self._create(authenticated_client, **overrides).status_code == 400

    def test_duplicate_name(self, authenticated_client):
        assert self._create(authenticated_client).status_code == 201
        assert self._create(authenticated_client).status_code == 400

    def test_list_scoped_to_tenant(self, authenticated_client, tenants_fixture):
        other = tenants_fixture[1]
        with rls_transaction(str(other.id)):
            ReportSchedule.objects.create(
                tenant_id=other.id,
                name="other-tenant",
                report_type="executive",
                schedule_cron="0 8 * * *",
            )
        assert self._create(authenticated_client).status_code == 201
        names = [
            item["attributes"]["name"]
            for item in authenticated_client.get(reverse("report-schedules-list")).json()["data"]
        ]
        assert names == ["Weekly exec"]
