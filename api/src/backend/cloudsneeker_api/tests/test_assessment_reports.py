"""Assessment reports end to end: parameters, collection from real rows, runs."""

from __future__ import annotations

import csv
import io
import json
from datetime import timedelta
from unittest.mock import patch
from uuid import uuid4

import pytest
from api.db_utils import rls_transaction
from api.models import (
    ComplianceOverviewSummary,
    Finding,
    Provider,
    Resource,
    ResourceFindingMapping,
    Scan,
    StateChoices,
)
from cloudsneeker_api.models import (
    CustodianPolicy,
    CustodianRun,
    FindingTriage,
    ReportRun,
)
from cloudsneeker_api.reports.catalog import (
    ASSESSMENT_TYPES,
    ReportParamsError,
    filters_from_params,
    validate_params,
)
from cloudsneeker_api.reports.data import assemble_report
from cloudsneeker_api.reports.runs import (
    artifact_path,
    enqueue_report_run,
    process_report_run,
    read_report_json,
)
from django.test import override_settings
from django.utils import timezone

POLICY_YAML = """
policies:
  - name: unencrypted-ebs
    resource: aws.ebs
    metadata:
      severity: high
"""


@pytest.fixture
def report_dir(tmp_path):
    with override_settings(DJANGO_TMP_OUTPUT_DIRECTORY=str(tmp_path)):
        yield tmp_path


def _scan(tenant_id, provider, *, days_ago=1, scanner_args=None):
    moment = timezone.now() - timedelta(days=days_ago)
    return Scan.objects.create(
        tenant_id=tenant_id,
        provider=provider,
        name="assessment scan",
        trigger=Scan.TriggerChoices.MANUAL,
        state=StateChoices.COMPLETED,
        started_at=moment,
        completed_at=moment,
        scanner_args=scanner_args or {},
    )


def _finding(
    scan,
    check_id,
    severity="high",
    *,
    status="FAIL",
    muted=False,
    raw=None,
    resource=None,
    uid=None,
    metadata=None,
):
    finding = Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid=uid or f"{check_id}-{uuid4()}",
        scan=scan,
        status=status,
        status_extended=f"{check_id} evidence",
        severity=severity,
        impact=severity,
        raw_result=raw or {},
        check_id=check_id,
        check_metadata=metadata
        or {
            "CheckTitle": f"Title {check_id}",
            "Risk": "Attackers could read data.",
            "Remediation": {
                "Recommendation": {
                    "Text": "Turn the setting on.",
                    "Url": "https://docs.aws.amazon.com/x",
                },
                "Code": {
                    "CLI": "aws example --resource <RESOURCE_ID>",
                    "Terraform": "",
                    "Other": "https://x",
                },
            },
        },
        muted=muted,
        first_seen_at=timezone.now() - timedelta(days=10),
    )
    if resource is not None:
        ResourceFindingMapping.objects.create(
            tenant_id=scan.tenant_id, resource=resource, finding=finding
        )
    return finding


def _resource(tenant_id, provider, uid):
    return Resource.objects.create(
        tenant_id=tenant_id,
        provider=provider,
        uid=uid,
        name=uid.split(":")[-1],
        region="eu-west-1",
        service="s3",
        type="bucket",
    )


class TestParams:
    @pytest.mark.parametrize("report_type", ASSESSMENT_TYPES)
    def test_defaults(self, report_type):
        params = validate_params(report_type, {})
        assert params["period"] == "latest"
        assert "ai_insights" not in params["sections"]
        assert params["stale_days"] == 7
        filters = filters_from_params(params)
        assert filters.options["period"] == "latest"

    @pytest.mark.parametrize(
        "params, message",
        [
            ({"period": "yesterday"}, "period must be one of"),
            ({"period": "custom"}, "custom period needs"),
            ({"sections": ["cover"]}, "Unknown section"),
            ({"stale_days": 0}, "stale_days must be between"),
            ({"frameworks": ["ok", "bad id!"]}, "Invalid framework id"),
            ({"compliance_id": "cis"}, "Unknown parameter"),
        ],
    )
    def test_rejects(self, params, message):
        with pytest.raises(ReportParamsError, match=message):
            validate_params("security_assessment", params)

    def test_frameworks_only_where_relevant(self):
        with pytest.raises(ReportParamsError, match="Unknown parameter"):
            validate_params("appsec_assessment", {"frameworks": ["cis_2.0_aws"]})
        params = validate_params(
            "governance_assessment",
            {"frameworks": "cis_2.0_aws,cis_2.0_aws", "period": "30d"},
        )
        assert params["frameworks"] == ["cis_2.0_aws"]

    def test_legacy_types_are_unchanged(self):
        assert "period" not in validate_params("executive", {})


@pytest.mark.django_db
class TestAssembly:
    @pytest.fixture
    def tenant_data(self, tenants_fixture, provider_factory):
        tenant = tenants_fixture[0]
        aws = provider_factory(Provider.ProviderChoices.AWS.value)
        aws_two = provider_factory(Provider.ProviderChoices.AWS.value)  # never scanned
        repo = provider_factory(Provider.ProviderChoices.IAC.value)
        with rls_transaction(str(tenant.id)):
            old = _scan(tenant.id, aws, days_ago=5)
            _finding(old, "old_check", "critical")
            cloud = _scan(tenant.id, aws, days_ago=1)
            bucket = _resource(tenant.id, aws, "arn:aws:s3:::customer-data")
            public = _finding(cloud, "s3_bucket_public", "critical", resource=bucket)
            _finding(cloud, "s3_bucket_versioning", "medium", resource=bucket)
            _finding(cloud, "iam_password_policy", "high", status="PASS")
            _finding(cloud, "ec2_old_ami", "low", muted=True)
            _finding(cloud, "manual_review", "medium", status="MANUAL")
            app = _scan(
                tenant.id,
                repo,
                days_ago=2,
                scanner_args={"source": "trivy_hub", "mode": "repo"},
            )
            vuln_raw = {
                "VulnerabilityID": "CVE-2024-4068",
                "PkgName": "braces",
                "InstalledVersion": "3.0.2",
                "FixedVersion": "3.0.3",
                "PkgIdentifier": {"PURL": "pkg:npm/braces@3.0.2"},
                "CVSS": {"nvd": {"V3Score": 7.5, "V3Vector": "CVSS:3.1/AV:N"}},
            }
            _finding(
                app,
                "CVE-2024-4068",
                "high",
                raw=vuln_raw,
                metadata={"CheckTitle": "braces issue"},
            )
            _finding(
                app,
                "aws-access-key-id",
                "critical",
                raw={
                    "RuleID": "aws-access-key-id",
                    "Match": "AKIA****",
                    "StartLine": 3,
                },
                metadata={"CheckTitle": "AWS key"},
            )
            ComplianceOverviewSummary.objects.create(
                tenant_id=tenant.id,
                scan=cloud,
                compliance_id="cis_2.0_aws",
                requirements_passed=8,
                requirements_failed=2,
                requirements_manual=1,
                total_requirements=11,
            )
            policy = CustodianPolicy.objects.create(
                tenant_id=tenant.id,
                name="unencrypted-ebs",
                policy_yaml=POLICY_YAML,
                provider=aws,
            )
            CustodianRun.objects.create(
                tenant_id=tenant.id,
                policy=policy,
                provider=aws,
                status=CustodianRun.Status.COMPLETED,
                finished_at=timezone.now() - timedelta(hours=3),
                summary={"resource_count": 2},
                output={
                    "resources": [
                        {"VolumeId": "vol-1", "c7n:policy": "unencrypted-ebs"},
                        {"VolumeId": "vol-2"},
                    ]
                },
            )
            FindingTriage.objects.create(
                tenant_id=tenant.id,
                finding_uid=public.uid,
                status="under_review",
                provider=aws,
            )
        return tenant, aws, aws_two, public

    def _assemble(self, tenant, report_type, params=None):
        params = validate_params(report_type, params or {})
        with rls_transaction(str(tenant.id)):
            return assemble_report(
                str(tenant.id), report_type, filters_from_params(params)
            )

    def test_executive_reads_every_area(self, tenant_data):
        tenant, aws, aws_two, public = tenant_data
        data = self._assemble(tenant, "security_assessment")
        content = data.extra["assessment"]
        metrics = content["summary"]["kpis"]
        # Latest scan only: old_check is gone. Open = 2 cloud + 2 app + 2 governance.
        assert metrics["open_findings"] == 6
        assert metrics["muted"] == 1 and metrics["manual_review"] == 1
        assert metrics["passed_results"] >= 1
        assert all(rule["ok"] for rule in content["accuracy"]["reconciliation"])
        states = {(row["source"], row["state"]) for row in content["coverage"]["rows"]}
        assert (str(aws_two.alias or aws_two.uid), "Not assessed") in states
        assert any(
            "no completed assessment" in w for w in content["coverage"]["warnings"]
        )
        by_check = {item.check_id: item for item in data.assessment_findings}
        assert by_check["s3_bucket_public"].triage_status == "under_review"
        assert by_check["s3_bucket_public"].resource_uid == "arn:aws:s3:::customer-data"
        assert by_check["CVE-2024-4068"].advisory["cvss_published"] == "7.5 (nvd)"
        assert by_check["CVE-2024-4068"].fix["fixed_version"] == "3.0.3"
        assert by_check["aws-access-key-id"].category == "exposed_secret"
        assert {row["framework"] for row in content["compliance"]["assessed"]} == {
            "cis_2.0_aws"
        }
        assert content["compliance"]["available_count"] > 0
        lead = content["top_risks"][0]
        assert lead["priority"] == "P0"

    def test_type_scoping(self, tenant_data):
        tenant = tenant_data[0]
        appsec = self._assemble(tenant, "appsec_assessment").extra["assessment"]
        assert appsec["summary"]["kpis"]["open_findings"] == 2
        assert appsec["compliance"] is None
        cloud = self._assemble(tenant, "cloud_assessment").extra["assessment"]
        assert cloud["summary"]["kpis"]["open_findings"] == 2
        gov = self._assemble(tenant, "governance_assessment").extra["assessment"]
        assert gov["summary"]["kpis"]["open_findings"] == 2
        assert gov["compliance"]["assessed"]

    def test_period_excludes_older_sources(self, tenant_data):
        tenant = tenant_data[0]
        data = self._assemble(
            tenant,
            "cloud_assessment",
            {
                "period": "custom",
                "date_to": (timezone.now() - timedelta(days=3)).date().isoformat(),
            },
        )
        content = data.extra["assessment"]
        # Only the five-day-old scan is inside the window.
        assert {item.check_id for item in data.assessment_findings} == {"old_check"}
        assert content["meta"]["period"]["label"].endswith(
            content["meta"]["period"]["to"][:10]
        )

    def test_provider_filter(self, tenant_data):
        tenant, aws, _, _ = tenant_data
        data = self._assemble(
            tenant, "security_assessment", {"provider_ids": [str(aws.id)]}
        )
        assert {item.provider_id for item in data.assessment_findings} == {str(aws.id)}


@pytest.mark.django_db
class TestRuns:
    def test_run_writes_pdf_csv_json_with_quality(
        self, tenants_fixture, provider_factory, report_dir
    ):
        tenant = tenants_fixture[0]
        aws = provider_factory(Provider.ProviderChoices.AWS.value)
        with rls_transaction(str(tenant.id)):
            scan = _scan(tenant.id, aws)
            source = _finding(scan, "s3_bucket_public", "critical")
        with patch("cloudsneeker_api.reports.runs.transaction.on_commit"):
            run = enqueue_report_run(
                tenant_id=str(tenant.id),
                report_type="security_assessment",
                params={"period": "30d"},
                formats=["csv", "pdf"],
            )
        result = process_report_run(tenant_id=str(tenant.id), run_id=str(run.id))
        assert result["status"] == ReportRun.Status.COMPLETED
        with rls_transaction(str(tenant.id)):
            run = ReportRun.objects.get(id=run.id)
        assert set(run.artifacts) == {"pdf", "csv", "json"}
        assert run.summary["engine_version"] == "2.0"
        assert run.summary["quality"]["status"] in ("pass", "warn"), run.summary["quality"]
        assert run.summary["quality"]["distributable"] is True
        assert run.summary["period"] == "Last 30 days"
        assert artifact_path(run, "pdf").read_bytes().startswith(b"%PDF")
        rows = list(
            csv.DictReader(
                io.StringIO(artifact_path(run, "csv").read_text(encoding="utf-8-sig"))
            )
        )
        assert rows[0]["Source record id"] == str(source.id)
        payload = read_report_json(run)
        assert payload["extra"]["assessment"]["quality"]["checks"]

    def test_run_without_pdf_still_has_quality(self, tenants_fixture, report_dir):
        tenant = tenants_fixture[0]
        with patch("cloudsneeker_api.reports.runs.transaction.on_commit"):
            run = enqueue_report_run(
                tenant_id=str(tenant.id),
                report_type="cloud_assessment",
                params={},
                formats=["csv"],
            )
        process_report_run(tenant_id=str(tenant.id), run_id=str(run.id))
        with rls_transaction(str(tenant.id)):
            run = ReportRun.objects.get(id=run.id)
        assert run.status == ReportRun.Status.COMPLETED
        assert run.summary["quality"]["status"] == "warn"


@pytest.mark.django_db
class TestRunsApi:
    def test_create_filter_and_creator_name(self, authenticated_client):
        from cloudsneeker_api.models import JSON_API_TYPE_PREFIX
        from django.urls import reverse

        body = {
            "data": {
                "type": f"{JSON_API_TYPE_PREFIX}report-runs",
                "attributes": {
                    "report_type": "cloud_assessment",
                    "params": {"period": "7d", "sections": ["roadmap"]},
                    "formats": ["pdf"],
                },
            }
        }
        with patch("cloudsneeker_api.reports.runs.transaction.on_commit"):
            created = authenticated_client.post(
                reverse("report-runs-list"), data=json.dumps(body), content_type="application/vnd.api+json"
            )
        assert created.status_code == 202, created.content
        assert created.json()["data"]["attributes"]["params"]["period"] == "7d"
        listing = authenticated_client.get(
            reverse("report-runs-list"), {"filter[report_type__in]": "cloud_assessment,appsec_assessment"}
        )
        rows = listing.json()["data"]
        assert [row["attributes"]["report_type"] for row in rows] == ["cloud_assessment"]
        assert rows[0]["attributes"]["created_by_name"]
        other = authenticated_client.get(reverse("report-runs-list"), {"filter[report_type__in]": "executive"})
        assert other.json()["data"] == []

    def test_invalid_assessment_params_are_rejected(self, authenticated_client):
        from cloudsneeker_api.models import JSON_API_TYPE_PREFIX
        from django.urls import reverse

        body = {
            "data": {
                "type": f"{JSON_API_TYPE_PREFIX}report-runs",
                "attributes": {"report_type": "security_assessment", "params": {"period": "forever"}},
            }
        }
        response = authenticated_client.post(
            reverse("report-runs-list"), data=json.dumps(body), content_type="application/vnd.api+json"
        )
        assert response.status_code == 400
