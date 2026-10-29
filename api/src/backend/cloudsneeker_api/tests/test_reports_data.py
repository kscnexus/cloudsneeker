"""Report data assembly against real Scan / Finding / Compliance rows."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from api.db_utils import rls_transaction
from api.models import (
    ComplianceOverviewSummary,
    ComplianceRequirementOverview,
    Finding,
    Provider,
    Scan,
    StateChoices,
)
from cloudsneeker_api.models import CustodianPolicy, CustodianRun
from cloudsneeker_api.reports.catalog import REPORT_TYPES
from cloudsneeker_api.reports.data import assemble_report
from cloudsneeker_api.reports.data.common import (
    CLOUD_SCOPE,
    ScanScope,
    latest_scan_ids,
)
from cloudsneeker_api.reports.schema import ReportFilters

NOW = datetime(2026, 10, 28, 12, 0, tzinfo=UTC)

POLICY_YAML = """
policies:
  - name: unused-ebs
    resource: aws.ebs
"""


def _scan(tenant_id, provider, *, completed_at=NOW, scanner_args=None, state=StateChoices.COMPLETED):
    return Scan.objects.create(
        tenant_id=tenant_id,
        provider=provider,
        name="report scan",
        trigger=Scan.TriggerChoices.MANUAL,
        state=state,
        started_at=completed_at,
        completed_at=completed_at,
        scanner_args=scanner_args or {},
    )


def _trivy(tenant_id, provider, mode, **kwargs):
    return _scan(
        tenant_id, provider, scanner_args={"source": "trivy_hub", "mode": mode}, **kwargs
    )


def _finding(
    scan,
    check_id,
    severity="high",
    *,
    status="FAIL",
    muted=False,
    raw=None,
    services=None,
    categories=None,
    compliance=None,
    metadata=None,
):
    return Finding.objects.create(
        tenant_id=scan.tenant_id,
        uid=f"{check_id}-{uuid4()}",
        scan=scan,
        status=status,
        status_extended=f"{check_id} detail",
        severity=severity,
        impact=severity,
        raw_result=raw or {},
        check_id=check_id,
        check_metadata=metadata or {"CheckTitle": f"Title {check_id}"},
        muted=muted,
        resource_services=services,
        categories=categories,
        compliance=compliance or {},
        first_seen_at=NOW,
    )


def _assemble(tenant, report_type, **filters):
    with rls_transaction(str(tenant.id)):
        return assemble_report(str(tenant.id), report_type, ReportFilters(**filters))


@pytest.mark.django_db
class TestEmptyTenant:
    @pytest.mark.parametrize("report_type", sorted(REPORT_TYPES))
    def test_every_report_has_an_empty_state(self, tenants_fixture, report_type):
        tenant = tenants_fixture[0]
        filters = {"compliance_id": "cis_2.0_aws"} if report_type == "compliance" else {}
        data = _assemble(tenant, report_type, **filters)
        assert data.report_type == report_type
        assert data.is_empty
        assert data.headline
        assert data.grade == "N/A"

    def test_sast_empty_state_explains_setup(self, tenants_fixture):
        data = _assemble(tenants_fixture[0], "sast")
        assert "SAST mode" in data.empty_state


@pytest.mark.django_db
class TestScanSelection:
    def test_cloud_scope_uses_latest_scan_per_provider(self, tenants_fixture, provider_factory):
        tenant = tenants_fixture[0]
        aws = provider_factory(Provider.ProviderChoices.AWS.value)
        k8s = provider_factory(Provider.ProviderChoices.KUBERNETES.value)
        _scan(tenant.id, aws, completed_at=NOW - timedelta(days=2))
        latest = _scan(tenant.id, aws)
        _scan(tenant.id, aws, state=StateChoices.EXECUTING, completed_at=None)
        # Trivy Hub k8s scans are application security, not cloud posture.
        _trivy(tenant.id, k8s, "k8s")
        with rls_transaction(str(tenant.id)):
            ids = latest_scan_ids(str(tenant.id), ReportFilters(), CLOUD_SCOPE)
        assert ids == [latest.id]

    def test_appsec_scope_keeps_one_scan_per_stream(self, tenants_fixture, provider_factory):
        tenant = tenants_fixture[0]
        repo = provider_factory(Provider.ProviderChoices.IAC.value)
        _trivy(tenant.id, repo, "repo", completed_at=NOW - timedelta(days=1))
        repo_latest = _trivy(tenant.id, repo, "repo")
        sbom = _trivy(tenant.id, repo, "sbom")
        # A plain IaC scan shares the "iac" stream with Trivy Hub iac targets.
        _scan(tenant.id, repo, completed_at=NOW - timedelta(days=3))
        iac_latest = _trivy(tenant.id, repo, "iac", completed_at=NOW - timedelta(hours=1))
        scope = ScanScope(
            trivy_modes=frozenset({"repo", "sbom", "iac"}),
            prowler_provider_types=frozenset({"iac"}),
        )
        with rls_transaction(str(tenant.id)):
            ids = latest_scan_ids(str(tenant.id), ReportFilters(), scope)
        assert set(ids) == {repo_latest.id, sbom.id, iac_latest.id}

    def test_provider_and_date_filters(self, tenants_fixture, provider_factory):
        tenant = tenants_fixture[0]
        first = provider_factory(Provider.ProviderChoices.AWS.value)
        second = provider_factory(Provider.ProviderChoices.AWS.value)
        old = _scan(tenant.id, first, completed_at=NOW - timedelta(days=30))
        _scan(tenant.id, first)
        _scan(tenant.id, second)
        filters = ReportFilters(
            provider_ids=[str(first.id)], date_to=NOW - timedelta(days=10)
        )
        with rls_transaction(str(tenant.id)):
            ids = latest_scan_ids(str(tenant.id), filters, CLOUD_SCOPE)
        assert ids == [old.id]


@pytest.mark.django_db
class TestCloudPosture:
    def test_counts_latest_scan_and_ranks_risks(self, tenants_fixture, provider_factory):
        tenant = tenants_fixture[0]
        aws = provider_factory(Provider.ProviderChoices.AWS.value)
        old = _scan(tenant.id, aws, completed_at=NOW - timedelta(days=1))
        _finding(old, "old_check", "critical")
        scan = _scan(tenant.id, aws)
        _finding(scan, "iam_root_mfa", "critical", metadata={
            "CheckTitle": "Root MFA",
            "Risk": "Account takeover.",
            "Remediation": {"Recommendation": {"Text": "Enable MFA."}},
        })
        _finding(scan, "s3_public", "high")
        _finding(scan, "s3_public", "high")
        _finding(scan, "ec2_imdsv2", "medium")
        _finding(scan, "ec2_imdsv2", "medium", muted=True)
        _finding(scan, "cloudtrail_on", "high", status="PASS")
        ComplianceOverviewSummary.objects.create(
            tenant_id=tenant.id,
            scan=scan,
            compliance_id="cis_2.0_aws",
            requirements_passed=3,
            requirements_failed=1,
            requirements_manual=0,
            total_requirements=4,
        )

        data = _assemble(tenant, "cloud_posture")

        assert not data.is_empty
        assert data.status_totals == {"pass": 1, "fail": 4, "muted": 1, "manual": 0}
        assert data.severity_totals["critical"] == 1
        assert data.severity_totals["high"] == 2
        assert data.kpis["scans_in_scope"] == 1
        assert data.top_risks[0]["check_id"] == "iam_root_mfa"
        assert data.top_risks[0]["impact"] == "Account takeover."
        assert data.top_risks[0]["remediation"] == "Enable MFA."
        assert data.top_risks[1]["check_id"] == "s3_public"
        assert data.top_risks[1]["findings"] == 2
        assert data.remediation[0]["priority"] == 1
        assert data.compliance[0]["compliance_id"] == "cis_2.0_aws"
        assert data.compliance[0]["pass_pct"] == 75.0
        assert data.sources[0]["fail"] == 4
        assert data.score is not None and 0 < data.score < 100
        findings = next(t for t in data.tables if t.key == "findings")
        assert findings.total == 4
        assert findings.rows[0]["severity"] == "critical"
        assert "old_check" not in {row["check_id"] for row in findings.rows}
        assert data.trend and data.trend[-1]["fail"] == 4

    def test_severity_floor(self, tenants_fixture, provider_factory):
        tenant = tenants_fixture[0]
        scan = _scan(tenant.id, provider_factory(Provider.ProviderChoices.AWS.value))
        _finding(scan, "a", "critical")
        _finding(scan, "b", "medium")
        data = _assemble(tenant, "cloud_posture", severity_floor="high")
        assert data.status_totals["fail"] == 1
        assert data.severity_totals["medium"] == 0


@pytest.mark.django_db
class TestApplicationSecurityReports:
    @pytest.fixture
    def repo_scan(self, tenants_fixture, provider_factory):
        tenant = tenants_fixture[0]
        repo = provider_factory(Provider.ProviderChoices.IAC.value)
        scan = _trivy(tenant.id, repo, "repo")
        _finding(
            scan,
            "CVE-2024-0001",
            "critical",
            raw={
                "VulnerabilityID": "CVE-2024-0001",
                "PkgName": "lodash",
                "InstalledVersion": "4.17.0",
                "FixedVersion": "4.17.21",
            },
            services=["lang-pkgs"],
        )
        _finding(
            scan,
            "AVD-AWS-0086",
            "high",
            raw={"ID": "AVD-AWS-0086", "AVDID": "AVD-AWS-0086"},
            services=["config"],
        )
        _finding(
            scan,
            "aws-access-key-id",
            "critical",
            raw={"RuleID": "aws-access-key-id", "Category": "AWS", "StartLine": 3},
            services=["secret"],
        )
        return tenant, scan

    def test_sca_keeps_vulnerabilities_only(self, repo_scan):
        tenant, _ = repo_scan
        data = _assemble(tenant, "sca")
        assert data.status_totals["fail"] == 1
        row = next(t for t in data.tables if t.key == "findings").rows[0]
        assert row["cve"] == "CVE-2024-0001"
        assert row["fixed_version"] == "4.17.21"
        assert data.kpis["fixable_in_table"] == 1
        assert data.top_risks[0]["remediation"] == "Upgrade lodash to 4.17.21 or later."

    def test_iac_keeps_misconfigurations_only(self, repo_scan):
        tenant, _ = repo_scan
        data = _assemble(tenant, "iac")
        assert data.status_totals["fail"] == 1
        assert data.top_risks[0]["check_id"] == "AVD-AWS-0086"

    def test_secrets_across_sources(self, repo_scan, provider_factory):
        tenant, _ = repo_scan
        cloud = _scan(tenant.id, provider_factory(Provider.ProviderChoices.AWS.value))
        _finding(cloud, "awslambda_function_no_secrets_in_variables", "critical", categories=["secrets"])
        _finding(cloud, "s3_public", "high")
        data = _assemble(tenant, "secrets")
        assert data.status_totals["fail"] == 2
        rows = next(t for t in data.tables if t.key == "findings").rows
        assert {row["check_id"] for row in rows} == {
            "aws-access-key-id",
            "awslambda_function_no_secrets_in_variables",
        }

    def test_container_split(self, tenants_fixture, provider_factory):
        tenant = tenants_fixture[0]
        image = provider_factory(Provider.ProviderChoices.IMAGE.value)
        scan = _trivy(tenant.id, image, "image")
        _finding(scan, "CVE-2023-1", "high", raw={"VulnerabilityID": "CVE-2023-1"})
        _finding(scan, "generic-secret", "medium", raw={"RuleID": "generic-secret"}, services=["secret"])
        _finding(scan, "DS002", "low", raw={"ID": "DS002"})
        data = _assemble(tenant, "container")
        assert data.kpis["vulnerabilities"] == 1
        assert data.kpis["secrets"] == 1
        assert data.kpis["misconfigurations"] == 1
        assert data.kpis["images_in_scope"] == 1

    def test_sast_reads_sast_mode(self, tenants_fixture, provider_factory):
        tenant = tenants_fixture[0]
        repo = provider_factory(Provider.ProviderChoices.IAC.value)
        scan = _trivy(tenant.id, repo, "sast")
        _finding(scan, "python.eval", "high", raw={"path": "app.py", "start": {"line": 9}})
        data = _assemble(tenant, "sast")
        assert not data.is_empty
        assert next(t for t in data.tables if t.key == "findings").rows[0]["location"] == "app.py:9"


@pytest.mark.django_db
class TestComplianceReport:
    def test_combines_regions_and_maps_findings(self, tenants_fixture, provider_factory):
        tenant = tenants_fixture[0]
        scan = _scan(tenant.id, provider_factory(Provider.ProviderChoices.AWS.value))
        common = {
            "tenant_id": tenant.id,
            "scan": scan,
            "compliance_id": "cis_2.0_aws",
            "framework": "CIS",
            "version": "2.0",
            "description": "desc",
            "passed_checks": 1,
            "failed_checks": 0,
            "total_checks": 1,
        }
        ComplianceRequirementOverview.objects.create(
            **common, region="us-east-1", requirement_id="1.1", requirement_status="PASS",
            passed_findings=2, total_findings=2,
        )
        ComplianceRequirementOverview.objects.create(
            **{**common, "failed_checks": 1}, region="eu-west-1", requirement_id="1.1",
            requirement_status="FAIL", passed_findings=0, total_findings=1,
        )
        ComplianceRequirementOverview.objects.create(
            **common, region="us-east-1", requirement_id="1.2", requirement_status="PASS",
            passed_findings=1, total_findings=1,
        )
        _finding(scan, "iam_root_mfa", "critical", compliance={"CIS-2.0": ["1.1"]})
        _finding(scan, "unmapped", "critical", compliance={"ISO27001-2022": ["A.5"]})

        data = _assemble(tenant, "compliance", compliance_id="cis_2.0_aws")

        assert data.kpis["requirements"] == 2
        assert data.kpis["requirements_failed"] == 1
        assert data.kpis["pass_pct"] == 50.0
        requirements = next(t for t in data.tables if t.key == "requirements").rows
        assert requirements[0]["requirement_id"] == "1.1"
        assert requirements[0]["status"] == "FAIL"
        assert requirements[0]["failed_findings"] == 1
        assert requirements[0]["passed_findings"] == 2
        findings = next(t for t in data.tables if t.key == "findings")
        assert [row["check_id"] for row in findings.rows] == ["iam_root_mfa"]
        assert data.title == "Compliance Report: CIS 2.0"

    def test_pinned_scan_outside_providers_is_empty(self, tenants_fixture, provider_factory):
        tenant = tenants_fixture[0]
        scan = _scan(tenant.id, provider_factory(Provider.ProviderChoices.AWS.value))
        data = _assemble(
            tenant,
            "compliance",
            compliance_id="cis_2.0_aws",
            scan_id=str(scan.id),
            provider_ids=[str(uuid4())],
        )
        assert data.is_empty


@pytest.mark.django_db
class TestGovernanceAndExecutive:
    def _policy_run(self, tenant, provider, *, count, finished_at, delta=None, name="unused-ebs"):
        with rls_transaction(str(tenant.id)):
            policy = CustodianPolicy.objects.filter(tenant_id=tenant.id, name=name).first()
            if policy is None:
                policy = CustodianPolicy.objects.create(
                    tenant_id=tenant.id, name=name, policy_yaml=POLICY_YAML, provider=provider
                )
            return CustodianRun.objects.create(
                tenant_id=tenant.id,
                policy=policy,
                provider=provider,
                status=CustodianRun.Status.COMPLETED,
                finished_at=finished_at,
                summary={
                    "resource_count": count,
                    "delta": delta or {"new_count": 0, "gone_count": 0},
                    "resources_preview": [
                        {"uid": "vol-1", "name": "data", "region": "us-east-1", "type": "ebs"}
                    ],
                },
            )

    def test_governance_uses_latest_run_per_policy(self, tenants_fixture, aws_provider):
        tenant = tenants_fixture[0]
        self._policy_run(tenant, aws_provider, count=9, finished_at=NOW - timedelta(days=1))
        self._policy_run(
            tenant, aws_provider, count=2, finished_at=NOW, delta={"new_count": 1, "gone_count": 3}
        )
        self._policy_run(tenant, aws_provider, count=0, finished_at=NOW, name="clean-policy")
        data = _assemble(tenant, "governance")
        assert data.kpis == {
            "policies_evaluated": 2,
            "policies_with_matches": 1,
            "matched_resources": 2,
            "new_since_last_run": 1,
            "resolved_since_last_run": 3,
        }
        assert data.score == 50.0
        assert data.top_risks[0]["check_id"] == "unused-ebs"
        resources = next(t for t in data.tables if t.key == "resources").rows
        assert resources[0]["uid"] == "vol-1"

    def test_executive_combines_domains(self, tenants_fixture, provider_factory):
        tenant = tenants_fixture[0]
        aws = provider_factory(Provider.ProviderChoices.AWS.value)
        cloud = _scan(tenant.id, aws)
        _finding(cloud, "iam_root_mfa", "critical")
        _finding(cloud, "cloudtrail_on", "high", status="PASS")
        repo = provider_factory(Provider.ProviderChoices.IAC.value)
        app = _trivy(tenant.id, repo, "repo")
        _finding(app, "CVE-2024-9", "high", raw={"VulnerabilityID": "CVE-2024-9"})
        _finding(app, "gh-token", "critical", raw={"RuleID": "gh-token"}, services=["secret"])
        ComplianceOverviewSummary.objects.create(
            tenant_id=tenant.id,
            scan=cloud,
            compliance_id="cis_2.0_aws",
            requirements_passed=1,
            requirements_failed=1,
            total_requirements=2,
        )

        data = _assemble(tenant, "executive")

        assert not data.is_empty
        assert data.grade in {"A", "B", "C", "D", "F"}
        assert data.kpis["open_issues"] == 3
        assert data.kpis["critical"] == 2
        assert data.kpis["secrets_open"] == 1
        assert data.kpis["compliance_pct"] == 50.0
        assert len(data.top_risks) <= 5
        assert data.top_risks[0]["severity"] == "critical"
        assert {row["domain"] for row in data.sources} == {
            "cloud",
            "application",
            "compliance",
            "governance",
        }
        assert data.headline.startswith(f"Overall security grade {data.grade}")
        assert data.remediation[0]["action"].startswith("Fix the 2 critical issue(s)")
        assert any("secret" in item["action"] for item in data.remediation)
