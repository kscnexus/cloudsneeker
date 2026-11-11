"""Synthetic assessment datasets shared by the engine and render tests.

Each builder returns an ``AssessmentDataset`` that mirrors one real-world
shape: thousands of findings, no data, multi-cloud, multi-account,
multi-framework, stale and partial coverage, history with a scope change,
duplicates, and findings without evidence. ``samples`` lists them for the CI
job that renders example PDFs to images.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from cloudsneeker_api.reports.assessment.model import (
    AREA_APPSEC,
    AREA_CLOUD,
    AREA_GOVERNANCE,
    CATEGORY_CLOUD_CONFIG,
    CATEGORY_CODE,
    CATEGORY_LICENSE,
    CATEGORY_MISCONFIGURATION,
    CATEGORY_POLICY,
    CATEGORY_SECRET,
    CATEGORY_VULNERABILITY,
    AssessmentDataset,
    ComplianceFramework,
    NormalizedFinding,
    SourceCoverage,
    TrendPoint,
)

NOW = datetime(2026, 11, 9, 9, 0, tzinfo=UTC)
SEVERITIES = ("critical", "high", "medium", "low", "informational")


def finding(**overrides) -> NormalizedFinding:
    """One finding with sensible defaults."""
    values = {
        "source_id": "00000000-0000-0000-0000-000000000001",
        "uid": "uid-1",
        "area": AREA_CLOUD,
        "category": CATEGORY_CLOUD_CONFIG,
        "scanner": "cloud_checks",
        "provider_type": "aws",
        "provider_id": "p-aws-1",
        "provider_label": "production-aws",
        "account": "111111111111",
        "resource_uid": "arn:aws:s3:::customer-data",
        "resource_name": "customer-data",
        "region": "eu-west-1",
        "service": "s3",
        "check_id": "s3_bucket_public_access",
        "title": "S3 bucket allows public access",
        "severity": "high",
        "status": "FAIL",
        "first_seen_at": NOW - timedelta(days=20),
        "last_seen_at": NOW - timedelta(days=1),
        "scan_id": "scan-1",
        "description": "The bucket policy grants read access to everyone.",
        "risk": "Public buckets can expose customer data.",
        "status_extended": "Bucket customer-data has a public read policy.",
        "fix": {
            "fix_available": True,
            "fix_summary": "Block public access on the bucket.",
        },
        "remediation_code": {
            "cli": "aws s3api put-public-access-block --bucket <BUCKET_NAME> "
            "--public-access-block-configuration BlockPublicAcls=true",
        },
    }
    values.update(overrides)
    return NormalizedFinding(**values)


def coverage(
    label: str,
    area: str,
    *,
    days_old: float | None = 1,
    provider_type: str = "aws",
    stream: str = "cloud_checks",
) -> SourceCoverage:
    assessed = None if days_old is None else NOW - timedelta(days=days_old)
    state = (
        "not_assessed" if assessed is None else ("stale" if days_old > 7 else "current")
    )
    return SourceCoverage(
        provider_id=f"p-{label}",
        provider_label=label,
        provider_type=provider_type,
        account=label,
        area=area,
        stream=stream,
        last_assessed_at=assessed,
        scan_id="" if assessed is None else f"scan-{label}",
        state=state,
    )


def _trend(points: int = 11, change_at: int | None = None) -> list[TrendPoint]:
    result = []
    for index in range(points):
        day = (NOW - timedelta(days=3 * (points - 1 - index))).date().isoformat()
        base = 140 - index * 6
        result.append(
            TrendPoint(
                date=day,
                open_by_severity={
                    "critical": max(0, 9 - index // 2),
                    "high": max(2, 30 - index),
                    "medium": base // 2,
                    "low": base // 3,
                    "informational": 3,
                },
                sources=3 if change_at is None or index >= change_at else 2,
                comparable=change_at is None or index >= change_at,
            )
        )
    return result


def empty_dataset() -> AssessmentDataset:
    """No source has ever been assessed."""
    return AssessmentDataset(
        coverage=[coverage("new-aws-account", AREA_CLOUD, days_old=None)]
    )


def multi_cloud_dataset(count: int = 240, seed: int = 7) -> AssessmentDataset:
    """Cloud, application, and governance across several accounts and clouds."""
    rng = random.Random(seed)
    accounts = [
        ("aws", "production-aws", "111111111111"),
        ("aws", "staging-aws", "222222222222"),
        ("azure", "corp-azure", "sub-3c1e"),
        ("gcp", "analytics-gcp", "analytics-prod"),
    ]
    cloud_checks = [
        ("iam_root_mfa_enabled", "Root account has no MFA", "critical", "iam"),
        (
            "s3_bucket_public_access",
            "Storage bucket allows public access",
            "high",
            "s3",
        ),
        (
            "ec2_securitygroup_allow_ingress_from_internet_to_port_22",
            "SSH open to the internet",
            "high",
            "ec2",
        ),
        (
            "cloudtrail_multi_region_enabled",
            "Audit logging is not enabled in every region",
            "medium",
            "cloudtrail",
        ),
        ("kms_cmk_rotation_enabled", "Key rotation is disabled", "medium", "kms"),
        (
            "ec2_instance_imdsv2_enabled",
            "Instance metadata v1 is allowed",
            "low",
            "ec2",
        ),
        (
            "account_security_contact_set",
            "No security contact is registered",
            "informational",
            "account",
        ),
    ]
    findings: list[NormalizedFinding] = []
    for index in range(count):
        provider_type, label, account = rng.choice(accounts)
        check, title, severity, service = rng.choice(cloud_checks)
        findings.append(
            finding(
                source_id=f"cloud-{index:05d}",
                uid=f"cloud-{check}-{index}",
                provider_type=provider_type,
                provider_label=label,
                account=account,
                resource_uid=f"{provider_type}:{service}:{label}:res-{index % 97}",
                resource_name=f"{service}-res-{index % 97}",
                region=rng.choice(
                    ["eu-west-1", "us-east-1", "westeurope", "europe-west1"]
                ),
                service=service,
                check_id=check,
                title=title,
                severity=severity,
                muted=index % 53 == 0,
                first_seen_at=NOW - timedelta(days=rng.randint(1, 120)),
                compliance=["cis_2.0_aws"],
            )
        )
    app = [
        (
            CATEGORY_VULNERABILITY,
            "CVE-2024-45337",
            "critical",
            "golang.org/x/crypto",
            "0.21.0",
            "0.31.0",
            "pkg:golang/golang.org/x/crypto@0.21.0",
        ),
        (
            CATEGORY_VULNERABILITY,
            "CVE-2023-44487",
            "high",
            "golang.org/x/net",
            "0.10.0",
            "0.17.0",
            "pkg:golang/golang.org/x/net@0.10.0",
        ),
        (
            CATEGORY_VULNERABILITY,
            "CVE-2024-4068",
            "high",
            "braces",
            "3.0.2",
            "3.0.3",
            "pkg:npm/braces@3.0.2",
        ),
        (
            CATEGORY_VULNERABILITY,
            "CVE-2024-6345",
            "medium",
            "setuptools",
            "65.5.0",
            "70.0.0",
            "pkg:pypi/setuptools@65.5.0",
        ),
        (
            CATEGORY_VULNERABILITY,
            "CVE-2025-0001",
            "high",
            "legacy-lib",
            "1.0.0",
            "",
            "pkg:npm/legacy-lib@1.0.0",
        ),
    ]
    for index in range(count // 3):
        category, check, severity, package, installed, fixed, purl = app[
            index % len(app)
        ]
        target = f"repo-{index % 6}"
        findings.append(
            finding(
                source_id=f"app-{index:05d}",
                uid=f"trivy-repo-{check}-{package}-{target}",
                area=AREA_APPSEC,
                category=category,
                scanner="repo",
                provider_type="iac",
                provider_label=f"github.com/acme/{target}",
                account=f"github.com/acme/{target}",
                resource_uid=f"{target}/go.sum:{package}",
                resource_name=package,
                region="",
                service="lang-pkgs",
                check_id=check,
                title=f"{package}: vulnerable version",
                severity=severity,
                location=f"{package} {installed}",
                fix={
                    "fix_available": bool(fixed),
                    "fix_summary": f"Upgrade {package} from {installed} to {fixed} or later."
                    if fixed
                    else "",
                    "installed_version": installed,
                    "fixed_version": fixed,
                    "package": package,
                    "purl": purl,
                },
                remediation_code={},
                advisory={"cvss_published": "9.1 (nvd)", "cvss_vector": "CVSS:3.1/AV:N"}
                if severity == "critical"
                else {},
                references=["https://avd.example.org/nvd/" + check.lower()],
            )
        )
    findings += [
        finding(
            source_id="secret-1",
            uid="trivy-repo-secret-aws-access-key-id-repo-1",
            area=AREA_APPSEC,
            category=CATEGORY_SECRET,
            scanner="repo",
            provider_type="iac",
            provider_label="github.com/acme/repo-1",
            account="github.com/acme/repo-1",
            resource_uid="deploy/config.env",
            resource_name="deploy/config.env",
            location="deploy/config.env:12",
            check_id="aws-access-key-id",
            title="AWS access key in source",
            severity="critical",
            fix={
                "fix_available": True,
                "fix_summary": "Revoke and rotate this credential.",
            },
            remediation_code={},
        ),
        finding(
            source_id="sast-1",
            uid="opengrep-sast-python.sqli-app/db.py:40-40",
            area=AREA_APPSEC,
            category=CATEGORY_CODE,
            scanner="sast",
            provider_type="iac",
            provider_label="github.com/acme/api",
            account="github.com/acme/api",
            resource_uid="app/db.py",
            resource_name="app/db.py",
            location="app/db.py:40",
            check_id="python.sqlalchemy.security.sqli",
            title="SQL built from string formatting",
            severity="high",
            fix={"fix_available": True, "fix_summary": "Use bound parameters."},
            remediation_code={},
        ),
        finding(
            source_id="iac-1",
            uid="trivy-iac-AVD-AWS-0086-main.tf",
            area=AREA_APPSEC,
            category=CATEGORY_MISCONFIGURATION,
            scanner="iac",
            provider_type="iac",
            provider_label="github.com/acme/infra",
            account="github.com/acme/infra",
            resource_uid="terraform/main.tf",
            resource_name="terraform/main.tf",
            location="terraform/main.tf:22",
            check_id="AVD-AWS-0086",
            title="S3 bucket does not block public ACLs",
            severity="high",
            fix={"fix_available": True, "fix_summary": "Set block_public_acls = true."},
            remediation_code={},
        ),
        finding(
            source_id="lic-1",
            uid="trivy-repo-license-AGPL-3.0-x",
            area=AREA_APPSEC,
            category=CATEGORY_LICENSE,
            scanner="repo",
            provider_type="iac",
            provider_label="github.com/acme/api",
            account="github.com/acme/api",
            resource_uid="go.mod:x",
            resource_name="x",
            check_id="license-AGPL-3.0",
            title="x uses the AGPL-3.0 license (restricted)",
            severity="medium",
            fix={
                "fix_available": True,
                "fix_summary": "Confirm the license is allowed.",
            },
            remediation_code={},
        ),
    ]
    for index in range(18):
        findings.append(
            finding(
                source_id=f"custodian-gov-{index}",
                uid=f"custodian-gov-{index}",
                area=AREA_GOVERNANCE,
                category=CATEGORY_POLICY,
                scanner="governance",
                provider_label="production-aws",
                resource_uid=f"vol-{index:04d}",
                resource_name=f"vol-{index:04d}",
                service="aws.ebs",
                check_id="unencrypted-ebs-volumes"
                if index % 2
                else "untagged-instances",
                title="Unencrypted EBS volume"
                if index % 2
                else "Instance missing owner tag",
                severity="high" if index % 2 else "low",
                status_extended="Matched by policy baseline.",
                fix={"fix_available": False, "fix_summary": ""},
                remediation_code={},
            )
        )
    dataset = AssessmentDataset(
        findings=findings,
        passed={
            AREA_CLOUD: {
                "critical": 40,
                "high": 310,
                "medium": 520,
                "low": 210,
                "informational": 30,
            },
            AREA_GOVERNANCE: {
                "critical": 0,
                "high": 2,
                "medium": 4,
                "low": 1,
                "informational": 0,
            },
        },
        passed_resources={AREA_CLOUD: 412},
        coverage=[
            coverage("production-aws", AREA_CLOUD, days_old=1),
            coverage("staging-aws", AREA_CLOUD, days_old=2),
            coverage("corp-azure", AREA_CLOUD, days_old=1, provider_type="azure"),
            coverage("analytics-gcp", AREA_CLOUD, days_old=1, provider_type="gcp"),
            *[
                coverage(
                    f"github.com/acme/repo-{i}",
                    AREA_APPSEC,
                    days_old=1,
                    provider_type="iac",
                    stream="repo",
                )
                for i in range(6)
            ],
            coverage(
                "github.com/acme/api",
                AREA_APPSEC,
                days_old=1,
                provider_type="iac",
                stream="sast",
            ),
            coverage(
                "production-aws",
                AREA_GOVERNANCE,
                days_old=1,
                stream="unencrypted-ebs-volumes",
            ),
            coverage(
                "production-aws",
                AREA_GOVERNANCE,
                days_old=1,
                stream="untagged-instances",
            ),
        ],
        compliance=[
            ComplianceFramework(
                "cis_2.0_aws",
                ["aws"],
                "assessed",
                passed=41,
                failed=12,
                manual=6,
                total=59,
            ),
            ComplianceFramework(
                "iso27001_2022_aws",
                ["aws"],
                "assessed",
                passed=58,
                failed=21,
                manual=14,
                total=93,
            ),
            ComplianceFramework(
                "soc2_azure",
                ["azure"],
                "assessed",
                passed=33,
                failed=4,
                manual=9,
                total=46,
            ),
            ComplianceFramework("pci_4.0_aws", ["aws"], "enabled"),
            *[
                ComplianceFramework(f"framework_{i}_gcp", ["gcp"], "available")
                for i in range(14)
            ],
        ],
        trend=_trend(),
    )
    return dataset


def large_dataset(count: int = 6000) -> AssessmentDataset:
    """Thousands of findings across every area."""
    return multi_cloud_dataset(count=count, seed=11)


def stale_partial_dataset() -> AssessmentDataset:
    """Stale accounts, a missing account, and a coverage change in the trend."""
    dataset = multi_cloud_dataset(count=60, seed=3)
    # Governance was never run in this scope: no records, no coverage.
    dataset.findings = [
        item for item in dataset.findings if item.area != AREA_GOVERNANCE
    ]
    dataset.passed.pop(AREA_GOVERNANCE, None)
    dataset.coverage = [
        coverage("production-aws", AREA_CLOUD, days_old=21),
        coverage("staging-aws", AREA_CLOUD, days_old=None),
        coverage("corp-azure", AREA_CLOUD, days_old=2, provider_type="azure"),
        coverage(
            "github.com/acme/repo-1",
            AREA_APPSEC,
            days_old=40,
            provider_type="iac",
            stream="repo",
        ),
    ]
    dataset.trend = _trend(change_at=6)
    dataset.notes.append("cloud: example collection note.")
    return dataset


def duplicates_dataset() -> AssessmentDataset:
    """The same finding reported by two scans of one stream, plus a pass/fail conflict."""
    first = finding(
        source_id="dup-a",
        last_seen_at=NOW - timedelta(days=3),
        first_seen_at=NOW - timedelta(days=30),
    )
    second = finding(
        source_id="dup-b",
        last_seen_at=NOW - timedelta(days=1),
        first_seen_at=NOW - timedelta(days=5),
    )
    passing = finding(source_id="dup-pass", status="PASS")
    other = finding(
        source_id="other", resource_uid="arn:aws:s3:::logs", resource_name="logs"
    )
    return AssessmentDataset(
        findings=[first, second, passing, other],
        coverage=[coverage("production-aws", AREA_CLOUD)],
    )


def missing_evidence_dataset() -> AssessmentDataset:
    """Findings without description, evidence, fix, or resource."""
    bare = finding(
        source_id="bare-1",
        description="",
        risk="",
        status_extended="",
        fix={},
        remediation_code={},
        resource_uid="",
        resource_name="",
        first_seen_at=None,
        severity="critical",
    )
    unknown = finding(source_id="unknown-1", status="UNKNOWN", check_id="weird_check")
    return AssessmentDataset(
        findings=[bare, unknown], coverage=[coverage("production-aws", AREA_CLOUD)]
    )


def samples() -> dict[str, AssessmentDataset]:
    """Named datasets rendered to sample PDFs in CI."""
    return {
        "typical": multi_cloud_dataset(),
        "large": large_dataset(3000),
        "stale-partial": stale_partial_dataset(),
        "empty": empty_dataset(),
    }
