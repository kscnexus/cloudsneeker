"""Normalized records the assessment pipeline works on.

Everything here is plain data. Database rows are turned into these records in
``collect``; every later stage only reads them, which keeps scoring,
deduplication, and recommendations testable without a database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

AREA_CLOUD = "cloud"
AREA_APPSEC = "application_security"
AREA_GOVERNANCE = "governance"
AREAS: tuple[str, ...] = (AREA_CLOUD, AREA_APPSEC, AREA_GOVERNANCE)

AREA_LABELS: dict[str, str] = {
    AREA_CLOUD: "Cloud security",
    AREA_APPSEC: "Application security",
    AREA_GOVERNANCE: "Governance",
}

# Finding categories. The category drives the recommendation template and the
# appendix grouping.
CATEGORY_CLOUD_CONFIG = "cloud_configuration"
CATEGORY_VULNERABILITY = "vulnerability"
CATEGORY_MISCONFIGURATION = "iac_misconfiguration"
CATEGORY_SECRET = "exposed_secret"
CATEGORY_LICENSE = "license"
CATEGORY_CODE = "code_weakness"
CATEGORY_POLICY = "policy_violation"

CATEGORY_LABELS: dict[str, str] = {
    CATEGORY_CLOUD_CONFIG: "Cloud configuration",
    CATEGORY_VULNERABILITY: "Vulnerable dependency",
    CATEGORY_MISCONFIGURATION: "Infrastructure-as-code misconfiguration",
    CATEGORY_SECRET: "Exposed secret",
    CATEGORY_LICENSE: "License risk",
    CATEGORY_CODE: "Source code weakness",
    CATEGORY_POLICY: "Governance policy violation",
}

STATUS_FAIL = "FAIL"
STATUS_PASS = "PASS"
STATUS_MANUAL = "MANUAL"
STATUS_UNKNOWN = "UNKNOWN"

NOT_ASSESSED = "Not assessed"


@dataclass
class NormalizedFinding:
    """One scanner result in a shape shared by every area.

    Attributes:
        source_id: Primary key of the source record (``Finding.id``) or the
            governance finding UID, so every exported row traces back.
        uid: Scanner UID of the finding.
        area: ``cloud``, ``application_security``, or ``governance``.
        category: One of the ``CATEGORY_*`` values.
        scanner: Engine stream (``cloud_checks``, ``sca``, ``sast``, ``iac``,
            ``image``, ``secrets``, ``governance``...).
        provider_type: Provider kind (``aws``, ``azure``, ``repository``...).
        provider_id: Provider UUID string.
        provider_label: Alias or UID of the provider.
        account: Account, subscription, project, or target identifier.
        resource_uid: Resource identifier (ARN, file, package path...).
        resource_name: Readable resource name.
        region: Region or location (empty when the scanner has none).
        service: Cloud service or scanner class.
        check_id: Check, rule, CVE, or policy id.
        title: Short title.
        severity: ``critical`` to ``informational`` as reported by the scanner.
        status: ``FAIL``, ``PASS``, ``MANUAL``, or ``UNKNOWN``.
        muted: True when a mute rule hides the finding.
        first_seen_at: First time the issue was seen.
        last_seen_at: Last scan that reported it.
        scan_id: Scan or run the record came from.
        description: Scanner description.
        risk: Scanner or check risk statement.
        status_extended: Scanner evidence message.
        fix: ``finding_fix`` output.
        remediation_code: Check metadata remediation code by kind.
        references: Advisory or documentation links.
        advisory: Values published by an advisory and carried in the scanner
            record (for example a CVSS vector), never computed here.
        compliance: Framework ids the check maps to.
        triage_status: Triage status, ``open`` when untriaged.
        location: File and line, package path, or similar.
        duplicate_source_ids: Source ids merged into this record.
        ref: Stable report reference (``F-0001``) assigned after sorting.
    """

    source_id: str
    uid: str
    area: str
    category: str
    scanner: str
    provider_type: str
    provider_id: str
    provider_label: str
    account: str
    resource_uid: str
    resource_name: str
    region: str
    service: str
    check_id: str
    title: str
    severity: str
    status: str
    muted: bool = False
    first_seen_at: datetime | None = None
    last_seen_at: datetime | None = None
    scan_id: str = ""
    description: str = ""
    risk: str = ""
    status_extended: str = ""
    fix: dict[str, Any] = field(default_factory=dict)
    remediation_code: dict[str, str] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    advisory: dict[str, Any] = field(default_factory=dict)
    compliance: list[str] = field(default_factory=list)
    triage_status: str = "open"
    location: str = ""
    duplicate_source_ids: list[str] = field(default_factory=list)
    ref: str = ""

    @property
    def is_open(self) -> bool:
        """An open exposure: the latest result failed and no mute rule hides it.

        Triage does not close a finding here. A finding triaged as resolved
        that the latest scan still reports is still open; the triage status
        is shown beside it instead.
        """
        return self.status == STATUS_FAIL and not self.muted

    @property
    def resource_key(self) -> str:
        """Identity of the affected resource, unique across accounts."""
        resource = self.resource_uid or self.resource_name or self.uid
        return f"{self.provider_type}|{self.account}|{resource}"


@dataclass
class SourceCoverage:
    """One assessed (or expected but missing) source in the scope.

    Attributes:
        provider_id: Provider UUID string.
        provider_label: Alias or UID.
        provider_type: Provider kind.
        account: Account or target identifier.
        area: Area the source feeds.
        stream: Scanner stream (``cloud_checks``, ``sca``, policy name...).
        last_assessed_at: Completion time of the latest result in scope.
        scan_id: Latest scan or run id.
        state: ``current``, ``stale``, or ``not_assessed``.
    """

    provider_id: str
    provider_label: str
    provider_type: str
    account: str
    area: str
    stream: str
    last_assessed_at: datetime | None
    scan_id: str
    state: str


@dataclass
class ComplianceFramework:
    """Posture of one framework.

    Attributes:
        framework_id: Framework id (``cis_2.0_aws``).
        provider_types: Provider kinds the framework applies to.
        state: ``assessed`` (requirement results exist), ``enabled`` (in the
            report scope but no results), or ``available`` (offered for the
            providers in scope, not evaluated).
        passed / failed / manual / total: Requirement counts when assessed.
    """

    framework_id: str
    provider_types: list[str]
    state: str
    passed: int = 0
    failed: int = 0
    manual: int = 0
    total: int = 0

    @property
    def pass_pct(self) -> float | None:
        """Requirement pass rate over scored (pass or fail) requirements."""
        scored = self.passed + self.failed
        if self.state != "assessed" or not scored:
            return None
        return round(100.0 * self.passed / scored, 1)


@dataclass
class TrendPoint:
    """Exposure at one moment, with the coverage it was measured on.

    Attributes:
        date: ISO date.
        open_by_severity: Open failed findings per severity on that date.
        sources: Sources with a result on or before that date.
        comparable: True when ``sources`` matches the current coverage, so the
            change is a posture change, not a scope change.
    """

    date: str
    open_by_severity: dict[str, int]
    sources: int
    comparable: bool


@dataclass
class AssessmentDataset:
    """Everything collected for one report.

    Attributes:
        findings: Non-pass findings (fail, manual, unknown; muted included).
        passed: Passed results per area and severity (aggregated in SQL).
        passed_resources: Distinct resources with a passed result per area.
        coverage: Assessed and missing sources.
        compliance: Framework posture.
        trend: Coverage-aware trend points, oldest first.
        polarity_conflicts: Failed findings whose UID also passed in scope.
        truncated: True when the finding load hit its bound.
        notes: Collection notes (bounds, skipped sources).
    """

    findings: list[NormalizedFinding] = field(default_factory=list)
    passed: dict[str, dict[str, int]] = field(default_factory=dict)
    passed_resources: dict[str, int] = field(default_factory=dict)
    coverage: list[SourceCoverage] = field(default_factory=list)
    compliance: list[ComplianceFramework] = field(default_factory=list)
    trend: list[TrendPoint] = field(default_factory=list)
    polarity_conflicts: int = 0
    truncated: bool = False
    notes: list[str] = field(default_factory=list)
