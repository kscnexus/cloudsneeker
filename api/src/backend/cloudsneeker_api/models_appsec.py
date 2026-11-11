"""Application security posture management (ASPM) tables.

The scan engine keeps writing the shared ``Scan`` / ``Finding`` rows, so the
existing reports, alerts, triage and integrations are unchanged. These tables
add what a per-scan row cannot hold: one persistent finding per target with a
detection lifecycle, the software inventory (SBOM and components) of each
scan, reusable scan profiles, tenant policies and risk settings.

Triage (status, notes, assignee) stays on ``FindingTriage``, keyed by
``AppSecFinding.uid``; it is not duplicated here.
"""

from uuid import uuid4

from api.rls import RowLevelSecurityConstraint
from django.conf import settings
from django.core.validators import MinLengthValidator
from django.db import models

# ``models`` imports this module at its end, after these names exist.
from cloudsneeker_api.models import (  # isort: skip
    JSON_API_TYPE_PREFIX,
    TABLE_PREFIX,
    CloudsneekerRLSModel,
    TrivyRun,
    TrivyTarget,
)


def _rls(name: str = "rls_on_%(class)s") -> RowLevelSecurityConstraint:
    return RowLevelSecurityConstraint(
        field="tenant_id",
        name=name,
        statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
    )


class AppSecApplication(CloudsneekerRLSModel):
    """A business application; groups the assets (targets) scanned for it."""

    class Criticality(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class Environment(models.TextChoices):
        PRODUCTION = "production", "Production"
        STAGING = "staging", "Staging"
        DEVELOPMENT = "development", "Development"
        TEST = "test", "Test"
        UNKNOWN = "unknown", "Unknown"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    name = models.CharField(max_length=100, validators=[MinLengthValidator(2)])
    description = models.TextField(blank=True, default="")
    owner = models.CharField(max_length=200, blank=True, default="")
    criticality = models.CharField(
        max_length=16, choices=Criticality.choices, default=Criticality.MEDIUM
    )
    environment = models.CharField(
        max_length=16, choices=Environment.choices, default=Environment.UNKNOWN
    )
    # ``None`` means not stated; the risk score then ignores exposure.
    internet_exposed = models.BooleanField(null=True, blank=True)
    tags = models.JSONField(default=list, blank=True)
    # ``builtin:<key>`` or a scan profile id; targets without their own
    # profile use it.
    default_profile_ref = models.CharField(max_length=64, blank=True, default="")

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}appsec_applications"
        constraints = [
            _rls(),
            models.UniqueConstraint(
                fields=("tenant_id", "name"),
                name="unique_cs_appsec_app_name_per_tenant",
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}appsec-applications"


class AppSecScanProfile(CloudsneekerRLSModel):
    """Reusable scan options. Built-in profiles live in code, not here."""

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    name = models.CharField(max_length=100, validators=[MinLengthValidator(3)])
    description = models.TextField(blank=True, default="")
    # Target types the profile applies to; empty means every type its
    # scanners support.
    target_types = models.JSONField(default=list, blank=True)
    # Validated by ``appsec.options.validate_options``.
    options = models.JSONField(default=dict, blank=True)
    enabled = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_appsec_scan_profiles",
    )

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}appsec_scan_profiles"
        constraints = [
            _rls(),
            models.UniqueConstraint(
                fields=("tenant_id", "name"),
                name="unique_cs_appsec_profile_name_per_tenant",
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}appsec-scan-profiles"


class AppSecPolicy(CloudsneekerRLSModel):
    """Tenant policy content the engine passes to a scan."""

    class Kind(models.TextChoices):
        REGO_CHECK = "rego_check", "Custom misconfiguration check (Rego)"
        SECRET_RULES = "secret_rules", "Secret detection rules"
        LICENSE_POLICY = "license_policy", "License policy"
        IGNORE_RULES = "ignore_rules", "Ignore rules"
        VEX = "vex", "VEX document"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    kind = models.CharField(max_length=32, choices=Kind.choices)
    name = models.CharField(max_length=100, validators=[MinLengthValidator(3)])
    description = models.TextField(blank=True, default="")
    content = models.TextField()
    enabled = models.BooleanField(default=True)
    version = models.PositiveIntegerField(default=1)
    # Result of the last validation: ``{"valid": bool, "errors": [...]}``.
    validation = models.JSONField(default=dict, blank=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_appsec_policies",
    )

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}appsec_policies"
        constraints = [
            _rls(),
            models.UniqueConstraint(
                fields=("tenant_id", "kind", "name"),
                name="unique_cs_appsec_policy_name_per_kind",
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}appsec-policies"


class AppSecPolicyVersion(CloudsneekerRLSModel):
    """Content of one earlier version of a policy."""

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    policy = models.ForeignKey(
        AppSecPolicy, on_delete=models.CASCADE, related_name="versions"
    )
    version = models.PositiveIntegerField()
    content = models.TextField()
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_appsec_policy_versions",
    )

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}appsec_policy_versions"
        constraints = [
            _rls(),
            models.UniqueConstraint(
                fields=("tenant_id", "policy", "version"),
                name="unique_cs_appsec_policy_version",
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}appsec-policy-versions"


class AppSecSettings(CloudsneekerRLSModel):
    """Tenant preferences: risk weights, remediation deadlines, retention.

    Engine limits (timeouts, concurrency, cache) are platform settings read
    from the environment and are not stored per tenant.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    # Overrides of ``appsec.risk.DEFAULT_RISK_CONFIG``.
    risk = models.JSONField(default=dict, blank=True)
    # Days to fix by severity, e.g. ``{"critical": 7, "high": 30}``.
    sla_days = models.JSONField(default=dict, blank=True)
    # ``fixed_findings_days``, ``raw_artifact_days``, ``sbom_versions``.
    retention = models.JSONField(default=dict, blank=True)
    # Default profile reference per target type.
    default_profiles = models.JSONField(default=dict, blank=True)
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_appsec_settings",
    )

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}appsec_settings"
        constraints = [
            _rls(),
            models.UniqueConstraint(
                fields=("tenant_id",), name="unique_cs_appsec_settings_per_tenant"
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}appsec-settings"


class AppSecFinding(CloudsneekerRLSModel):
    """One finding on one target, kept across scans.

    ``fingerprint`` identifies the finding; a later scan that reports the same
    fingerprint updates this row instead of adding one.
    """

    class Category(models.TextChoices):
        VULNERABILITY = "vulnerability", "Vulnerability"
        MISCONFIGURATION = "misconfiguration", "Misconfiguration"
        SECRET = "secret", "Secret"
        LICENSE = "license", "License"
        CODE = "code", "Code weakness (SAST)"

    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"
        INFORMATIONAL = "informational", "Informational"
        UNKNOWN = "unknown", "Unknown"

    class State(models.TextChoices):
        """Detection state, set only by scans."""

        NEW = "new", "New"
        OPEN = "open", "Open"
        REOPENED = "reopened", "Reopened"
        FIXED = "fixed", "Fixed"

    class Priority(models.TextChoices):
        URGENT = "urgent", "Urgent"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    target = models.ForeignKey(
        TrivyTarget, on_delete=models.CASCADE, related_name="appsec_findings"
    )
    fingerprint = models.CharField(max_length=64)
    # UID of the shared ``Finding`` rows and of ``FindingTriage``.
    uid = models.CharField(max_length=300)
    category = models.CharField(max_length=32, choices=Category.choices)
    # Scanner class or file type: ``os-pkgs``, ``lang-pkgs``, ``terraform``...
    finding_type = models.CharField(max_length=64, blank=True, default="")
    scanner = models.CharField(max_length=32, blank=True, default="")
    title = models.CharField(max_length=500)
    description = models.TextField(blank=True, default="")
    severity = models.CharField(max_length=16, choices=Severity.choices)
    # Severity string exactly as the scanner reported it.
    source_severity = models.CharField(max_length=32, blank=True, default="")
    # CVE or advisory id, check id, secret rule id, or license name.
    rule_id = models.CharField(max_length=200, blank=True, default="")
    pkg_name = models.CharField(max_length=300, blank=True, default="")
    pkg_version = models.CharField(max_length=200, blank=True, default="")
    fixed_version = models.CharField(max_length=500, blank=True, default="")
    ecosystem = models.CharField(max_length=64, blank=True, default="")
    purl = models.CharField(max_length=600, blank=True, default="")
    # Scanned file, lock file, image or Kubernetes resource the result is on.
    location = models.CharField(max_length=600, blank=True, default="")
    file_path = models.CharField(max_length=600, blank=True, default="")
    start_line = models.IntegerField(null=True, blank=True)
    end_line = models.IntegerField(null=True, blank=True)
    resource = models.CharField(max_length=400, blank=True, default="")
    primary_url = models.CharField(max_length=600, blank=True, default="")
    cvss_score = models.FloatField(null=True, blank=True)
    # ``None`` when the scanner cannot say (licenses, secrets).
    fix_available = models.BooleanField(null=True, blank=True)
    # Exploit intelligence. ``None`` until a source provides it; never guessed.
    epss_score = models.FloatField(null=True, blank=True)
    known_exploited = models.BooleanField(null=True, blank=True)
    # Suppressed by an ignore rule or VEX statement in the scan itself.
    suppressed = models.BooleanField(default=False)
    suppression = models.JSONField(default=dict, blank=True)
    state = models.CharField(max_length=16, choices=State.choices, default=State.NEW)
    priority = models.CharField(
        max_length=16, choices=Priority.choices, default=Priority.MEDIUM
    )
    priority_score = models.PositiveSmallIntegerField(default=0)
    # Each factor of the score with its points, for the "why" panel.
    priority_factors = models.JSONField(default=list, blank=True)
    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    fixed_at = models.DateTimeField(null=True, blank=True)
    due_at = models.DateTimeField(null=True, blank=True)
    reopen_count = models.PositiveSmallIntegerField(default=0)
    first_run = models.ForeignKey(
        TrivyRun,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="appsec_first_findings",
    )
    last_run = models.ForeignKey(
        TrivyRun,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="appsec_last_findings",
    )
    # Category-specific fields plus every scanner field with no column.
    details = models.JSONField(default=dict, blank=True)

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}appsec_findings"
        constraints = [
            _rls(),
            models.UniqueConstraint(
                fields=("tenant_id", "target", "fingerprint"),
                name="unique_cs_appsec_finding_fingerprint",
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant_id", "category", "state"],
                name="cs_asf_tenant_cat_state_idx",
            ),
            models.Index(
                fields=["tenant_id", "target", "state"],
                name="cs_asf_tenant_target_idx",
            ),
            models.Index(
                fields=["tenant_id", "rule_id"], name="cs_asf_tenant_rule_idx"
            ),
            models.Index(
                fields=["tenant_id", "pkg_name"], name="cs_asf_tenant_pkg_idx"
            ),
            models.Index(
                fields=["tenant_id", "-priority_score"],
                name="cs_asf_tenant_priority_idx",
            ),
            models.Index(
                fields=["tenant_id", "-last_seen_at"],
                name="cs_asf_tenant_seen_idx",
            ),
            models.Index(fields=["tenant_id", "uid"], name="cs_asf_tenant_uid_idx"),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}appsec-findings"


class AppSecFindingEvent(CloudsneekerRLSModel):
    """State change of a finding (detected, fixed, reopened, ...)."""

    class Kind(models.TextChoices):
        DETECTED = "detected", "Detected"
        FIXED = "fixed", "Fixed"
        REOPENED = "reopened", "Reopened"
        SEVERITY_CHANGED = "severity_changed", "Severity changed"
        SUPPRESSED = "suppressed", "Suppressed"
        UNSUPPRESSED = "unsuppressed", "Suppression removed"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    finding = models.ForeignKey(
        AppSecFinding, on_delete=models.CASCADE, related_name="events"
    )
    run = models.ForeignKey(
        TrivyRun,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="appsec_finding_events",
    )
    kind = models.CharField(max_length=32, choices=Kind.choices)
    detail = models.JSONField(default=dict, blank=True)

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}appsec_finding_events"
        constraints = [_rls()]
        indexes = [
            models.Index(
                fields=["tenant_id", "finding", "-inserted_at"],
                name="cs_asfe_tenant_finding_idx",
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}appsec-finding-events"


class AppSecSbom(CloudsneekerRLSModel):
    """Software inventory of one scan of a target."""

    class Source(models.TextChoices):
        GENERATED = "generated", "Generated from a scan"
        IMPORTED = "imported", "Imported document"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    target = models.ForeignKey(
        TrivyTarget, on_delete=models.CASCADE, related_name="appsec_sboms"
    )
    run = models.ForeignKey(
        TrivyRun,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="appsec_sboms",
    )
    source = models.CharField(
        max_length=16, choices=Source.choices, default=Source.GENERATED
    )
    # Format of the imported document (``cyclonedx``, ``spdx``); empty for a
    # generated inventory, which exports to either.
    document_format = models.CharField(max_length=32, blank=True, default="")
    # Sequence number per target, 1 for the first inventory.
    version = models.PositiveIntegerField(default=1)
    artifact_name = models.CharField(max_length=600, blank=True, default="")
    artifact_type = models.CharField(max_length=64, blank=True, default="")
    component_count = models.PositiveIntegerField(default=0)
    vulnerable_component_count = models.PositiveIntegerField(default=0)
    vulnerability_count = models.PositiveIntegerField(default=0)
    # ``{"ecosystems": {...}, "licenses": {...}, "license_categories": {...}}``.
    summary = models.JSONField(default=dict, blank=True)

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}appsec_sboms"
        constraints = [
            _rls(),
            models.UniqueConstraint(
                fields=("tenant_id", "target", "version"),
                name="unique_cs_appsec_sbom_version",
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant_id", "target", "-version"],
                name="cs_assb_tenant_target_idx",
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}appsec-sboms"


class AppSecComponent(CloudsneekerRLSModel):
    """One package in an SBOM."""

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    sbom = models.ForeignKey(
        AppSecSbom, on_delete=models.CASCADE, related_name="components"
    )
    target = models.ForeignKey(
        TrivyTarget, on_delete=models.CASCADE, related_name="appsec_components"
    )
    # Identity inside the scan report (``Package.ID``), used by ``depends_on``.
    ref = models.CharField(max_length=600, blank=True, default="")
    name = models.CharField(max_length=300)
    version = models.CharField(max_length=200, blank=True, default="")
    ecosystem = models.CharField(max_length=64, blank=True, default="")
    # ``os-pkgs`` or ``lang-pkgs``.
    package_class = models.CharField(max_length=32, blank=True, default="")
    purl = models.CharField(max_length=600, blank=True, default="")
    licenses = models.JSONField(default=list, blank=True)
    # ``direct``, ``indirect``, ``root``, ``workspace`` or ``unknown``.
    relationship = models.CharField(max_length=16, blank=True, default="unknown")
    dev = models.BooleanField(default=False)
    # Lock file, image layer target or SBOM the package was found in.
    location = models.CharField(max_length=600, blank=True, default="")
    depends_on = models.JSONField(default=list, blank=True)
    vulnerability_count = models.PositiveIntegerField(default=0)
    max_severity = models.CharField(max_length=16, blank=True, default="")
    # Lowest version that fixes every reported vulnerability, when known.
    fixed_version = models.CharField(max_length=200, blank=True, default="")

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}appsec_components"
        constraints = [_rls()]
        indexes = [
            models.Index(
                fields=["tenant_id", "sbom", "name"], name="cs_asc_tenant_sbom_idx"
            ),
            models.Index(fields=["tenant_id", "name"], name="cs_asc_tenant_name_idx"),
            models.Index(fields=["tenant_id", "purl"], name="cs_asc_tenant_purl_idx"),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}appsec-components"
