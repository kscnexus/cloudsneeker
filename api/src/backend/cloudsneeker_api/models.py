"""Cloudsneeker database models.

Auth, tenants, roles, credentials, scans, and findings stay on the upstream
``api`` models. Reference them with foreign keys; do not duplicate them.

Every table uses ``TABLE_PREFIX`` so Cloudsneeker tables never collide with
upstream tables on merge. New tables ship with a new migration under
``cloudsneeker_api/migrations/``. Never edit an upstream migration.
"""

from uuid import uuid4

from api.models import Provider, User, fernet
from api.rls import RowLevelSecurityConstraint, RowLevelSecurityProtectedModel
from django.conf import settings
from django.core.validators import MinLengthValidator
from django.db import models

TABLE_PREFIX = "cloudsneeker_"
JSON_API_TYPE_PREFIX = "cloudsneeker-"


class CloudsneekerRLSModel(RowLevelSecurityProtectedModel):
    """RLS base for Cloudsneeker tables.

    Upstream ``RowLevelSecurityProtectedModel`` declares ``ForeignKey("Tenant")``.
    Concrete models in this app would resolve that string to
    ``cloudsneeker_api.Tenant``. Point at ``api.Tenant`` explicitly.
    """

    tenant = models.ForeignKey("api.Tenant", on_delete=models.CASCADE)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        abstract = True


class ScanConfiguration(CloudsneekerRLSModel):
    """Named YAML/JSON scan options attached to one or more providers."""

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    name = models.CharField(max_length=100, validators=[MinLengthValidator(3)])
    configuration = models.JSONField(default=dict)
    providers = models.ManyToManyField(
        Provider,
        through="ScanConfigurationProvider",
        related_name="cloudsneeker_scan_configurations",
        blank=True,
    )

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}scan_configurations"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=("tenant_id", "name"),
                name="unique_cs_scan_config_name_per_tenant",
            ),
        ]

    class JSONAPIMeta:
        resource_name = "scan-configurations"


class ScanConfigurationProvider(CloudsneekerRLSModel):
    """Through table so a provider belongs to at most one scan configuration."""

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    scan_configuration = models.ForeignKey(
        ScanConfiguration,
        on_delete=models.CASCADE,
        related_name="provider_links",
    )
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="cloudsneeker_scan_configuration_links",
    )
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}scan_configuration_providers"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=("tenant_id", "provider"),
                name="unique_cs_provider_scan_config",
            ),
        ]


class AlertRecipient(CloudsneekerRLSModel):
    """Email destination for alert rules, with confirmation lifecycle."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        CONFIRMED = "confirmed", "Confirmed"
        UNSUBSCRIBED = "unsubscribed", "Unsubscribed"
        BOUNCED = "bounced", "Bounced"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    email = models.EmailField()
    status = models.CharField(
        max_length=32, choices=Status.choices, default=Status.PENDING
    )
    confirmation_token = models.CharField(max_length=64, blank=True, default="")
    unsubscribe_token = models.CharField(max_length=64, blank=True, default="")
    confirmation_sent_at = models.DateTimeField(null=True, blank=True)
    confirmation_expires_at = models.DateTimeField(null=True, blank=True)
    confirmed_at = models.DateTimeField(null=True, blank=True)
    unsubscribed_at = models.DateTimeField(null=True, blank=True)
    last_bounce_at = models.DateTimeField(null=True, blank=True)

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}alert_recipients"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=("tenant_id", "email"),
                name="unique_cs_alert_recipient_email",
            ),
        ]

    class JSONAPIMeta:
        resource_name = "alert-recipients"


class AlertRule(CloudsneekerRLSModel):
    """Finding alert rule evaluated after scans or on a daily schedule."""

    class Trigger(models.TextChoices):
        AFTER_SCAN = "after_scan", "After scan"
        DAILY = "daily", "Daily"
        BOTH = "both", "Both"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    name = models.CharField(max_length=100, validators=[MinLengthValidator(3)])
    description = models.TextField(blank=True, default="")
    enabled = models.BooleanField(default=True)
    trigger = models.CharField(
        max_length=32, choices=Trigger.choices, default=Trigger.AFTER_SCAN
    )
    condition = models.JSONField(default=dict)
    schema_version = models.PositiveSmallIntegerField(default=1)
    slack_channel_ids = models.JSONField(default=list, blank=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_alert_rules",
    )
    recipients = models.ManyToManyField(
        AlertRecipient,
        through="AlertRuleRecipient",
        related_name="rules",
        blank=True,
    )

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}alert_rules"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=("tenant_id", "name"),
                name="unique_cs_alert_rule_name_per_tenant",
            ),
        ]

    class JSONAPIMeta:
        resource_name = "alert-rules"


class AlertRuleRecipient(CloudsneekerRLSModel):
    """Through table linking alert rules to recipients."""

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    rule = models.ForeignKey(
        AlertRule, on_delete=models.CASCADE, related_name="recipient_links"
    )
    recipient = models.ForeignKey(
        AlertRecipient, on_delete=models.CASCADE, related_name="rule_links"
    )
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}alert_rule_recipients"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=("tenant_id", "rule", "recipient"),
                name="unique_cs_alert_rule_recipient",
            ),
        ]


class EmailDeliveryConfig(CloudsneekerRLSModel):
    """Per-tenant SMTP settings used to deliver alert emails."""

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    enabled = models.BooleanField(default=True)
    host = models.CharField(max_length=255)
    port = models.PositiveIntegerField(default=587)
    use_tls = models.BooleanField(default=True)
    use_ssl = models.BooleanField(default=False)
    username = models.CharField(max_length=255, blank=True, default="")
    _password = models.BinaryField(db_column="password", null=True, blank=True)
    from_email = models.EmailField()

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}email_delivery_configs"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=("tenant_id",),
                name="unique_cs_email_delivery_config_per_tenant",
            ),
        ]

    class JSONAPIMeta:
        resource_name = "email-delivery-configs"

    @property
    def password(self) -> str:
        if not self._password:
            return ""
        if isinstance(self._password, memoryview):
            encrypted_bytes = self._password.tobytes()
        elif isinstance(self._password, str):
            encrypted_bytes = self._password.encode()
        else:
            encrypted_bytes = self._password
        return fernet.decrypt(encrypted_bytes).decode()

    @password.setter
    def password(self, value: str | None) -> None:
        if value is None or value == "":
            self._password = None
            return
        self._password = fernet.encrypt(value.encode())


class SlackAppConfig(CloudsneekerRLSModel):
    """Per-tenant Slack app credentials used for the OAuth install flow."""

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    enabled = models.BooleanField(default=True)
    client_id = models.CharField(max_length=255)
    _client_secret = models.BinaryField(
        db_column="client_secret", null=True, blank=True
    )

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}slack_app_configs"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=("tenant_id",),
                name="unique_cs_slack_app_config_per_tenant",
            ),
        ]

    class JSONAPIMeta:
        resource_name = "slack-app-configs"

    @property
    def client_secret(self) -> str:
        if not self._client_secret:
            return ""
        if isinstance(self._client_secret, memoryview):
            encrypted_bytes = self._client_secret.tobytes()
        elif isinstance(self._client_secret, str):
            encrypted_bytes = self._client_secret.encode()
        else:
            encrypted_bytes = self._client_secret
        return fernet.decrypt(encrypted_bytes).decode()

    @client_secret.setter
    def client_secret(self, value: str | None) -> None:
        if value is None or value == "":
            self._client_secret = None
            return
        self._client_secret = fernet.encrypt(value.encode())


class FindingIngestion(CloudsneekerRLSModel):
    """Upload job that imports a CLI OCSF finding report."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        PROCESSING = "processing", "Processing"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    status = models.CharField(
        max_length=32, choices=Status.choices, default=Status.PENDING
    )
    original_filename = models.CharField(max_length=255, blank=True, default="")
    payload = models.JSONField(default=list, blank=True)
    total_records = models.PositiveIntegerField(default=0)
    processed_records = models.PositiveIntegerField(default=0)
    invalid_records = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True, default="")
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_ingestions",
    )
    scan_id = models.UUIDField(null=True, blank=True)

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}finding_ingestions"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

    class JSONAPIMeta:
        resource_name = "ingestions"


class CustodianPolicy(CloudsneekerRLSModel):
    """Cloud Custodian policy YAML bound to one supported cloud provider."""

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    name = models.CharField(max_length=100, validators=[MinLengthValidator(3)])
    description = models.TextField(blank=True, default="")
    policy_yaml = models.TextField()
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="cloudsneeker_custodian_policies",
    )
    schedule_enabled = models.BooleanField(default=False)
    schedule_cron = models.CharField(max_length=64, blank=True, default="")
    schedule_timezone = models.CharField(max_length=64, default="UTC")
    # Optional AWS region override; empty means use provider scanner regions.
    regions_override = models.JSONField(default=list, blank=True)
    scheduler_task = models.ForeignKey(
        "django_celery_beat.PeriodicTask",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_custodian_policies",
    )
    next_run_at = models.DateTimeField(null=True, blank=True)

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}custodian_policies"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=("tenant_id", "name"),
                name="unique_cs_custodian_policy_name_per_tenant",
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}custodian-policies"


class CustodianRun(CloudsneekerRLSModel):
    """One dry-run execution of a Custodian policy against a provider."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    class Mode(models.TextChoices):
        DRYRUN = "dryrun", "Dry-run"

    class Trigger(models.TextChoices):
        MANUAL = "manual", "Manual"
        SCHEDULED = "scheduled", "Scheduled"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    policy = models.ForeignKey(
        CustodianPolicy,
        on_delete=models.CASCADE,
        related_name="runs",
    )
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="cloudsneeker_custodian_runs",
    )
    status = models.CharField(
        max_length=32, choices=Status.choices, default=Status.PENDING
    )
    mode = models.CharField(
        max_length=32, choices=Mode.choices, default=Mode.DRYRUN
    )
    trigger = models.CharField(
        max_length=32, choices=Trigger.choices, default=Trigger.MANUAL
    )
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    summary = models.JSONField(default=dict, blank=True)
    output = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True, default="")
    error_class = models.CharField(max_length=32, blank=True, default="")
    triggered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_custodian_runs",
    )

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}custodian_runs"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}custodian-runs"


class TrivyTarget(CloudsneekerRLSModel):
    """Named Trivy scan target that feeds the shared Scan/Finding tables."""

    class Mode(models.TextChoices):
        IAC = "iac", "IaC"
        IMAGE = "image", "Image"
        FS = "fs", "Filesystem"
        REPO = "repo", "Repository"
        SBOM = "sbom", "SBOM"
        K8S = "k8s", "Kubernetes"
        SAST = "sast", "Static analysis (SAST)"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    name = models.CharField(max_length=100, validators=[MinLengthValidator(3)])
    description = models.TextField(blank=True, default="")
    mode = models.CharField(max_length=32, choices=Mode.choices)
    config = models.JSONField(default=dict, blank=True)
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="cloudsneeker_trivy_targets",
    )
    schedule_enabled = models.BooleanField(default=False)
    schedule_cron = models.CharField(max_length=64, blank=True, default="")
    schedule_timezone = models.CharField(max_length=64, default="UTC")
    scheduler_task = models.ForeignKey(
        "django_celery_beat.PeriodicTask",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_trivy_targets",
    )
    next_run_at = models.DateTimeField(null=True, blank=True)

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}trivy_targets"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=("tenant_id", "name"),
                name="unique_cs_trivy_target_name_per_tenant",
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}trivy-targets"


class TrivyRun(CloudsneekerRLSModel):
    """One Trivy Hub execution; findings live on the linked Scan."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    class Trigger(models.TextChoices):
        MANUAL = "manual", "Manual"
        SCHEDULED = "scheduled", "Scheduled"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    target = models.ForeignKey(
        TrivyTarget,
        on_delete=models.CASCADE,
        related_name="runs",
    )
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="cloudsneeker_trivy_runs",
    )
    status = models.CharField(
        max_length=32, choices=Status.choices, default=Status.PENDING
    )
    trigger = models.CharField(
        max_length=32, choices=Trigger.choices, default=Trigger.MANUAL
    )
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    scan_id = models.UUIDField(null=True, blank=True)
    summary = models.JSONField(default=dict, blank=True)
    output = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True, default="")
    error_class = models.CharField(max_length=32, blank=True, default="")
    triggered_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_trivy_runs",
    )

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}trivy_runs"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}trivy-runs"


class ReportSchedule(CloudsneekerRLSModel):
    """Recurring report emailed to recipients on a cron schedule."""

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    name = models.CharField(max_length=100, validators=[MinLengthValidator(3)])
    report_type = models.CharField(max_length=32)
    params = models.JSONField(default=dict, blank=True)
    formats = models.JSONField(default=list, blank=True)
    schedule_cron = models.CharField(max_length=64)
    schedule_timezone = models.CharField(max_length=64, default="UTC")
    recipients = models.JSONField(default=list, blank=True)
    enabled = models.BooleanField(default=True)
    scheduler_task = models.ForeignKey(
        "django_celery_beat.PeriodicTask",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_report_schedules",
    )
    next_run_at = models.DateTimeField(null=True, blank=True)
    last_run_at = models.DateTimeField(null=True, blank=True)
    last_run = models.ForeignKey(
        "cloudsneeker_api.ReportRun",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="+",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_report_schedules",
    )

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}report_schedules"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=("tenant_id", "name"),
                name="unique_cs_report_schedule_name_per_tenant",
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}report-schedules"


class ReportRun(CloudsneekerRLSModel):
    """One generated report and its artifacts on the shared output volume."""

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    class Trigger(models.TextChoices):
        MANUAL = "manual", "Manual"
        SCHEDULED = "scheduled", "Scheduled"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    report_type = models.CharField(max_length=32)
    params = models.JSONField(default=dict, blank=True)
    formats = models.JSONField(default=list, blank=True)
    status = models.CharField(
        max_length=32, choices=Status.choices, default=Status.PENDING
    )
    trigger = models.CharField(
        max_length=32, choices=Trigger.choices, default=Trigger.MANUAL
    )
    error = models.TextField(blank=True, default="")
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    # Format -> path relative to the report root; format -> size in bytes.
    artifacts = models.JSONField(default=dict, blank=True)
    artifact_sizes = models.JSONField(default=dict, blank=True)
    size_bytes = models.BigIntegerField(default=0)
    summary = models.JSONField(default=dict, blank=True)
    schedule = models.ForeignKey(
        ReportSchedule,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="runs",
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_report_runs",
    )

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}report_runs"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant_id", "-inserted_at"],
                name="cs_report_run_tenant_ins_idx",
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}report-runs"


class ReportShareLink(CloudsneekerRLSModel):
    """Expiring public link to one report run's JSON payload.

    Only the SHA-256 of the random token is stored; the raw token is returned
    once at creation.
    """

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    report_run = models.ForeignKey(
        ReportRun,
        on_delete=models.CASCADE,
        related_name="share_links",
    )
    token_hash = models.CharField(max_length=64, unique=True)
    expires_at = models.DateTimeField()
    revoked_at = models.DateTimeField(null=True, blank=True)
    last_accessed_at = models.DateTimeField(null=True, blank=True)
    access_count = models.PositiveIntegerField(default=0)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_report_share_links",
    )

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}report_share_links"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}report-share-links"


# --- Audit log (EB-007) -------------------------------------------------------


class AuditEvent(CloudsneekerRLSModel):
    """One user action in a tenant, written by ``cloudsneeker_api.audit``.

    Append-only: the API exposes no update or delete, and the retention task
    is the only code that removes rows. ``metadata`` holds field names and
    other non-secret context only, never submitted values.
    """

    class Outcome(models.TextChoices):
        SUCCESS = "success", "Success"
        FAILURE = "failure", "Failure"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    # Kept as a plain UUID plus an email snapshot so events outlive the user.
    actor_id = models.UUIDField(null=True, blank=True)
    actor_email = models.CharField(max_length=254, blank=True, default="")
    action = models.CharField(max_length=100)
    target_type = models.CharField(max_length=64, blank=True, default="")
    target_id = models.CharField(max_length=255, blank=True, default="")
    target_label = models.CharField(max_length=255, blank=True, default="")
    outcome = models.CharField(
        max_length=16, choices=Outcome.choices, default=Outcome.SUCCESS
    )
    status_code = models.PositiveSmallIntegerField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=512, blank=True, default="")
    request_id = models.CharField(max_length=64, blank=True, default="")
    method = models.CharField(max_length=10, blank=True, default="")
    path = models.CharField(max_length=512, blank=True, default="")
    metadata = models.JSONField(default=dict, blank=True)

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}audit_events"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant_id", "-inserted_at"],
                name="cs_audit_tenant_ins_idx",
            ),
            models.Index(
                fields=["tenant_id", "action"],
                name="cs_audit_tenant_action_idx",
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}audit-events"


# --- Finding triage (EB-010) --------------------------------------------------
# Keyed by the stable finding UID so a status survives rescans (upstream
# ``Finding`` rows are per scan). EB-019 (risk acceptance), EB-020 (ownership)
# and EB-021 (SLA) extend ``FindingTriage``; keep new columns nullable.

FINDING_TRIAGE_NOTE_MAX_LENGTH = 4000


class FindingTriage(CloudsneekerRLSModel):
    """Workflow state of one finding UID in a tenant."""

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        UNDER_REVIEW = "under_review", "Under review"
        REMEDIATING = "remediating", "Remediating"
        RESOLVED = "resolved", "Resolved"
        # Reserved for EB-019 (expiry and approver); allowed now.
        RISK_ACCEPTED = "risk_accepted", "Risk accepted"
        FALSE_POSITIVE = "false_positive", "False positive"
        REOPENED = "reopened", "Reopened"

    class Source(models.TextChoices):
        MANUAL = "manual", "Manual"
        BULK = "bulk", "Bulk"
        # Reserved for EB-031 / EB-042 (ticket sync) and rescan automation.
        INTEGRATION = "integration", "Integration"
        AUTOMATION = "automation", "Automation"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    finding_uid = models.CharField(max_length=300)
    status = models.CharField(
        max_length=32, choices=Status.choices, default=Status.OPEN
    )
    status_changed_at = models.DateTimeField(null=True, blank=True)
    source = models.CharField(
        max_length=32, choices=Source.choices, default=Source.MANUAL
    )
    # Denormalized from the latest finding with this UID, for filtering and
    # provider visibility without joining the partitioned findings table.
    check_id = models.CharField(max_length=100, blank=True, default="")
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name="cloudsneeker_finding_triages",
    )
    # EB-020: owner of the finding.
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_assigned_finding_triages",
    )
    updated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_updated_finding_triages",
    )

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}finding_triages"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=("tenant_id", "finding_uid"),
                name="unique_cs_finding_triage_uid_per_tenant",
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant_id", "status"], name="cs_triage_tenant_status_idx"
            ),
            models.Index(
                fields=["tenant_id", "check_id"], name="cs_triage_tenant_check_idx"
            ),
            models.Index(
                fields=["tenant_id", "provider_id"],
                name="cs_triage_tenant_provider_idx",
            ),
            models.Index(
                fields=["tenant_id", "-updated_at"],
                name="cs_triage_tenant_updated_idx",
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}finding-triages"


class FindingTriageNote(CloudsneekerRLSModel):
    """Plain-text note in a triage thread (newest first in the API)."""

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    triage = models.ForeignKey(
        FindingTriage, on_delete=models.CASCADE, related_name="notes"
    )
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cloudsneeker_finding_triage_notes",
    )
    body = models.TextField(max_length=FINDING_TRIAGE_NOTE_MAX_LENGTH)
    # Status the triage moved to when this note was written, if any.
    status = models.CharField(max_length=32, blank=True, default="")

    class Meta(CloudsneekerRLSModel.Meta):
        db_table = f"{TABLE_PREFIX}finding_triage_notes"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant_id", "triage_id", "-inserted_at"],
                name="cs_triage_note_tenant_ins_idx",
            ),
        ]

    class JSONAPIMeta:
        resource_name = f"{JSON_API_TYPE_PREFIX}finding-triage-notes"


# --- End finding triage (EB-010) ----------------------------------------------
