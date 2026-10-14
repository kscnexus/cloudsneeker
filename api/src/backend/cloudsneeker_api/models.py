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
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    summary = models.JSONField(default=dict, blank=True)
    output = models.JSONField(default=dict, blank=True)
    error = models.TextField(blank=True, default="")

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
