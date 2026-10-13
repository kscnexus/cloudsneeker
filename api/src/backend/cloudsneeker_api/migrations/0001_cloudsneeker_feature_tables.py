# Cloudsneeker feature tables: scan configs, alerts, CLI import jobs.

import uuid

import api.rls
import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        ("api", "0100_attack_paths_tmp_db_reap_periodic_task"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ScanConfiguration",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "name",
                    models.CharField(
                        max_length=100,
                        validators=[django.core.validators.MinLengthValidator(3)],
                    ),
                ),
                ("configuration", models.JSONField(default=dict)),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_scan_configurations",
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="ScanConfigurationProvider",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cloudsneeker_scan_configuration_links",
                        to="api.provider",
                    ),
                ),
                (
                    "scan_configuration",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="provider_links",
                        to="cloudsneeker_api.scanconfiguration",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_scan_configuration_providers",
                "abstract": False,
            },
        ),
        migrations.AddField(
            model_name="scanconfiguration",
            name="providers",
            field=models.ManyToManyField(
                blank=True,
                related_name="cloudsneeker_scan_configurations",
                through="cloudsneeker_api.ScanConfigurationProvider",
                to="api.provider",
            ),
        ),
        migrations.AddConstraint(
            model_name="scanconfiguration",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_scanconfiguration",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="scanconfiguration",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "name"),
                name="unique_cs_scan_config_name_per_tenant",
            ),
        ),
        migrations.AddConstraint(
            model_name="scanconfigurationprovider",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_scanconfigurationprovider",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="scanconfigurationprovider",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "provider"),
                name="unique_cs_provider_scan_config",
            ),
        ),
        migrations.CreateModel(
            name="AlertRecipient",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("email", models.EmailField(max_length=254)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("confirmed", "Confirmed"),
                            ("unsubscribed", "Unsubscribed"),
                            ("bounced", "Bounced"),
                        ],
                        default="pending",
                        max_length=32,
                    ),
                ),
                ("confirmation_token", models.CharField(blank=True, default="", max_length=64)),
                ("unsubscribe_token", models.CharField(blank=True, default="", max_length=64)),
                ("confirmation_sent_at", models.DateTimeField(blank=True, null=True)),
                ("confirmation_expires_at", models.DateTimeField(blank=True, null=True)),
                ("confirmed_at", models.DateTimeField(blank=True, null=True)),
                ("unsubscribed_at", models.DateTimeField(blank=True, null=True)),
                ("last_bounce_at", models.DateTimeField(blank=True, null=True)),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_alert_recipients",
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="AlertRule",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "name",
                    models.CharField(
                        max_length=100,
                        validators=[django.core.validators.MinLengthValidator(3)],
                    ),
                ),
                ("description", models.TextField(blank=True, default="")),
                ("enabled", models.BooleanField(default=True)),
                (
                    "trigger",
                    models.CharField(
                        choices=[
                            ("after_scan", "After scan"),
                            ("daily", "Daily"),
                            ("both", "Both"),
                        ],
                        default="after_scan",
                        max_length=32,
                    ),
                ),
                ("condition", models.JSONField(default=dict)),
                ("schema_version", models.PositiveSmallIntegerField(default=1)),
                ("slack_channel_ids", models.JSONField(blank=True, default=list)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="cloudsneeker_alert_rules",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_alert_rules",
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="AlertRuleRecipient",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                (
                    "recipient",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="rule_links",
                        to="cloudsneeker_api.alertrecipient",
                    ),
                ),
                (
                    "rule",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="recipient_links",
                        to="cloudsneeker_api.alertrule",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_alert_rule_recipients",
                "abstract": False,
            },
        ),
        migrations.AddField(
            model_name="alertrule",
            name="recipients",
            field=models.ManyToManyField(
                blank=True,
                related_name="rules",
                through="cloudsneeker_api.AlertRuleRecipient",
                to="cloudsneeker_api.alertrecipient",
            ),
        ),
        migrations.AddConstraint(
            model_name="alertrecipient",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_alertrecipient",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="alertrecipient",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "email"),
                name="unique_cs_alert_recipient_email",
            ),
        ),
        migrations.AddConstraint(
            model_name="alertrule",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_alertrule",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="alertrule",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "name"),
                name="unique_cs_alert_rule_name_per_tenant",
            ),
        ),
        migrations.AddConstraint(
            model_name="alertrulerecipient",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_alertrulerecipient",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="alertrulerecipient",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "rule", "recipient"),
                name="unique_cs_alert_rule_recipient",
            ),
        ),
        migrations.CreateModel(
            name="FindingIngestion",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("processing", "Processing"),
                            ("completed", "Completed"),
                            ("failed", "Failed"),
                        ],
                        default="pending",
                        max_length=32,
                    ),
                ),
                ("original_filename", models.CharField(blank=True, default="", max_length=255)),
                ("payload", models.JSONField(blank=True, default=list)),
                ("total_records", models.PositiveIntegerField(default=0)),
                ("processed_records", models.PositiveIntegerField(default=0)),
                ("invalid_records", models.PositiveIntegerField(default=0)),
                ("error_message", models.TextField(blank=True, default="")),
                ("scan_id", models.UUIDField(blank=True, null=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="cloudsneeker_ingestions",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_finding_ingestions",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="findingingestion",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_findingingestion",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
