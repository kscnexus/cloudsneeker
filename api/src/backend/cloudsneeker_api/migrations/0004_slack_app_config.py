# Per-tenant Slack app Client ID/Secret for in-app OAuth configuration.

import uuid

import api.rls
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0100_attack_paths_tmp_db_reap_periodic_task"),
        ("cloudsneeker_api", "0003_custodian_policies_and_runs"),
    ]

    operations = [
        migrations.CreateModel(
            name="SlackAppConfig",
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
                ("enabled", models.BooleanField(default=True)),
                ("client_id", models.CharField(max_length=255)),
                (
                    "_client_secret",
                    models.BinaryField(
                        blank=True, db_column="client_secret", null=True
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
                "db_table": "cloudsneeker_slack_app_configs",
            },
        ),
        migrations.AddConstraint(
            model_name="slackappconfig",
            constraint=api.rls.RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_slackappconfig",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="slackappconfig",
            constraint=models.UniqueConstraint(
                fields=("tenant_id",),
                name="unique_cs_slack_app_config_per_tenant",
            ),
        ),
    ]
