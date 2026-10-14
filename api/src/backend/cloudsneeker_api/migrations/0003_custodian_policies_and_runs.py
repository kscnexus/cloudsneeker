# Cloud Custodian policy and dry-run tables.

import uuid

import api.rls
import django.core.validators
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0100_attack_paths_tmp_db_reap_periodic_task"),
        ("cloudsneeker_api", "0002_email_delivery_config"),
    ]

    operations = [
        migrations.CreateModel(
            name="CustodianPolicy",
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
                ("policy_yaml", models.TextField()),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cloudsneeker_custodian_policies",
                        to="api.provider",
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
                "db_table": "cloudsneeker_custodian_policies",
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="CustodianRun",
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
                            ("running", "Running"),
                            ("completed", "Completed"),
                            ("failed", "Failed"),
                        ],
                        default="pending",
                        max_length=32,
                    ),
                ),
                (
                    "mode",
                    models.CharField(
                        choices=[("dryrun", "Dry-run")],
                        default="dryrun",
                        max_length=32,
                    ),
                ),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("summary", models.JSONField(blank=True, default=dict)),
                ("output", models.JSONField(blank=True, default=dict)),
                ("error", models.TextField(blank=True, default="")),
                (
                    "policy",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="runs",
                        to="cloudsneeker_api.custodianpolicy",
                    ),
                ),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cloudsneeker_custodian_runs",
                        to="api.provider",
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
                "db_table": "cloudsneeker_custodian_runs",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="custodianpolicy",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_custodianpolicy",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="custodianpolicy",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "name"),
                name="unique_cs_custodian_policy_name_per_tenant",
            ),
        ),
        migrations.AddConstraint(
            model_name="custodianrun",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_custodianrun",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
