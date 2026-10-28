# Trivy Hub target and run tables (job tracking; findings stay on Scan/Finding).

import uuid

import api.rls
import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0100_attack_paths_tmp_db_reap_periodic_task"),
        ("cloudsneeker_api", "0007_custodian_trim_outputs_periodic_task"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="TrivyTarget",
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
                (
                    "mode",
                    models.CharField(
                        choices=[
                            ("iac", "IaC"),
                            ("image", "Image"),
                            ("fs", "Filesystem"),
                            ("repo", "Repository"),
                            ("sbom", "SBOM"),
                            ("k8s", "Kubernetes"),
                        ],
                        max_length=32,
                    ),
                ),
                ("config", models.JSONField(blank=True, default=dict)),
                ("schedule_enabled", models.BooleanField(default=False)),
                (
                    "schedule_cron",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                (
                    "schedule_timezone",
                    models.CharField(default="UTC", max_length=64),
                ),
                ("next_run_at", models.DateTimeField(blank=True, null=True)),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cloudsneeker_trivy_targets",
                        to="api.provider",
                    ),
                ),
                (
                    "scheduler_task",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="cloudsneeker_trivy_targets",
                        to="django_celery_beat.periodictask",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.tenant",
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_trivy_targets",
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="TrivyRun",
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
                    "trigger",
                    models.CharField(
                        choices=[
                            ("manual", "Manual"),
                            ("scheduled", "Scheduled"),
                        ],
                        default="manual",
                        max_length=32,
                    ),
                ),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("scan_id", models.UUIDField(blank=True, null=True)),
                ("summary", models.JSONField(blank=True, default=dict)),
                ("output", models.JSONField(blank=True, default=dict)),
                ("error", models.TextField(blank=True, default="")),
                (
                    "error_class",
                    models.CharField(blank=True, default="", max_length=32),
                ),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cloudsneeker_trivy_runs",
                        to="api.provider",
                    ),
                ),
                (
                    "target",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="runs",
                        to="cloudsneeker_api.trivytarget",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.tenant",
                    ),
                ),
                (
                    "triggered_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="cloudsneeker_trivy_runs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_trivy_runs",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="trivytarget",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_trivytarget",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="trivytarget",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "name"),
                name="unique_cs_trivy_target_name_per_tenant",
            ),
        ),
        migrations.AddConstraint(
            model_name="trivyrun",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_trivyrun",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
