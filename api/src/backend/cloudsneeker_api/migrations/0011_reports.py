# Reporting engine tables: runs, schedules, and share links.

import uuid

import api.rls
import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0100_attack_paths_tmp_db_reap_periodic_task"),
        ("cloudsneeker_api", "0010_trivytarget_sast_mode"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ReportSchedule",
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
                ("report_type", models.CharField(max_length=32)),
                ("params", models.JSONField(blank=True, default=dict)),
                ("formats", models.JSONField(blank=True, default=list)),
                ("schedule_cron", models.CharField(max_length=64)),
                (
                    "schedule_timezone",
                    models.CharField(default="UTC", max_length=64),
                ),
                ("recipients", models.JSONField(blank=True, default=list)),
                ("enabled", models.BooleanField(default=True)),
                ("next_run_at", models.DateTimeField(blank=True, null=True)),
                ("last_run_at", models.DateTimeField(blank=True, null=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="cloudsneeker_report_schedules",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "scheduler_task",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="cloudsneeker_report_schedules",
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
                "db_table": "cloudsneeker_report_schedules",
                "abstract": False,
            },
        ),
        migrations.CreateModel(
            name="ReportRun",
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
                ("report_type", models.CharField(max_length=32)),
                ("params", models.JSONField(blank=True, default=dict)),
                ("formats", models.JSONField(blank=True, default=list)),
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
                ("error", models.TextField(blank=True, default="")),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("artifacts", models.JSONField(blank=True, default=dict)),
                ("artifact_sizes", models.JSONField(blank=True, default=dict)),
                ("size_bytes", models.BigIntegerField(default=0)),
                ("summary", models.JSONField(blank=True, default=dict)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="cloudsneeker_report_runs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "schedule",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="runs",
                        to="cloudsneeker_api.reportschedule",
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
                "db_table": "cloudsneeker_report_runs",
                "abstract": False,
                "indexes": [
                    models.Index(
                        fields=["tenant_id", "-inserted_at"],
                        name="cs_report_run_tenant_ins_idx",
                    ),
                ],
            },
        ),
        migrations.CreateModel(
            name="ReportShareLink",
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
                ("token_hash", models.CharField(max_length=64, unique=True)),
                ("expires_at", models.DateTimeField()),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("last_accessed_at", models.DateTimeField(blank=True, null=True)),
                ("access_count", models.PositiveIntegerField(default=0)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="cloudsneeker_report_share_links",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "report_run",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="share_links",
                        to="cloudsneeker_api.reportrun",
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
                "db_table": "cloudsneeker_report_share_links",
                "abstract": False,
            },
        ),
        migrations.AddField(
            model_name="reportschedule",
            name="last_run",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="+",
                to="cloudsneeker_api.reportrun",
            ),
        ),
        migrations.AddConstraint(
            model_name="reportschedule",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_reportschedule",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="reportschedule",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "name"),
                name="unique_cs_report_schedule_name_per_tenant",
            ),
        ),
        migrations.AddConstraint(
            model_name="reportrun",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_reportrun",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="reportsharelink",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_reportsharelink",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
