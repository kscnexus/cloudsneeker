# User-action audit log (EB-007): the audit events table and its daily
# retention task.

import uuid

import api.rls
import django.db.models.deletion
from django.db import migrations, models

RETENTION_TASK_NAME = "cloudsneeker-purge-audit-events"
RETENTION_INTERVAL_DAYS = 1


def create_retention_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=RETENTION_INTERVAL_DAYS,
        period="days",
    )
    PeriodicTask.objects.update_or_create(
        name=RETENTION_TASK_NAME,
        defaults={
            "task": RETENTION_TASK_NAME,
            "interval": schedule,
            "enabled": True,
        },
    )


def delete_retention_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    PeriodicTask.objects.filter(name=RETENTION_TASK_NAME).delete()
    IntervalSchedule.objects.filter(
        every=RETENTION_INTERVAL_DAYS,
        period="days",
        periodictask__isnull=True,
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("cloudsneeker_api", "0011_reports"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
    ]

    operations = [
        migrations.CreateModel(
            name="AuditEvent",
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
                ("actor_id", models.UUIDField(blank=True, null=True)),
                (
                    "actor_email",
                    models.CharField(blank=True, default="", max_length=254),
                ),
                ("action", models.CharField(max_length=100)),
                (
                    "target_type",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                (
                    "target_id",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                (
                    "target_label",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                (
                    "outcome",
                    models.CharField(
                        choices=[("success", "Success"), ("failure", "Failure")],
                        default="success",
                        max_length=16,
                    ),
                ),
                (
                    "status_code",
                    models.PositiveSmallIntegerField(blank=True, null=True),
                ),
                (
                    "ip_address",
                    models.GenericIPAddressField(blank=True, null=True),
                ),
                (
                    "user_agent",
                    models.CharField(blank=True, default="", max_length=512),
                ),
                (
                    "request_id",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                ("method", models.CharField(blank=True, default="", max_length=10)),
                ("path", models.CharField(blank=True, default="", max_length=512)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.tenant",
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_audit_events",
                "abstract": False,
                "indexes": [
                    models.Index(
                        fields=["tenant_id", "-inserted_at"],
                        name="cs_audit_tenant_ins_idx",
                    ),
                    models.Index(
                        fields=["tenant_id", "action"],
                        name="cs_audit_tenant_action_idx",
                    ),
                ],
            },
        ),
        migrations.AddConstraint(
            model_name="auditevent",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_auditevent",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.RunPython(create_retention_task, delete_retention_task),
    ]
