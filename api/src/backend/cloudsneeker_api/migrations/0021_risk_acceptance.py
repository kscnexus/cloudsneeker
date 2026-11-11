# Risk acceptance with expiry and approver (EB-019): reason, approver, expiry
# date and expiry time on each triage row, and an hourly Beat task that
# reopens findings whose acceptance has expired.

from datetime import timedelta

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models
from django.utils import timezone

TASK_NAME = "cloudsneeker-expire-risk-acceptances"
INTERVAL_HOURS = 1


def create_periodic_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=INTERVAL_HOURS,
        period="hours",
    )
    # Backdated so Beat runs it on its next tick instead of an hour after
    # deploy (Beat starts an interval's clock when it first sees the task).
    PeriodicTask.objects.update_or_create(
        name=TASK_NAME,
        defaults={
            "task": TASK_NAME,
            "interval": schedule,
            "enabled": True,
            "last_run_at": timezone.now() - timedelta(hours=2),
        },
    )


def delete_periodic_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    PeriodicTask.objects.filter(name=TASK_NAME).delete()
    IntervalSchedule.objects.filter(
        every=INTERVAL_HOURS,
        period="hours",
        periodictask__isnull=True,
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("cloudsneeker_api", "0020_vuln_intel_first_run"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="findingtriage",
            name="risk_reason",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="findingtriage",
            name="risk_expires_on",
            field=models.DateField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="findingtriage",
            name="risk_approved_by",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="cloudsneeker_approved_risk_triages",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        migrations.AddField(
            model_name="findingtriage",
            name="risk_approved_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="findingtriage",
            name="risk_expired_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.RunPython(create_periodic_task, delete_periodic_task),
    ]
