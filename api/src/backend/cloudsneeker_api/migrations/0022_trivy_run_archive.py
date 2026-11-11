# Application Security scan history: ``archived_at`` on Trivy runs and the
# daily Beat task that archives runs older than the retention window.

from datetime import timedelta

from django.db import migrations, models
from django.utils import timezone

TASK_NAME = "cloudsneeker-archive-trivy-runs"
INTERVAL_DAYS = 1


def create_periodic_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=INTERVAL_DAYS,
        period="days",
    )
    # Backdated so Beat runs it on its next tick instead of a day after deploy.
    PeriodicTask.objects.update_or_create(
        name=TASK_NAME,
        defaults={
            "task": TASK_NAME,
            "interval": schedule,
            "enabled": True,
            "last_run_at": timezone.now() - timedelta(days=2),
        },
    )


def delete_periodic_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    PeriodicTask.objects.filter(name=TASK_NAME).delete()
    IntervalSchedule.objects.filter(
        every=INTERVAL_DAYS,
        period="days",
        periodictask__isnull=True,
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("cloudsneeker_api", "0021_risk_acceptance"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
    ]

    operations = [
        # Nullable with no default: a metadata-only change on PostgreSQL.
        migrations.AddField(
            model_name="trivyrun",
            name="archived_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.RunPython(create_periodic_task, delete_periodic_task),
    ]
