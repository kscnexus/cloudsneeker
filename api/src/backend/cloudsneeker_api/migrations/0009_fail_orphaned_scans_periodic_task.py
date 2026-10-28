from django.db import migrations

TASK_NAME = "cloudsneeker-fail-orphaned-scans"
INTERVAL_MINUTES = 5


def create_periodic_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=INTERVAL_MINUTES,
        period="minutes",
    )

    PeriodicTask.objects.update_or_create(
        name=TASK_NAME,
        defaults={
            "task": TASK_NAME,
            "interval": schedule,
            "enabled": True,
        },
    )


def delete_periodic_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    PeriodicTask.objects.filter(name=TASK_NAME).delete()

    IntervalSchedule.objects.filter(
        every=INTERVAL_MINUTES,
        period="minutes",
        periodictask__isnull=True,
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("cloudsneeker_api", "0008_trivy_targets_and_runs"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
    ]

    operations = [
        migrations.RunPython(create_periodic_task, delete_periodic_task),
    ]
