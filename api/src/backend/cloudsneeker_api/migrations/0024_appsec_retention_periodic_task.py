# Application security retention: a daily task deletes raw scan reports and
# long-fixed findings past each tenant's retention settings.

from django.db import migrations

TASK_NAME = "cloudsneeker-appsec-retention"
INTERVAL_HOURS = 24


def create_periodic_task(apps, schema_editor):
    IntervalSchedule = apps.get_model("django_celery_beat", "IntervalSchedule")
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")

    schedule, _ = IntervalSchedule.objects.get_or_create(
        every=INTERVAL_HOURS,
        period="hours",
    )
    PeriodicTask.objects.update_or_create(
        name=TASK_NAME,
        defaults={"task": TASK_NAME, "interval": schedule, "enabled": True},
    )


def delete_periodic_task(apps, schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    PeriodicTask.objects.filter(name=TASK_NAME).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("cloudsneeker_api", "0023_appsec_aspm"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
    ]

    operations = [
        migrations.RunPython(create_periodic_task, delete_periodic_task),
    ]
