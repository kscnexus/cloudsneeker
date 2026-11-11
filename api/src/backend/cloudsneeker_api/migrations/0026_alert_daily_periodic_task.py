# Daily alert rules: a beat task queues the evaluation of every tenant that
# has an enabled daily rule. Before this, "daily" rules never ran.

from django.db import migrations

TASK_NAME = "cloudsneeker-evaluate-daily-alert-rules"
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
        ("cloudsneeker_api", "0025_appsec_rls_write_grants"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
    ]

    operations = [
        migrations.RunPython(create_periodic_task, delete_periodic_task),
    ]
