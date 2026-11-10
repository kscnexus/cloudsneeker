# Run the exploit intelligence refresh on the next Beat tick after deploy.
#
# Beat starts an interval task's clock when it first sees it, so a new daily
# task would first run 24 hours after deploy and findings would show no EPSS
# or KEV data until then. Backdating ``last_run_at`` on a task that has never
# run makes it due at once; later runs keep the daily interval.

from datetime import timedelta

from django.db import migrations
from django.utils import timezone

TASK_NAME = "cloudsneeker-refresh-vuln-intel"


def make_due(apps, schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    PeriodicTasks = apps.get_model("django_celery_beat", "PeriodicTasks")
    now = timezone.now()
    updated = PeriodicTask.objects.filter(name=TASK_NAME, total_run_count=0).update(
        last_run_at=now - timedelta(days=2)
    )
    if updated:
        # Tell a running Beat to reload its schedule.
        PeriodicTasks.objects.update_or_create(ident=1, defaults={"last_update": now})


class Migration(migrations.Migration):
    dependencies = [
        ("cloudsneeker_api", "0019_vulnerability_intel"),
        ("django_celery_beat", "0019_alter_periodictasks_options"),
    ]

    operations = [
        migrations.RunPython(make_due, migrations.RunPython.noop),
    ]
