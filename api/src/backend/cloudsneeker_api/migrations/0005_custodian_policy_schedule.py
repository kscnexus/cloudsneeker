# Per-policy Custodian dry-run schedule fields and run trigger.

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("django_celery_beat", "0019_alter_periodictasks_options"),
        ("cloudsneeker_api", "0004_slack_app_config"),
    ]

    operations = [
        migrations.AddField(
            model_name="custodianpolicy",
            name="schedule_cron",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="custodianpolicy",
            name="schedule_enabled",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="custodianpolicy",
            name="schedule_timezone",
            field=models.CharField(default="UTC", max_length=64),
        ),
        migrations.AddField(
            model_name="custodianpolicy",
            name="next_run_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="custodianpolicy",
            name="scheduler_task",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="cloudsneeker_custodian_policies",
                to="django_celery_beat.periodictask",
            ),
        ),
        migrations.AddField(
            model_name="custodianrun",
            name="trigger",
            field=models.CharField(
                choices=[("manual", "Manual"), ("scheduled", "Scheduled")],
                default="manual",
                max_length=32,
            ),
        ),
    ]
