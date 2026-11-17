# Repository targets can run static analysis in the same run (their rows go
# to a second shared scan, ``code_scan_id``) and scan extra branches
# (``branch``). Nullable / constant-default columns: no table rewrite.

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("cloudsneeker_api", "0027_alert_events"),
    ]

    operations = [
        migrations.AddField(
            model_name="trivyrun",
            name="code_scan_id",
            field=models.UUIDField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="trivyrun",
            name="branch",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
    ]
