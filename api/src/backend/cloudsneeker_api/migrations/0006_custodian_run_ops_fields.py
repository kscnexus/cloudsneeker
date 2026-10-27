import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("cloudsneeker_api", "0005_custodian_policy_schedule"),
    ]

    operations = [
        migrations.AddField(
            model_name="custodianpolicy",
            name="regions_override",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="custodianrun",
            name="error_class",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
        migrations.AddField(
            model_name="custodianrun",
            name="triggered_by",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="cloudsneeker_custodian_runs",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
