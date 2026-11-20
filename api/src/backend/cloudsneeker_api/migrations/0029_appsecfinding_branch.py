# Findings of a target's extra branches live beside its main-branch findings,
# so the fingerprint is unique per branch. Every existing row is a main-branch
# row (``branch`` empty), so the new constraint holds for current data.

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("cloudsneeker_api", "0028_trivyrun_branch_code_scan"),
    ]

    operations = [
        migrations.AddField(
            model_name="appsecfinding",
            name="branch",
            field=models.CharField(blank=True, default="", max_length=255),
        ),
        migrations.RemoveConstraint(
            model_name="appsecfinding",
            name="unique_cs_appsec_finding_fingerprint",
        ),
        migrations.AddConstraint(
            model_name="appsecfinding",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "target", "branch", "fingerprint"),
                name="unique_cs_appsec_finding_branch_fingerprint",
            ),
        ),
    ]
