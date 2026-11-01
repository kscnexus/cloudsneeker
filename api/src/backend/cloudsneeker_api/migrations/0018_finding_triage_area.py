# Area findings: product area (cloud, application_security, governance) on
# each triage row, so each area lists only its own triage.
#
# Existing rows are backfilled from the UID prefix the importers write
# (``trivy-...`` and ``opengrep-...`` for Application Security). Every later
# write sets the area from the finding it resolves.

from django.contrib.postgres.operations import AddIndexConcurrently
from django.db import migrations, models

APP_SECURITY_UID_PREFIXES = ("trivy-", "opengrep-")


def backfill_area(apps, schema_editor):
    FindingTriage = apps.get_model("cloudsneeker_api", "FindingTriage")
    query = models.Q()
    for prefix in APP_SECURITY_UID_PREFIXES:
        query |= models.Q(finding_uid__startswith=prefix)
    FindingTriage.objects.filter(query).update(area="application_security")


class Migration(migrations.Migration):
    atomic = False

    dependencies = [
        ("cloudsneeker_api", "0017_refresh_vuln_db_periodic_task"),
    ]

    operations = [
        migrations.AddField(
            model_name="findingtriage",
            name="area",
            field=models.CharField(
                choices=[
                    ("cloud", "Cloud Security"),
                    ("application_security", "Application Security"),
                    ("governance", "Cloud Governance"),
                ],
                default="cloud",
                max_length=32,
            ),
        ),
        migrations.RunPython(backfill_area, migrations.RunPython.noop),
        AddIndexConcurrently(
            model_name="findingtriage",
            index=models.Index(
                fields=["tenant_id", "area", "status"],
                name="cs_triage_tenant_area_idx",
            ),
        ),
    ]
