# Static analysis (SAST) mode for Trivy Hub targets (choices only; no data change).

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("cloudsneeker_api", "0009_fail_orphaned_scans_periodic_task"),
    ]

    operations = [
        migrations.AlterField(
            model_name="trivytarget",
            name="mode",
            field=models.CharField(
                choices=[
                    ("iac", "IaC"),
                    ("image", "Image"),
                    ("fs", "Filesystem"),
                    ("repo", "Repository"),
                    ("sbom", "SBOM"),
                    ("k8s", "Kubernetes"),
                    ("sast", "Static analysis (SAST)"),
                ],
                max_length=32,
            ),
        ),
    ]
