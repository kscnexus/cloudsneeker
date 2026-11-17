# Code repository sources imported from a Git connection (a GitHub provider)
# read that connection's credentials. Table plus its RLS constraint.

import uuid

import api.rls
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0100_attack_paths_tmp_db_reap_periodic_task"),
        ("cloudsneeker_api", "0029_appsecfinding_branch"),
    ]

    operations = [
        migrations.CreateModel(
            name="RepositoryConnection",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("full_name", models.CharField(max_length=300)),
                ("secret_managed", models.BooleanField(default=False)),
                (
                    "connection",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cloudsneeker_connected_repositories",
                        to="api.provider",
                    ),
                ),
                (
                    "repository",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cloudsneeker_repository_connection",
                        to="api.provider",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_repository_connections",
                "abstract": False,
            },
        ),
        migrations.AddConstraint(
            model_name="repositoryconnection",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_repositoryconnection",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
    ]
