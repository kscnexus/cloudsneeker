# Per-tenant SMTP configuration for alert email delivery.

import uuid

import api.rls
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0100_attack_paths_tmp_db_reap_periodic_task"),
        ("cloudsneeker_api", "0001_cloudsneeker_feature_tables"),
    ]

    operations = [
        migrations.CreateModel(
            name="EmailDeliveryConfig",
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
                ("enabled", models.BooleanField(default=True)),
                ("host", models.CharField(max_length=255)),
                ("port", models.PositiveIntegerField(default=587)),
                ("use_tls", models.BooleanField(default=True)),
                ("use_ssl", models.BooleanField(default=False)),
                ("username", models.CharField(blank=True, default="", max_length=255)),
                (
                    "_password",
                    models.BinaryField(blank=True, db_column="password", null=True),
                ),
                ("from_email", models.EmailField(max_length=254)),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "cloudsneeker_email_delivery_configs",
            },
        ),
        migrations.AddConstraint(
            model_name="emaildeliveryconfig",
            constraint=api.rls.RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_emaildeliveryconfig",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="emaildeliveryconfig",
            constraint=models.UniqueConstraint(
                fields=("tenant_id",),
                name="unique_cs_email_delivery_config_per_tenant",
            ),
        ),
    ]
