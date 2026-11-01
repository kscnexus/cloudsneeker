# Multi-factor authentication (EB-008): one authenticator per password user
# and one "require MFA" switch per tenant.
#
# Not row-level security protected; the application reads them through the
# admin connection. The tenant-scoped database user gets SELECT and DELETE so
# deleting a user or a tenant can cascade to them.

import uuid

import django.db.models.deletion
from api.db_utils import DB_PROWLER_USER
from django.conf import settings
from django.db import migrations, models

CASCADE_TABLES = (
    "cloudsneeker_user_mfa",
    "cloudsneeker_tenant_mfa_policies",
)

GRANT_SQL = "\n".join(
    f"GRANT SELECT, DELETE ON TABLE {table} TO {DB_PROWLER_USER};"
    for table in CASCADE_TABLES
)
REVOKE_SQL = "\n".join(
    f"REVOKE SELECT, DELETE ON TABLE {table} FROM {DB_PROWLER_USER};"
    for table in CASCADE_TABLES
)


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0100_attack_paths_tmp_db_reap_periodic_task"),
        ("cloudsneeker_api", "0014_operator_console"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="UserMfa",
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
                ("secret_encrypted", models.TextField()),
                ("confirmed_at", models.DateTimeField(blank=True, null=True)),
                ("last_used_step", models.BigIntegerField(blank=True, null=True)),
                (
                    "recovery_code_hashes",
                    models.JSONField(blank=True, default=list),
                ),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cloudsneeker_mfa",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"db_table": "cloudsneeker_user_mfa"},
        ),
        migrations.CreateModel(
            name="TenantMfaPolicy",
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
                ("require_mfa", models.BooleanField(default=False)),
                ("updated_by", models.UUIDField(blank=True, null=True)),
                (
                    "tenant",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cloudsneeker_mfa_policy",
                        to="api.tenant",
                    ),
                ),
            ],
            options={"db_table": "cloudsneeker_tenant_mfa_policies"},
        ),
        migrations.RunSQL(GRANT_SQL, reverse_sql=REVOKE_SQL),
    ]
