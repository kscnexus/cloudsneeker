# SAML hardening (EB-009): per-tenant option to reject IdP-initiated SSO.
#
# Not row-level security protected; read through the admin connection. The
# tenant-scoped database user gets SELECT and DELETE so deleting a tenant can
# cascade to it.

import uuid

import django.db.models.deletion
from api.db_utils import DB_PROWLER_USER
from django.db import migrations, models

TABLE = "cloudsneeker_tenant_sso_policies"


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0100_attack_paths_tmp_db_reap_periodic_task"),
        ("cloudsneeker_api", "0015_mfa"),
    ]

    operations = [
        migrations.CreateModel(
            name="TenantSsoPolicy",
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
                ("reject_idp_initiated_sso", models.BooleanField(default=False)),
                ("updated_by", models.UUIDField(blank=True, null=True)),
                (
                    "tenant",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="cloudsneeker_sso_policy",
                        to="api.tenant",
                    ),
                ),
            ],
            options={"db_table": TABLE},
        ),
        migrations.RunSQL(
            f"GRANT SELECT, DELETE ON TABLE {TABLE} TO {DB_PROWLER_USER};",
            reverse_sql=f"REVOKE SELECT, DELETE ON TABLE {TABLE} FROM {DB_PROWLER_USER};",
        ),
    ]
