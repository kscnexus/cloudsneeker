"""Let the API database user write the ASPM tables.

``0023_appsec_aspm`` created the row-level security constraint of each ASPM
table with the default ``SELECT`` statement only, so the API could read the
tables but every insert, update and delete (settings, applications, scan
profiles, policies, triage of ASPM findings) failed with "permission denied".
Scans were unaffected because the worker writes through the admin user.

Each constraint is dropped and added again with the statements the models
declare, which creates the missing policies and grants.
"""

import api.rls
from django.db import migrations

STATEMENTS = ["SELECT", "INSERT", "UPDATE", "DELETE"]

MODELS = (
    "appsecapplication",
    "appsecscanprofile",
    "appsecpolicy",
    "appsecpolicyversion",
    "appsecsettings",
    "appsecfinding",
    "appsecfindingevent",
    "appsecsbom",
    "appseccomponent",
)


def _operations():
    operations = []
    for model_name in MODELS:
        name = f"rls_on_{model_name}"
        operations.append(migrations.RemoveConstraint(model_name=model_name, name=name))
        operations.append(
            migrations.AddConstraint(
                model_name=model_name,
                constraint=api.rls.RowLevelSecurityConstraint(
                    "tenant_id", name=name, statements=STATEMENTS
                ),
            )
        )
    return operations


class Migration(migrations.Migration):
    dependencies = [
        ("cloudsneeker_api", "0024_appsec_retention_periodic_task"),
    ]

    operations = _operations()
