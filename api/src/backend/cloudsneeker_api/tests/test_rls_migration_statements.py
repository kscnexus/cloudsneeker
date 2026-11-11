"""Every Cloudsneeker row-level security table must be writable by the API.

``RowLevelSecurityConstraint`` does not deconstruct its ``statements`` (and
Django copies model constraints through ``deconstruct``), so neither
``makemigrations`` nor the models can show a migration that grants ``SELECT``
only. ``0023_appsec_aspm`` shipped that way and every API write to the ASPM
tables failed in production; CI missed it because the test database user
bypasses row-level security. This test reads the migrations instead.
"""

from api.rls import RowLevelSecurityConstraint
from django.db.migrations import AddConstraint
from django.db.migrations.loader import MigrationLoader

APP_LABEL = "cloudsneeker_api"
FULL_ACCESS = ["DELETE", "INSERT", "SELECT", "UPDATE"]


def _migrated_statements() -> dict[str, list[str]]:
    """Statements of the last ``AddConstraint`` of each RLS constraint."""
    loader = MigrationLoader(None, ignore_no_migrations=True)
    plan = loader.graph.forwards_plan(
        max(
            (key for key in loader.disk_migrations if key[0] == APP_LABEL),
            key=lambda key: key[1],
        )
    )
    statements: dict[str, list[str]] = {}
    for key in plan:
        if key[0] != APP_LABEL:
            continue
        for operation in loader.disk_migrations[key].operations:
            constraint = getattr(operation, "constraint", None)
            if isinstance(operation, AddConstraint) and isinstance(
                constraint, RowLevelSecurityConstraint
            ):
                statements[constraint.name] = sorted(constraint.statements)
    return statements


def test_every_rls_table_lets_the_api_write():
    migrated = _migrated_statements()
    assert migrated
    read_only = {
        name: statements
        for name, statements in migrated.items()
        if statements != FULL_ACCESS
    }
    assert read_only == {}
