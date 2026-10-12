"""Cloudsneeker database models.

There are no tables yet. When one is added it must:

* subclass ``api.rls.RowLevelSecurityProtectedModel`` and use ``UUIDField``
  primary keys with ``default=uuid4``;
* set ``Meta.db_table`` to ``TABLE_PREFIX + "<name>"`` so Cloudsneeker tables
  never collide with upstream tables on merge;
* ship with a new migration under ``cloudsneeker_api/migrations/``. Never
  edit an upstream migration.

Auth, tenants, roles, credentials, scans, and findings stay on the upstream
``api`` models. Reference them with foreign keys; do not duplicate them.
"""

TABLE_PREFIX = "cloudsneeker_"
JSON_API_TYPE_PREFIX = "cloudsneeker-"
