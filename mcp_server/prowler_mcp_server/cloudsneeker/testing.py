"""Environment that makes the MCP server report upstream Prowler identifiers.

``tests/conftest.py`` applies this before ``prowler_mcp_server.server`` is
imported, so the upstream suite keeps asserting the names it was written for.
Cloudsneeker-specific tests under ``tests/cloudsneeker/`` build their own
``Brand`` instead of reading the environment.

This module must not import ``prowler_mcp_server.cloudsneeker.brand``: that
module reads the environment at import time.
"""

UPSTREAM_COMPAT_ENV: dict[str, str] = {
    "CLOUDSNEEKER_NAME": "Prowler",
    "CLOUDSNEEKER_SLUG": "prowler",
    "CLOUDSNEEKER_API_URL": "https://api.prowler.com",
    "CLOUDSNEEKER_DOCS_URL": "https://docs.prowler.com",
    "CLOUDSNEEKER_MCP_HUB_TOOLS": "true",
    "CLOUDSNEEKER_MCP_DOCS_TOOLS": "true",
}
