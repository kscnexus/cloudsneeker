"""Product identity for the MCP server.

The MCP server is installed on its own, without the ``prowler`` SDK, so it
carries a small copy of the brand contract. Field names and the
``CLOUDSNEEKER_*`` environment overrides match ``cloudsneeker/brand.py`` at the
repository root; keep the two in step.
"""

import os
from dataclasses import dataclass, fields, replace

ENV_PREFIX = "CLOUDSNEEKER_"


@dataclass(frozen=True)
class Brand:
    """Names and URLs the MCP server reports to clients."""

    name: str = "Cloudsneeker"
    slug: str = "cloudsneeker"
    api_url: str = "https://api.cloudsneeker.example"
    docs_url: str = "https://docs.cloudsneeker.example"
    # The upstream Hub and Documentation tool sets talk to upstream vendor hosts.
    # They stay off unless a deployment turns them on explicitly.
    mcp_hub_tools: bool = False
    mcp_docs_tools: bool = False

    @property
    def server_name(self) -> str:
        """Name of the root MCP server and ``serviceId`` of ``/health``."""
        return f"{self.slug}-mcp-server"

    @property
    def app_server_name(self) -> str:
        """Name of the mounted application tools server."""
        return f"{self.slug}-app"

    @property
    def description(self) -> str:
        """Human-readable server description."""
        return f"{self.name} MCP Server"

    @property
    def api_base_url(self) -> str:
        """Default ``API_BASE_URL`` when the environment does not set one."""
        return f"{self.api_url.rstrip('/')}/api/v1"


def _coerce(current: object, raw: str) -> object:
    if isinstance(current, bool):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return raw


def load_brand(environ: dict[str, str] | None = None) -> Brand:
    """Build the brand from defaults plus ``CLOUDSNEEKER_*`` overrides.

    Args:
        environ: Mapping to read overrides from. Defaults to ``os.environ``.

    Returns:
        A frozen ``Brand`` instance.
    """
    source = os.environ if environ is None else environ
    base = Brand()
    overrides: dict[str, object] = {}
    for field in fields(Brand):
        raw = source.get(f"{ENV_PREFIX}{field.name.upper()}")
        if raw is not None and raw != "":
            overrides[field.name] = _coerce(getattr(base, field.name), raw)
    return replace(base, **overrides) if overrides else base


brand = load_brand()
