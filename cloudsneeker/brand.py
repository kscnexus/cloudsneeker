"""Product identity for every Cloudsneeker surface.

The SDK, the API, and the MCP server import ``brand`` from this module.
Values can be overridden with ``CLOUDSNEEKER_*`` environment variables so a
deployment can point help links at its own domains without a code change.

This module depends only on the standard library so build tooling can import
it before project dependencies are installed.
"""

import os
from dataclasses import dataclass, fields, replace

ENV_PREFIX = "CLOUDSNEEKER_"


@dataclass(frozen=True)
class Brand:
    """Display names, URLs, and identifiers that clients can see."""

    name: str = "Cloudsneeker"
    # In-app assistant. Routes and code identifiers stay as they are.
    assistant_name: str = "Seeker AI"
    short_name: str = "Cloudsneeker"
    vendor: str = "Cloudsneeker"
    slug: str = "cloudsneeker"
    tagline: str = "Cloud security posture, continuously."
    website_url: str = "https://cloudsneeker.example"
    api_url: str = "https://api.cloudsneeker.example"
    docs_url: str = "https://docs.cloudsneeker.example"
    support_url: str = "https://support.cloudsneeker.example"
    status_url: str = ""
    terms_url: str = "https://cloudsneeker.example/terms"
    privacy_url: str = "https://cloudsneeker.example/privacy"
    logo_url: str = "https://docs.cloudsneeker.example/logo/cloudsneeker-mark.png"
    cloudformation_template_url: str = (
        "https://docs.cloudsneeker.example/templates/cloudsneeker-scan-role.yml"
    )
    # ``str.format`` template; ``{docs_url}`` and ``{check_id}`` are available.
    check_docs_url_template: str = "{docs_url}/checks/{check_id}"
    finding_uid_prefix: str = "cloudsneeker"
    output_file_prefix: str = "cloudsneeker-output"
    inventory_file_prefix: str = "cloudsneeker-inventory"
    jira_label_prefix: str = "cloudsneeker"
    slack_bot_name: str = "Cloudsneeker"
    security_hub_product_name: str = "Cloudsneeker"
    # Partner integration name (``vendor/product``). Empty means findings are
    # imported under the account's own default product, which needs no
    # Security Hub partner registration.
    security_hub_integration_name: str = ""
    sarif_driver_name: str = "Cloudsneeker"
    ocsf_product_uid: str = "cloudsneeker"
    scanner_version_header: str = "SCANNER_VERSION"
    jwt_default_issuer: str = "https://api.cloudsneeker.example"
    saml_sp_entity_id: str = "urn:cloudsneeker:sp"
    cli_command: str = "cloudsneeker"
    show_upsell: bool = False

    def check_docs_url(self, check_id: str) -> str:
        """Return the public documentation page for a security check.

        Args:
            check_id: The check identifier, for example ``iam_avoid_root_usage``.

        Returns:
            Absolute URL under ``docs_url``.
        """
        return self.check_docs_url_template.format(
            docs_url=self.docs_url.rstrip("/"), check_id=check_id
        )

    def version_string(self, version: str) -> str:
        """Return the product version line printed by ``--version``.

        Args:
            version: Semantic version of the engine.

        Returns:
            ``"<name> <version>"``.
        """
        return f"{self.name} {version}"


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
