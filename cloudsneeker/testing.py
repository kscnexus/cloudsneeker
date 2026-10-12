"""Test-only helpers.

Upstream test suites assert upstream identifiers ("Prowler", ``prowler-`` UID
prefixes, ``hub.prowler.com`` links). Rather than editing hundreds of upstream
assertions, the SDK test session loads the brand with these overrides so those
suites stay byte-identical to upstream. Cloudsneeker's own tests under
``tests/cloudsneeker`` use :func:`cloudsneeker.brand.load_brand` with an empty
environment to assert the shipped defaults.

This module must not import :mod:`cloudsneeker.brand`; it runs before the brand
is loaded.
"""

UPSTREAM_COMPAT_ENV: dict[str, str] = {
    "CLOUDSNEEKER_NAME": "Prowler",
    "CLOUDSNEEKER_SHORT_NAME": "Prowler",
    "CLOUDSNEEKER_VENDOR": "Prowler",
    "CLOUDSNEEKER_SLUG": "prowler",
    "CLOUDSNEEKER_TAGLINE": "The Handy Cloud Security Tool",
    "CLOUDSNEEKER_WEBSITE_URL": "https://prowler.com",
    "CLOUDSNEEKER_API_URL": "https://api.prowler.com",
    "CLOUDSNEEKER_DOCS_URL": "https://hub.prowler.com",
    "CLOUDSNEEKER_CHECK_DOCS_URL_TEMPLATE": "{docs_url}/check/{check_id}",
    "CLOUDSNEEKER_LOGO_URL": (
        "https://raw.githubusercontent.com/prowler-cloud/prowler/"
        "dc7d2d5aeb92fdf12e8604f42ef6472cd3e8e889/docs/img/prowler-logo-black.png"
    ),
    "CLOUDSNEEKER_FINDING_UID_PREFIX": "prowler",
    "CLOUDSNEEKER_OUTPUT_FILE_PREFIX": "prowler-output",
    "CLOUDSNEEKER_INVENTORY_FILE_PREFIX": "prowler-inventory",
    "CLOUDSNEEKER_JIRA_LABEL_PREFIX": "prowler",
    "CLOUDSNEEKER_SLACK_BOT_NAME": "Prowler",
    "CLOUDSNEEKER_SECURITY_HUB_PRODUCT_NAME": "Prowler",
    "CLOUDSNEEKER_SECURITY_HUB_INTEGRATION_NAME": "prowler/prowler",
    "CLOUDSNEEKER_SARIF_DRIVER_NAME": "Prowler",
    "CLOUDSNEEKER_OCSF_PRODUCT_UID": "prowler",
    "CLOUDSNEEKER_SCANNER_VERSION_HEADER": "PROWLER_VERSION",
    "CLOUDSNEEKER_CLI_COMMAND": "prowler",
}

__all__ = ["UPSTREAM_COMPAT_ENV"]
