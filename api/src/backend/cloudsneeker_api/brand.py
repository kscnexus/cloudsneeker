"""Brand values used by API hooks.

Re-exports the SDK brand so the API, the workers, and the engine agree on
every client-visible name. API-only fields live here.
"""

import os

from cloudsneeker.brand import Brand, brand

LOGO_FILENAME = "cloudsneeker_logo.png"


def report_logo_path(assets_img_dir: str) -> str:
    """Return the PDF cover logo path inside the tasks assets directory.

    Args:
        assets_img_dir: Absolute path of ``tasks/assets/img``.

    Returns:
        Path to the product logo PNG.
    """
    return os.path.join(assets_img_dir, LOGO_FILENAME)


def api_title() -> str:
    """OpenAPI document title."""
    return f"{brand.name} API"


def api_description() -> str:
    """OpenAPI document description."""
    return f"{brand.name} API specification.\n\nThis file is auto-generated."


def health_service_id() -> str:
    """``serviceId`` reported by the health endpoints."""
    return f"{brand.slug}-api"


def health_description() -> str:
    """``description`` reported by the health endpoints."""
    return f"{brand.name} API"


def pdf_footer() -> str:
    """Right-hand footer text on every PDF report page."""
    return f"Powered by {brand.name}"


def pdf_author() -> str:
    """PDF metadata author."""
    return brand.vendor


def pdf_creator() -> str:
    """PDF metadata creator."""
    return f"{brand.vendor} Engineering Team"


def pdf_keywords(framework: str) -> str:
    """PDF metadata keywords."""
    return f"compliance,{framework},security,framework,{brand.slug}"


def threatscore_display_name() -> str:
    """Display name of the built-in risk framework."""
    return f"{brand.name} ThreatScore"


__all__ = [
    "Brand",
    "api_description",
    "api_title",
    "brand",
    "health_description",
    "health_service_id",
    "pdf_author",
    "pdf_creator",
    "pdf_footer",
    "pdf_keywords",
    "report_logo_path",
    "threatscore_display_name",
]
