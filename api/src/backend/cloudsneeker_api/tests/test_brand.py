import os
from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest
from api import health
from cloudsneeker_api import brand as api_brand
from cloudsneeker_api.brand import brand
from django.conf import settings
from tasks.jobs.export import _build_output_path
from tasks.jobs.integrations import JIRA_LABEL_PREFIX
from tasks.jobs.reports.config import FRAMEWORK_REGISTRY

ASSETS_IMG_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "..",
    "tasks",
    "assets",
    "img",
)


class TestBrandHelpers:
    def test_api_title_uses_brand_name(self):
        assert api_brand.api_title() == f"{brand.name} API"
        assert "Prowler" not in api_brand.api_title()

    def test_api_description_mentions_brand(self):
        description = api_brand.api_description()
        assert description.startswith(f"{brand.name} API specification.")
        assert "auto-generated" in description

    def test_health_identifiers(self):
        assert api_brand.health_service_id() == f"{brand.slug}-api"
        assert api_brand.health_description() == f"{brand.name} API"

    def test_pdf_metadata(self):
        assert api_brand.pdf_footer() == f"Powered by {brand.name}"
        assert api_brand.pdf_author() == brand.vendor
        assert api_brand.pdf_creator().startswith(brand.vendor)
        assert api_brand.pdf_keywords("cis_1.4_aws").endswith(f",{brand.slug}")
        assert "prowler" not in api_brand.pdf_keywords("cis_1.4_aws")

    def test_threatscore_display_name(self):
        assert api_brand.threatscore_display_name() == f"{brand.name} ThreatScore"

    def test_report_logo_path_points_at_shipped_asset(self):
        path = api_brand.report_logo_path(ASSETS_IMG_DIR)
        assert path.endswith(api_brand.LOGO_FILENAME)
        assert os.path.exists(path), f"missing report logo: {path}"


class TestHooksReadBrand:
    def test_health_module_constants(self):
        assert health.SERVICE_ID == api_brand.health_service_id()
        assert health.SERVICE_DESCRIPTION == api_brand.health_description()

    def test_spectacular_title(self):
        assert settings.SPECTACULAR_SETTINGS["TITLE"] == f"API Reference - {brand.name}"

    def test_jwt_defaults_do_not_point_at_upstream(self):
        for key in ("AUDIENCE", "ISSUER"):
            assert "prowler" not in settings.SIMPLE_JWT[key]

    def test_saml_sp_entity_id(self):
        entity_id = settings.SOCIALACCOUNT_PROVIDERS["saml"]["sp"]["entity_id"]
        assert entity_id == brand.saml_sp_entity_id

    def test_jira_label_prefix(self):
        assert JIRA_LABEL_PREFIX == brand.jira_label_prefix

    def test_threatscore_registry_display_name(self):
        assert (
            FRAMEWORK_REGISTRY["prowler_threatscore"].display_name
            == api_brand.threatscore_display_name()
        )

    @pytest.mark.parametrize("subdirectory", [None, "compliance"])
    def test_export_output_prefix(self, subdirectory):
        started_at = datetime(2026, 1, 1, tzinfo=UTC)
        with (
            patch("tasks.jobs.export.rls_transaction"),
            patch("tasks.jobs.export.Scan.objects.get") as scan_get,
            patch("tasks.jobs.export.os.makedirs"),
        ):
            scan_get.return_value = Mock(started_at=started_at)
            path = _build_output_path(
                output_directory="/tmp/out",
                prowler_provider="aws",
                tenant_id="tenant",
                scan_id="scan",
                subdirectory=subdirectory,
            )
        assert path.endswith(f"/{brand.output_file_prefix}-aws-20260101000000")
        assert "prowler-output" not in path
