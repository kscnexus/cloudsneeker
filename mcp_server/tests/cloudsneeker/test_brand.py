"""Tests for the MCP server brand module."""

from prowler_mcp_server.cloudsneeker.brand import Brand, load_brand
from prowler_mcp_server.cloudsneeker.testing import UPSTREAM_COMPAT_ENV


class TestBrandDefaults:
    def test_defaults_name_cloudsneeker(self):
        brand = Brand()

        assert brand.name == "Cloudsneeker"
        assert brand.server_name == "cloudsneeker-mcp-server"
        assert brand.app_server_name == "cloudsneeker-app"
        assert brand.description == "Cloudsneeker MCP Server"

    def test_upstream_tool_sets_off_by_default(self):
        brand = Brand()

        assert brand.mcp_hub_tools is False
        assert brand.mcp_docs_tools is False

    def test_api_base_url_appends_api_v1(self):
        assert (
            Brand(api_url="https://api.example/").api_base_url
            == "https://api.example/api/v1"
        )


class TestLoadBrand:
    def test_empty_environment_returns_defaults(self):
        assert load_brand({}) == Brand()

    def test_string_and_bool_overrides(self):
        brand = load_brand(
            {
                "CLOUDSNEEKER_NAME": "Acme Cloud",
                "CLOUDSNEEKER_SLUG": "acme",
                "CLOUDSNEEKER_MCP_HUB_TOOLS": "true",
                "CLOUDSNEEKER_MCP_DOCS_TOOLS": "0",
            }
        )

        assert brand.name == "Acme Cloud"
        assert brand.server_name == "acme-mcp-server"
        assert brand.mcp_hub_tools is True
        assert brand.mcp_docs_tools is False

    def test_blank_override_is_ignored(self):
        assert load_brand({"CLOUDSNEEKER_NAME": ""}).name == "Cloudsneeker"

    def test_unknown_keys_are_ignored(self):
        assert load_brand({"CLOUDSNEEKER_NOPE": "x"}) == Brand()


class TestUpstreamCompatEnv:
    def test_restores_upstream_identifiers(self):
        brand = load_brand(UPSTREAM_COMPAT_ENV)

        assert brand.server_name == "prowler-mcp-server"
        assert brand.description == "Prowler MCP Server"
        assert brand.api_base_url == "https://api.prowler.com/api/v1"
        assert brand.mcp_hub_tools is True
        assert brand.mcp_docs_tools is True

    def test_every_key_is_a_brand_field(self):
        field_names = {
            f"CLOUDSNEEKER_{name.upper()}" for name in Brand.__dataclass_fields__
        }

        assert set(UPSTREAM_COMPAT_ENV) <= field_names
