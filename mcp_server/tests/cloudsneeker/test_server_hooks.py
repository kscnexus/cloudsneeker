"""Tests for the brand hooks in the root MCP server and its health route."""

import pytest
from fastmcp import Client, FastMCP
from starlette.testclient import TestClient

from prowler_mcp_server import __version__
from prowler_mcp_server.cloudsneeker.brand import Brand
from tests.helpers.assertions import tools_in_namespace


@pytest.fixture(scope="session", autouse=True)
def _import_server_outside_singleton_snapshot() -> None:
    """Import the server before any function-scoped fixture runs.

    Tools capture the ``ProwlerAPIClient`` singleton when ``prowler_app.server``
    is first imported. If that first import happened inside a test, the
    ``_singleton_registry_guard`` fixture would evict the instance afterwards
    and every later test would be mocking a client the tools no longer hold.
    """
    import prowler_mcp_server.server  # noqa: F401


@pytest.fixture
def default_brand(monkeypatch) -> Brand:
    """Point the imported server module at the Cloudsneeker defaults."""
    import prowler_mcp_server.server as server_module

    brand = Brand()
    monkeypatch.setattr(server_module, "brand", brand)
    return brand


class TestSetupMainServer:
    async def test_default_brand_mounts_only_app_tools(self, default_brand):
        from prowler_mcp_server.server import setup_main_server

        root = FastMCP("test-root")
        setup_main_server(root)

        async with Client(root) as client:
            tools = await client.list_tools()

        assert tools_in_namespace(tools, "prowler_"), "app tools missing"
        assert not tools_in_namespace(tools, "prowler_hub_"), "hub tools mounted"
        assert not tools_in_namespace(tools, "prowler_docs_"), "docs tools mounted"

    async def test_upstream_tool_sets_mount_when_enabled(self, monkeypatch):
        import prowler_mcp_server.server as server_module

        monkeypatch.setattr(
            server_module, "brand", Brand(mcp_hub_tools=True, mcp_docs_tools=True)
        )
        root = FastMCP("test-root")
        server_module.setup_main_server(root)

        async with Client(root) as client:
            tools = await client.list_tools()

        assert tools_in_namespace(tools, "prowler_hub_")
        assert tools_in_namespace(tools, "prowler_docs_")

    def test_root_server_is_named_from_brand(self, mcp_root_server):
        # The module is imported under the upstream-compat environment.
        assert mcp_root_server.name == "prowler-mcp-server"


class TestHealth:
    def test_health_reports_brand_service(self, default_brand):
        from prowler_mcp_server.server import app

        with TestClient(app) as client:
            response = client.get("/health")

        assert response.status_code == 200
        assert response.json() == {
            "status": "pass",
            "version": "1",
            "releaseId": __version__,
            "serviceId": "cloudsneeker-mcp-server",
            "description": "Cloudsneeker MCP Server",
        }
