"""Assistant tools for Application Security and Cloud Governance findings."""

import httpx
from fastmcp import Client

AREA = "/api/v1/area-findings"


def _page(rows, count):
    return {"data": rows, "meta": {"pagination": {"page": 1, "pages": 1, "count": count}}}


async def test_search_area_findings_sends_area_filters(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add(
        "GET",
        AREA,
        json=_page(
            [
                {
                    "type": "area-findings",
                    "id": "trivy-repo-1",
                    "attributes": {
                        "uid": "trivy-repo-1",
                        "title": "CVE-2024-1 in lodash",
                        "severity": "critical",
                        "triage_status": "open",
                        "raw_result": {"ignored": True},
                    },
                }
            ],
            7,
        ),
    )
    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_search_area_findings",
            {
                "area": "application_security",
                "severity": ["critical", "high"],
                "overdue_only": True,
            },
        )

    params = mock_router.query_params("GET", AREA)
    assert params["filter[area]"] == "application_security"
    assert params["filter[severity__in]"] == "critical,high"
    assert params["filter[overdue]"] == "true"
    assert result.data["total"] == 7
    assert result.data["module"] == "Application Security"
    finding = result.data["findings"][0]
    assert finding["module"] == "Application Security"
    assert "raw_result" not in finding


async def test_overdue_is_ignored_outside_application_security(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add("GET", AREA, json=_page([], 0))
    async with Client(mcp_root_server) as client:
        await client.call_tool(
            "prowler_search_area_findings",
            {"area": "governance", "overdue_only": True, "include_muted": True},
        )
    params = mock_router.query_params("GET", AREA)
    assert "filter[overdue]" not in params
    assert params["filter[muted]"] == "include"


async def test_posture_summary_counts_each_area_and_reports_failures(
    mcp_root_server, mock_api_client, mock_router
):
    def handler(request: httpx.Request) -> httpx.Response:
        area = request.url.params["filter[area]"]
        if area == "governance":
            return httpx.Response(
                403, json={"errors": [{"detail": "This area is not included in your plan."}]}
            )
        count = 2 if area == "cloud" else 1
        return httpx.Response(200, json=_page([], count))

    mock_router.add_handler("GET", AREA, handler)
    async with Client(mcp_root_server) as client:
        result = await client.call_tool("prowler_get_platform_posture_summary", {})

    areas = result.data["areas"]
    assert areas["cloud"]["open_findings"] == 10
    assert areas["application_security"]["by_severity"]["critical"] == 1
    assert areas["governance"]["available"] is False


async def test_application_security_finding_detail(
    mcp_root_server, mock_api_client, mock_router
):
    mock_router.add(
        "GET",
        "/api/v1/appsec-findings/f1",
        json={"data": {"type": "appsec-findings", "id": "f1", "attributes": {"title": "x"}}},
    )
    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_get_application_security_finding", {"finding_id": "f1"}
        )
    assert result.data["title"] == "x"
    assert result.data["source"] == "/application-security/findings/f1"


async def test_list_governance_policies(mcp_root_server, mock_api_client, mock_router):
    mock_router.add(
        "GET",
        "/api/v1/custodian-policies",
        json=_page(
            [
                {
                    "type": "custodian-policies",
                    "id": "p1",
                    "attributes": {"name": "unused-ebs", "provider_alias": "prod"},
                }
            ],
            1,
        ),
    )
    async with Client(mcp_root_server) as client:
        result = await client.call_tool(
            "prowler_list_governance_policies", {"search": "ebs"}
        )
    assert mock_router.query_params("GET", "/api/v1/custodian-policies")[
        "filter[search]"
    ] == "ebs"
    assert result.data["policies"][0]["account"] == "prod"
