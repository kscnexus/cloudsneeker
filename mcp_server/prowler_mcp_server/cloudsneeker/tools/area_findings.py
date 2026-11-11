"""Findings of every product area for the assistant.

The upstream finding tools read cloud scans. Application Security findings
(code, dependencies, images, secrets, licenses) and Cloud Governance findings
(resources matched by a policy dry run) come from ``/area-findings``, which
applies the caller's provider visibility and plan, like the product pages.
"""

from typing import Any, Literal

from pydantic import Field

from prowler_mcp_server.lib.types import NonBlankStr
from prowler_mcp_server.prowler_app.tools.base import BaseTool

Area = Literal["cloud", "application_security", "governance"]
Severity = Literal["critical", "high", "medium", "low", "informational"]
AREAS: tuple[str, ...] = ("cloud", "application_security", "governance")
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "informational")
AREA_LABEL = {
    "cloud": "Cloud Security",
    "application_security": "Application Security",
    "governance": "Cloud Governance",
}
AREA_PAGE = {
    "cloud": "/findings",
    "application_security": "/application-security/findings",
    "governance": "/governance/findings",
}
_FINDING_FIELDS = (
    "uid",
    "title",
    "severity",
    "status",
    "muted",
    "check_id",
    "category",
    "resource_name",
    "resource_type",
    "location",
    "region",
    "source_kind",
    "source_name",
    "triage_status",
    "priority",
    "due_at",
    "fix_available",
    "fix_summary",
    "installed_version",
    "fixed_version",
    "known_exploited",
    "first_seen_at",
    "last_seen_at",
    "remediation",
)


def _count(response: dict[str, Any]) -> int:
    pagination = (response.get("meta") or {}).get("pagination") or {}
    count = pagination.get("count")
    return int(count) if isinstance(count, int) else len(response.get("data") or [])


def _finding(area: str, row: dict[str, Any]) -> dict[str, Any]:
    attributes = row.get("attributes") or {}
    item = {key: attributes.get(key) for key in _FINDING_FIELDS if key in attributes}
    item["area"] = area
    item["module"] = AREA_LABEL[area]
    return item


class AreaFindingsTools(BaseTool):
    """Read-only tools over the three product areas."""

    async def search_area_findings(
        self,
        area: Area = Field(
            default="cloud",
            description=(
                "Product area: cloud (cloud posture checks), application_security "
                "(code, dependency, image, secret, license and IaC findings) or "
                "governance (cloud resources matched by governance policies)."
            )
        ),
        severity: list[Severity] = Field(
            default=[],
            description="Severities to include. Empty returns every severity.",
        ),
        search: str | None = Field(
            default=None,
            description="Text in the rule, CVE, title, package, file or resource.",
        ),
        triage_status: list[
            Literal[
                "open",
                "under_review",
                "remediating",
                "resolved",
                "risk_accepted",
                "false_positive",
                "reopened",
            ]
        ] = Field(
            default=[],
            description="Triage statuses to include. Empty returns every status.",
        ),
        overdue_only: bool = Field(
            default=False,
            description="Application Security only: findings past their remediation deadline.",
        ),
        include_muted: bool = Field(
            default=False,
            description="Include findings suppressed by the mutelist.",
        ),
        sort: Literal["severity", "-last_seen_at", "first_seen_at", "check_id"] = Field(
            default="severity", description="Sort order."
        ),
        page_size: int = Field(default=25, description="Results per page (1-100)."),
        page_number: int = Field(default=1, description="Page number, from 1."),
    ) -> dict[str, Any]:
        """Search the current findings of one product area.

        Returns the open findings of the latest scan of each cloud account,
        application target or governance policy, with severity, triage status
        and the module they belong to. Use it for questions about application
        vulnerabilities, secrets, licenses or governance violations, which the
        cloud finding tools do not return. Every result is a stored finding;
        state it as such and keep recommendations separate.
        """
        self.api_client.validate_page_size(page_size)
        params: dict[str, Any] = {
            "filter[area]": area,
            "sort": sort,
            "page[size]": page_size,
            "page[number]": page_number,
        }
        if severity:
            params["filter[severity__in]"] = severity
        if search:
            params["filter[search]"] = search
        if triage_status:
            params["filter[triage_status__in]"] = triage_status
        if overdue_only and area == "application_security":
            params["filter[overdue]"] = "true"
        if include_muted:
            params["filter[muted]"] = "include"
        response = await self.api_client.get(
            "/area-findings", params=self.api_client.build_filter_params(params)
        )
        return {
            "area": area,
            "module": AREA_LABEL[area],
            "total": _count(response),
            "page": page_number,
            "findings": [_finding(area, row) for row in response.get("data") or []],
            "source": f"{AREA_PAGE[area]} (area findings API)",
        }

    async def get_platform_posture_summary(self) -> dict[str, Any]:
        """Open finding counts per product area and severity.

        One call answers "summarise my security posture" or "compare
        application risk with cloud risk": for Cloud Security, Application
        Security and Cloud Governance it returns the open (unmuted) findings
        of the latest scans by severity. An area the plan does not include,
        or that failed to load, is reported as unavailable, never as zero.
        """
        summary: dict[str, Any] = {}
        for area in AREAS:
            counts: dict[str, int] = {}
            try:
                for severity in SEVERITIES:
                    response = await self.api_client.get(
                        "/area-findings",
                        params={
                            "filter[area]": area,
                            "filter[severity__in]": severity,
                            "page[size]": 1,
                        },
                    )
                    counts[severity] = _count(response)
            except Exception as error:  # noqa: BLE001 - one area must not hide the rest
                summary[area] = {
                    "module": AREA_LABEL[area],
                    "available": False,
                    "reason": str(error)[:200],
                }
                continue
            summary[area] = {
                "module": AREA_LABEL[area],
                "available": True,
                "open_findings": sum(counts.values()),
                "by_severity": counts,
                "page": AREA_PAGE[area],
            }
        return {
            "areas": summary,
            "definition": (
                "Open = failing, not muted, in the latest scan of each account, "
                "target or policy."
            ),
        }

    async def get_application_security_finding(
        self,
        finding_id: NonBlankStr = Field(
            description=(
                "Id of an Application Security finding: the last path segment of "
                "/application-security/findings/<id>."
            )
        ),
    ) -> dict[str, Any]:
        """Full detail of one Application Security finding.

        Includes the package, versions, file and line, CVSS, priority and its
        factors, remediation deadline, lifecycle history and related
        findings. When the user is on /application-security/findings/<id>,
        that id is the finding they mean.
        """
        response = await self.api_client.get(f"/appsec-findings/{finding_id}")
        data = response.get("data") or {}
        attributes = data.get("attributes") or {}
        return {
            "id": data.get("id"),
            "module": AREA_LABEL["application_security"],
            **attributes,
            "source": f"/application-security/findings/{data.get('id')}",
        }

    async def get_application_security_overview(self) -> dict[str, Any]:
        """Application Security dashboard figures.

        Applications and assets, findings by category, severity and
        priority, overdue findings, vulnerable packages and scan health.
        """
        response = await self.api_client.get("/appsec/overview")
        data = response.get("data") or {}
        attributes = data.get("attributes") if isinstance(data, dict) else None
        return {
            "module": AREA_LABEL["application_security"],
            "overview": attributes if attributes is not None else data,
            "source": "/application-security",
        }

    async def list_governance_policies(
        self,
        search: str | None = Field(
            default=None, description="Text in the policy name or description."
        ),
        page_size: int = Field(default=25, description="Results per page (1-100)."),
        page_number: int = Field(default=1, description="Page number, from 1."),
    ) -> dict[str, Any]:
        """Cloud Governance policies with their account and schedule.

        Use search_area_findings with area=governance for the resources each
        policy matched.
        """
        self.api_client.validate_page_size(page_size)
        params: dict[str, Any] = {
            "page[size]": page_size,
            "page[number]": page_number,
            "sort": "name",
        }
        if search:
            params["filter[search]"] = search
        response = await self.api_client.get("/custodian-policies", params=params)
        policies = []
        for row in response.get("data") or []:
            attributes = row.get("attributes") or {}
            policies.append(
                {
                    "id": row.get("id"),
                    "name": attributes.get("name"),
                    "description": attributes.get("description"),
                    "account": attributes.get("provider_alias")
                    or attributes.get("provider_uid"),
                    "provider_type": attributes.get("provider_type"),
                    "schedule_enabled": attributes.get("schedule_enabled"),
                    "next_run_at": attributes.get("next_run_at"),
                }
            )
        return {
            "module": AREA_LABEL["governance"],
            "total": _count(response),
            "policies": policies,
            "source": "/governance?tab=policies",
        }
