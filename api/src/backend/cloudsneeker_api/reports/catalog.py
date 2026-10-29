"""Report type catalog and parameter validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, time
from typing import Any
from uuid import UUID

from cloudsneeker_api.reports.schema import SEVERITY_ORDER, ReportFilters
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime

FORMAT_PDF = "pdf"
FORMAT_XLSX = "xlsx"
FORMAT_CSV = "csv"
FORMAT_JSON = "json"

REPORT_FORMATS: tuple[str, ...] = (FORMAT_PDF, FORMAT_XLSX, FORMAT_CSV, FORMAT_JSON)

FORMAT_CONTENT_TYPES: dict[str, str] = {
    FORMAT_PDF: "application/pdf",
    FORMAT_XLSX: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    FORMAT_CSV: "text/csv",
    FORMAT_JSON: "application/json",
}

MAX_TREND_POINTS = 30


class ReportParamsError(ValueError):
    """Raised when report parameters are invalid."""


@dataclass(frozen=True)
class ReportType:
    """One entry in the report catalog.

    Attributes:
        id: Stable key stored on runs and schedules.
        name: Display name.
        description: One sentence describing the report.
        audience: ``management`` or ``engineering``.
        category: Product area the report covers.
        required_params: Parameter names that must be present.
        optional_params: Extra parameter names this report understands.
    """

    id: str
    name: str
    description: str
    audience: str
    category: str
    required_params: tuple[str, ...] = field(default_factory=tuple)
    optional_params: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Return the JSON:API attributes of this report type."""
        return {
            "name": self.name,
            "description": self.description,
            "audience": self.audience,
            "category": self.category,
            "formats": list(REPORT_FORMATS),
            "parameters": {
                "required": list(self.required_params),
                "optional": [*COMMON_PARAMS, *self.optional_params],
            },
        }


COMMON_PARAMS: tuple[str, ...] = (
    "provider_ids",
    "date_from",
    "date_to",
    "severity_floor",
    "trend_points",
)

EXECUTIVE = "executive"
CLOUD_POSTURE = "cloud_posture"
COMPLIANCE = "compliance"
SCA = "sca"
SAST = "sast"
CONTAINER = "container"
IAC = "iac"
SECRETS = "secrets"
GOVERNANCE = "governance"

REPORT_TYPES: dict[str, ReportType] = {
    item.id: item
    for item in (
        ReportType(
            id=EXECUTIVE,
            name="Executive summary",
            description=(
                "Management summary across cloud, application, compliance, and "
                "governance: overall grade, top risks, trend, and next actions."
            ),
            audience="management",
            category="overview",
        ),
        ReportType(
            id=CLOUD_POSTURE,
            name="Cloud posture",
            description=(
                "Cloud account findings from the latest scan of each provider, "
                "by severity, service, and provider."
            ),
            audience="engineering",
            category="cloud",
        ),
        ReportType(
            id=COMPLIANCE,
            name="Compliance",
            description=(
                "Requirement-level posture for one compliance framework across "
                "the latest scans, or one pinned scan."
            ),
            audience="engineering",
            category="compliance",
            required_params=("compliance_id",),
            optional_params=("scan_id",),
        ),
        ReportType(
            id=SCA,
            name="Software composition (SCA)",
            description=(
                "Vulnerable open-source dependencies with CVE, package, installed "
                "and fixed versions from repository, filesystem, SBOM, and image "
                "scans."
            ),
            audience="engineering",
            category="application",
        ),
        ReportType(
            id=SAST,
            name="Static application security (SAST)",
            description="Source code weaknesses found by static analysis scans.",
            audience="engineering",
            category="application",
        ),
        ReportType(
            id=CONTAINER,
            name="Container images",
            description=(
                "Vulnerabilities, secrets, and misconfigurations found in "
                "container images and Kubernetes workloads."
            ),
            audience="engineering",
            category="application",
        ),
        ReportType(
            id=IAC,
            name="Infrastructure as Code",
            description=(
                "Misconfigurations in Terraform, CloudFormation, Kubernetes "
                "manifests, and other templates."
            ),
            audience="engineering",
            category="application",
        ),
        ReportType(
            id=SECRETS,
            name="Secrets",
            description=(
                "Exposed credentials and keys found in code, images, and cloud "
                "accounts."
            ),
            audience="engineering",
            category="application",
        ),
        ReportType(
            id=GOVERNANCE,
            name="Cloud governance",
            description=(
                "Cloud Governance policy dry-run results: matched resources per "
                "policy, provider, and change since the previous run."
            ),
            audience="engineering",
            category="governance",
        ),
    )
}


def get_report_type(report_type: str) -> ReportType:
    """Return a catalog entry.

    Args:
        report_type: Catalog key.

    Returns:
        The matching ``ReportType``.

    Raises:
        ReportParamsError: The key is not in the catalog.
    """
    try:
        return REPORT_TYPES[report_type]
    except KeyError as exc:
        raise ReportParamsError(
            f"report_type must be one of: {', '.join(REPORT_TYPES)}."
        ) from exc


def validate_formats(formats: Any) -> list[str]:
    """Validate and de-duplicate requested output formats.

    Args:
        formats: List of format names; empty or ``None`` means PDF only.

    Returns:
        Ordered, unique list of formats. JSON is always included because the
        in-app report page and share links read it.

    Raises:
        ReportParamsError: A format is unknown or the value is not a list.
    """
    if formats in (None, "", []):
        formats = [FORMAT_PDF]
    if isinstance(formats, str):
        formats = [item.strip() for item in formats.split(",") if item.strip()]
    if not isinstance(formats, (list, tuple)):
        raise ReportParamsError("formats must be a list.")
    result: list[str] = []
    for item in formats:
        value = str(item).lower()
        if value not in REPORT_FORMATS:
            raise ReportParamsError(
                f"Unknown format '{item}'. Use: {', '.join(REPORT_FORMATS)}."
            )
        if value not in result:
            result.append(value)
    if FORMAT_JSON not in result:
        result.append(FORMAT_JSON)
    return result


def _parse_moment(value: Any, *, end_of_day: bool) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        moment = value
    else:
        text = str(value)
        # A bare date covers the whole day. Check it first: parse_datetime
        # also accepts "YYYY-MM-DD" (as midnight) on Python 3.11+.
        day = parse_date(text) if len(text) == 10 else None
        if day is not None:
            moment = datetime.combine(day, time.max if end_of_day else time.min)
        else:
            moment = parse_datetime(text)
            if moment is None:
                raise ReportParamsError(f"Invalid date: {value}")
    if timezone.is_naive(moment):
        moment = timezone.make_aware(moment, UTC)
    return moment


def _parse_uuid(value: Any, label: str) -> str:
    try:
        return str(UUID(str(value)))
    except (TypeError, ValueError) as exc:
        raise ReportParamsError(f"{label} must be a UUID.") from exc


def validate_params(report_type: str, params: Any) -> dict[str, Any]:
    """Validate report parameters and return their normalized form.

    Args:
        report_type: Catalog key.
        params: Raw parameter mapping from the API or a schedule.

    Returns:
        Normalized, JSON-safe parameters (dates as ISO strings).

    Raises:
        ReportParamsError: Unknown report type or an invalid parameter.
    """
    spec = get_report_type(report_type)
    if params in (None, ""):
        params = {}
    if not isinstance(params, dict):
        raise ReportParamsError("params must be an object.")

    allowed = set(COMMON_PARAMS) | set(spec.required_params) | set(spec.optional_params)
    unknown = sorted(set(params) - allowed)
    if unknown:
        raise ReportParamsError(
            f"Unknown parameter(s) for {spec.id}: {', '.join(unknown)}."
        )
    for name in spec.required_params:
        if params.get(name) in (None, ""):
            raise ReportParamsError(f"{name} is required for the {spec.name} report.")

    provider_ids = params.get("provider_ids") or []
    if isinstance(provider_ids, str):
        provider_ids = [item for item in provider_ids.split(",") if item]
    if not isinstance(provider_ids, (list, tuple)):
        raise ReportParamsError("provider_ids must be a list.")
    normalized_providers = sorted(
        {_parse_uuid(item, "provider_ids") for item in provider_ids}
    )

    date_from = _parse_moment(params.get("date_from"), end_of_day=False)
    date_to = _parse_moment(params.get("date_to"), end_of_day=True)
    if date_from and date_to and date_from > date_to:
        raise ReportParamsError("date_from must be before date_to.")

    severity_floor = params.get("severity_floor") or None
    if severity_floor is not None:
        severity_floor = str(severity_floor).lower()
        if severity_floor not in SEVERITY_ORDER:
            raise ReportParamsError(
                f"severity_floor must be one of: {', '.join(SEVERITY_ORDER)}."
            )

    trend_points = params.get("trend_points") or 10
    try:
        trend_points = int(trend_points)
    except (TypeError, ValueError) as exc:
        raise ReportParamsError("trend_points must be an integer.") from exc
    if not 1 <= trend_points <= MAX_TREND_POINTS:
        raise ReportParamsError(
            f"trend_points must be between 1 and {MAX_TREND_POINTS}."
        )

    normalized: dict[str, Any] = {
        "provider_ids": normalized_providers,
        "date_from": date_from.isoformat() if date_from else None,
        "date_to": date_to.isoformat() if date_to else None,
        "severity_floor": severity_floor,
        "trend_points": trend_points,
    }
    if "compliance_id" in allowed:
        compliance_id = params.get("compliance_id")
        normalized["compliance_id"] = str(compliance_id) if compliance_id else None
    if "scan_id" in allowed:
        scan_id = params.get("scan_id")
        normalized["scan_id"] = _parse_uuid(scan_id, "scan_id") if scan_id else None
    return normalized


def filters_from_params(params: dict[str, Any]) -> ReportFilters:
    """Build ``ReportFilters`` from normalized parameters.

    Args:
        params: Output of ``validate_params``.

    Returns:
        The filters the data assemblers consume.
    """
    return ReportFilters(
        provider_ids=list(params.get("provider_ids") or []),
        date_from=_parse_moment(params.get("date_from"), end_of_day=False),
        date_to=_parse_moment(params.get("date_to"), end_of_day=True),
        severity_floor=params.get("severity_floor"),
        compliance_id=params.get("compliance_id"),
        scan_id=params.get("scan_id"),
        trend_points=int(params.get("trend_points") or 10),
    )


def report_filename(report_type: str, fmt: str, when: datetime) -> str:
    """Return the download filename ``cloudsneeker-<type>-<date>.<ext>``.

    The prefix comes from the brand slug so a white-label build keeps its name.

    Args:
        report_type: Catalog key.
        fmt: Output format.
        when: Date stamped into the name.

    Returns:
        File name without directories.
    """
    from cloudsneeker_api.brand import brand

    slug = report_type.replace("_", "-")
    return f"{brand.slug}-{slug}-{when.strftime('%Y-%m-%d')}.{fmt}"
