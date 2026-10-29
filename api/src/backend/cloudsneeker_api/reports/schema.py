"""Typed containers shared by report data assembly and the renderers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

SEVERITY_ORDER: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "informational",
)


def empty_severity_counts() -> dict[str, int]:
    """Return a zeroed counter keyed by every severity, most severe first."""
    return {severity: 0 for severity in SEVERITY_ORDER}


@dataclass
class ReportFilters:
    """Normalized filters every report accepts.

    Attributes:
        provider_ids: Provider UUID strings; empty means every visible provider.
        date_from: Lower bound on scan completion (inclusive).
        date_to: Upper bound on scan completion (inclusive).
        severity_floor: Lowest severity included (``None`` keeps every level).
        compliance_id: Framework id, required by the compliance report.
        scan_id: Optional scan pinned by the compliance report.
        trend_points: How many points the trend series keeps.
    """

    provider_ids: list[str] = field(default_factory=list)
    date_from: datetime | None = None
    date_to: datetime | None = None
    severity_floor: str | None = None
    compliance_id: str | None = None
    scan_id: str | None = None
    trend_points: int = 10

    def severities(self) -> list[str]:
        """Return the severities kept by ``severity_floor``, most severe first."""
        if not self.severity_floor or self.severity_floor not in SEVERITY_ORDER:
            return list(SEVERITY_ORDER)
        floor_index = SEVERITY_ORDER.index(self.severity_floor)
        return list(SEVERITY_ORDER[: floor_index + 1])

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe representation for payloads and rendering."""
        return {
            "provider_ids": list(self.provider_ids),
            "date_from": self.date_from.isoformat() if self.date_from else None,
            "date_to": self.date_to.isoformat() if self.date_to else None,
            "severity_floor": self.severity_floor,
            "compliance_id": self.compliance_id,
            "scan_id": self.scan_id,
            "trend_points": self.trend_points,
        }


@dataclass
class ReportTable:
    """A bounded detail table.

    Attributes:
        key: Stable identifier (also the CSV / XLSX sheet name source).
        title: Human-readable title.
        columns: ``(field, header)`` pairs in display order.
        rows: Row dictionaries keyed by field.
        total: Rows that matched before the export bound was applied.
        truncated: True when ``rows`` holds fewer rows than ``total``.
    """

    key: str
    title: str
    columns: list[tuple[str, str]]
    rows: list[dict[str, Any]] = field(default_factory=list)
    total: int = 0
    truncated: bool = False

    def to_dict(self, row_limit: int | None = None) -> dict[str, Any]:
        """Return a JSON-safe table, optionally cut to ``row_limit`` rows."""
        rows = self.rows if row_limit is None else self.rows[:row_limit]
        return {
            "key": self.key,
            "title": self.title,
            "columns": [{"field": f, "header": h} for f, h in self.columns],
            "rows": rows,
            "total": self.total,
            "truncated": self.truncated or len(rows) < self.total,
        }


@dataclass
class ReportData:
    """Everything a renderer needs for one report.

    Attributes:
        report_type: Catalog key.
        title: Report title shown on the cover.
        generated_at: Assembly timestamp (UTC).
        filters: Filters the data was assembled with.
        headline: One plain-language sentence for management readers.
        score: Security score 0-100 (higher is better) or ``None`` with no data.
        grade: Letter grade derived from ``score`` (``"N/A"`` with no data).
        kpis: Named headline numbers (label -> value).
        severity_totals: Failed, unmuted findings per severity.
        status_totals: ``pass`` / ``fail`` / ``muted`` / ``manual`` counts.
        trend: Ordered points ``{"date", "fail", "pass", "critical", "high"}``.
        top_risks: Ranked risks with title, severity, impact, and remediation.
        sources: Per-source / per-provider breakdown rows.
        compliance: Framework posture rows ``{"compliance_id", "pass_pct", ...}``.
        remediation: Prioritized next actions.
        tables: Detail tables.
        empty_state: Message shown instead of data when nothing was found.
        extra: Report-specific values that do not fit the shared shape.
    """

    report_type: str
    title: str
    generated_at: datetime
    filters: ReportFilters
    headline: str = ""
    score: float | None = None
    grade: str = "N/A"
    kpis: dict[str, Any] = field(default_factory=dict)
    severity_totals: dict[str, int] = field(default_factory=empty_severity_counts)
    status_totals: dict[str, int] = field(
        default_factory=lambda: {"pass": 0, "fail": 0, "muted": 0, "manual": 0}
    )
    trend: list[dict[str, Any]] = field(default_factory=list)
    top_risks: list[dict[str, Any]] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)
    compliance: list[dict[str, Any]] = field(default_factory=list)
    remediation: list[dict[str, Any]] = field(default_factory=list)
    tables: list[ReportTable] = field(default_factory=list)
    empty_state: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        """True when the report found no data to show."""
        return self.empty_state is not None

    def to_dict(self, table_row_limit: int | None = None) -> dict[str, Any]:
        """Return the JSON payload served to the in-app report page.

        Args:
            table_row_limit: Cap on rows per detail table (``None`` keeps all).

        Returns:
            JSON-serializable dictionary.
        """
        payload = asdict(self)
        payload["generated_at"] = self.generated_at.isoformat()
        payload["filters"] = self.filters.to_dict()
        payload["tables"] = [
            table.to_dict(row_limit=table_row_limit) for table in self.tables
        ]
        return _json_safe(payload)


def _json_safe(value: Any) -> Any:
    """Recursively convert datetimes and other objects to JSON-safe values."""
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)
