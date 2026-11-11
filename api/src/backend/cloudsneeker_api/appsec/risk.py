"""Explainable priority score for application security findings.

The scanner severity is never changed. The score is a separate 0 to 100
number built from named factors, each with its points, so the UI can show why
a finding ranks where it does. A factor whose input is unknown adds nothing:
exploit intelligence (EPSS, known-exploited lists) and internet exposure are
only counted when a source supplied them.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

PRIORITY_URGENT = "urgent"
PRIORITY_HIGH = "high"
PRIORITY_MEDIUM = "medium"
PRIORITY_LOW = "low"

DEFAULT_RISK_CONFIG: dict[str, Any] = {
    # Base points for the scanner severity.
    "severity_points": {
        "critical": 55,
        "high": 40,
        "medium": 22,
        "low": 8,
        "informational": 2,
        "unknown": 12,
    },
    # CVSS adds up to this many points, scaled by score / 10.
    "cvss_max_points": 10,
    # EPSS adds up to this many points, scaled by probability.
    "epss_max_points": 15,
    "known_exploited_points": 20,
    "fix_available_points": 5,
    "direct_dependency_points": 4,
    "internet_exposed_points": 8,
    "criticality_points": {"critical": 10, "high": 6, "medium": 2, "low": 0},
    "environment_points": {
        "production": 6,
        "staging": 2,
        "development": 0,
        "test": 0,
        "unknown": 0,
    },
    # Secrets are exploitable as found; they get a floor, not a bonus.
    "secret_floor": 70,
    # Age adds one point per this many days open, up to the cap.
    "age_days_per_point": 30,
    "age_max_points": 5,
    # Score at or above which a finding takes the priority.
    "thresholds": {"urgent": 80, "high": 60, "medium": 35},
}

DEFAULT_SLA_DAYS: dict[str, int] = {
    "critical": 7,
    "high": 30,
    "medium": 90,
    "low": 180,
}


class RiskConfigError(ValueError):
    """A tenant risk override is malformed."""


@dataclass(frozen=True)
class RiskInput:
    """What the score reads from a finding and its application."""

    category: str
    severity: str
    cvss_score: float | None = None
    epss_score: float | None = None
    known_exploited: bool | None = None
    fix_available: bool | None = None
    direct_dependency: bool | None = None
    criticality: str | None = None
    environment: str | None = None
    internet_exposed: bool | None = None
    first_seen_at: datetime | None = None
    now: datetime | None = None


@dataclass
class RiskResult:
    score: int
    priority: str
    factors: list[dict[str, Any]] = field(default_factory=list)


def _number(value: Any, name: str, low: float = 0, high: float = 100) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RiskConfigError(f"{name} must be a number.")
    if not low <= value <= high:
        raise RiskConfigError(f"{name} must be between {low:g} and {high:g}.")
    return value


def merge_risk_config(overrides: dict[str, Any] | None) -> dict[str, Any]:
    """Return the default config with validated tenant overrides applied.

    Args:
        overrides: Partial config in the shape of ``DEFAULT_RISK_CONFIG``.

    Returns:
        A full config.

    Raises:
        RiskConfigError: Unknown key, wrong type, or thresholds out of order.
    """
    config = deepcopy(DEFAULT_RISK_CONFIG)
    if not overrides:
        return config
    if not isinstance(overrides, dict):
        raise RiskConfigError("Risk settings must be an object.")
    for key, value in overrides.items():
        if key not in config:
            raise RiskConfigError(f"Unknown risk setting: {key}.")
        default = config[key]
        if isinstance(default, dict):
            if not isinstance(value, dict):
                raise RiskConfigError(f"{key} must be an object.")
            for name, points in value.items():
                if name not in default:
                    raise RiskConfigError(f"Unknown {key} entry: {name}.")
                default[name] = _number(points, f"{key}.{name}")
        else:
            high = 3650 if key == "age_days_per_point" else 100
            low = 1 if key == "age_days_per_point" else 0
            config[key] = _number(value, key, low, high)
    thresholds = config["thresholds"]
    if not thresholds["urgent"] >= thresholds["high"] >= thresholds["medium"]:
        raise RiskConfigError("thresholds must satisfy urgent >= high >= medium.")
    return config


def merge_sla_days(overrides: dict[str, Any] | None) -> dict[str, int]:
    """Return remediation deadlines (days) by severity with overrides applied.

    Raises:
        RiskConfigError: Unknown severity or a value outside 1 to 3650.
    """
    days = dict(DEFAULT_SLA_DAYS)
    if not overrides:
        return days
    if not isinstance(overrides, dict):
        raise RiskConfigError("Remediation deadlines must be an object.")
    for severity, value in overrides.items():
        if severity not in days:
            raise RiskConfigError(f"Unknown severity for a deadline: {severity}.")
        days[severity] = int(_number(value, f"sla_days.{severity}", 1, 3650))
    return days


def priority_for_score(score: int, thresholds: dict[str, Any]) -> str:
    if score >= thresholds["urgent"]:
        return PRIORITY_URGENT
    if score >= thresholds["high"]:
        return PRIORITY_HIGH
    if score >= thresholds["medium"]:
        return PRIORITY_MEDIUM
    return PRIORITY_LOW


def score_finding(item: RiskInput, config: dict[str, Any] | None = None) -> RiskResult:
    """Score one finding.

    Args:
        item: Finding and application context.
        config: Full risk config (``merge_risk_config``); defaults when None.

    Returns:
        Score (0 to 100), priority, and the factors that built the score.
    """
    config = config or DEFAULT_RISK_CONFIG
    factors: list[dict[str, Any]] = []

    def add(key: str, label: str, points: float, value: Any = None) -> None:
        points = round(points, 1)
        if points:
            factors.append(
                {"key": key, "label": label, "points": points, "value": value}
            )

    severity = (
        item.severity if item.severity in config["severity_points"] else "unknown"
    )
    add(
        "severity",
        f"Scanner severity: {severity}",
        config["severity_points"][severity],
        severity,
    )
    if item.cvss_score is not None:
        add(
            "cvss",
            f"CVSS base score {item.cvss_score:g}",
            config["cvss_max_points"] * max(0.0, min(item.cvss_score, 10.0)) / 10,
            item.cvss_score,
        )
    if item.epss_score is not None:
        add(
            "epss",
            f"Exploit probability (EPSS) {item.epss_score:.1%}",
            config["epss_max_points"] * max(0.0, min(item.epss_score, 1.0)),
            item.epss_score,
        )
    if item.known_exploited:
        add(
            "known_exploited",
            "Listed as exploited in the wild",
            config["known_exploited_points"],
            True,
        )
    if item.fix_available:
        add(
            "fix_available",
            "A fixed version exists",
            config["fix_available_points"],
            True,
        )
    if item.direct_dependency:
        add(
            "direct_dependency",
            "Direct dependency",
            config["direct_dependency_points"],
            True,
        )
    if item.internet_exposed:
        add(
            "internet_exposed",
            "Application is internet facing",
            config["internet_exposed_points"],
            True,
        )
    if item.criticality in config["criticality_points"]:
        add(
            "criticality",
            f"Application criticality: {item.criticality}",
            config["criticality_points"][item.criticality],
            item.criticality,
        )
    if item.environment in config["environment_points"]:
        add(
            "environment",
            f"Environment: {item.environment}",
            config["environment_points"][item.environment],
            item.environment,
        )
    if item.first_seen_at is not None and item.now is not None:
        age_days = max(0, (item.now - item.first_seen_at).days)
        points = min(
            config["age_max_points"],
            age_days // max(1, int(config["age_days_per_point"])),
        )
        add("age", f"Open for {age_days} days", points, age_days)

    total = sum(factor["points"] for factor in factors)
    if item.category == "secret" and total < config["secret_floor"]:
        add(
            "secret_floor",
            "Exposed credentials are usable as found",
            config["secret_floor"] - total,
            True,
        )
        total = config["secret_floor"]
    score = int(max(0, min(100, round(total))))
    return RiskResult(
        score=score,
        priority=priority_for_score(score, config["thresholds"]),
        factors=factors,
    )
