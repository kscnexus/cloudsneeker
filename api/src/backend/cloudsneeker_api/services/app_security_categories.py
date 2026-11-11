"""Security categories of Application Security findings.

Every Application Security finding belongs to exactly one category, so
category counts always add up to the finding total:

* ``sast``: source code issues from a static analysis run (``extra`` key).
* ``secrets``: exposed credentials (``RuleID`` and ``Match`` keys).
* ``sca``: vulnerable or license-restricted third-party packages.
* ``container``: package vulnerabilities and misconfigurations found in a
  container image (and image vulnerabilities in a Kubernetes cluster).
* ``iac``: every other result, which is an infrastructure misconfiguration.

The category is derived from the stored raw result and the target's mode.
Severity, status and priority are separate dimensions and never change it.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from cloudsneeker_api.models import TrivyTarget
from django.db.models import Case, CharField, Q, Value, When

MODE = TrivyTarget.Mode


class SECURITY_CATEGORY:  # noqa: N801 - mirrors the UI constant object
    SAST = "sast"
    SCA = "sca"
    SECRETS = "secrets"
    IAC = "iac"
    CONTAINER = "container"


SECURITY_CATEGORIES = (
    SECURITY_CATEGORY.SAST,
    SECURITY_CATEGORY.SCA,
    SECURITY_CATEGORY.SECRETS,
    SECURITY_CATEGORY.IAC,
    SECURITY_CATEGORY.CONTAINER,
)

# Modes whose package vulnerabilities belong to a container image.
CONTAINER_VULNERABILITY_MODES = frozenset({MODE.IMAGE, MODE.K8S})
# Modes whose misconfigurations belong to a container image.
CONTAINER_MISCONFIGURATION_MODES = frozenset({MODE.IMAGE})


def _is_secret(raw: dict[str, Any]) -> bool:
    return "RuleID" in raw and "Match" in raw


def _is_sast(raw: dict[str, Any]) -> bool:
    return "extra" in raw


def _is_vulnerability(raw: dict[str, Any]) -> bool:
    return "VulnerabilityID" in raw


def _is_license(raw: dict[str, Any]) -> bool:
    return "Category" in raw and "Name" in raw and "RuleID" not in raw


def classify(raw: Any, mode: str | None) -> str:
    """The category of one finding from its raw result and target mode."""
    raw = raw if isinstance(raw, dict) else {}
    if _is_secret(raw):
        return SECURITY_CATEGORY.SECRETS
    if _is_sast(raw):
        return SECURITY_CATEGORY.SAST
    if _is_vulnerability(raw):
        if mode in CONTAINER_VULNERABILITY_MODES:
            return SECURITY_CATEGORY.CONTAINER
        return SECURITY_CATEGORY.SCA
    if _is_license(raw):
        return SECURITY_CATEGORY.SCA
    if mode in CONTAINER_MISCONFIGURATION_MODES:
        return SECURITY_CATEGORY.CONTAINER
    return SECURITY_CATEGORY.IAC


def category_case(scan_modes: dict[str, str]) -> Case:
    """Database form of :func:`classify` for ``Finding`` rows.

    ``scan_modes`` maps each scan id to its target mode. Conditions are
    checked in the same order as :func:`classify`; a JSON key missing from
    ``raw_result`` makes a condition false, so the row falls through to IaC.
    """

    def scans(modes: Iterable[str]) -> list[str]:
        return [scan_id for scan_id, mode in scan_modes.items() if mode in modes]

    secret = Q(raw_result__has_key="RuleID") & Q(raw_result__has_key="Match")
    sast = Q(raw_result__has_key="extra")
    vulnerability = Q(raw_result__has_key="VulnerabilityID")
    license_ = (
        Q(raw_result__has_key="Category")
        & Q(raw_result__has_key="Name")
        & ~Q(raw_result__has_key="RuleID")
    )
    return Case(
        When(secret, then=Value(SECURITY_CATEGORY.SECRETS)),
        When(sast, then=Value(SECURITY_CATEGORY.SAST)),
        When(
            vulnerability & Q(scan_id__in=scans(CONTAINER_VULNERABILITY_MODES)),
            then=Value(SECURITY_CATEGORY.CONTAINER),
        ),
        When(vulnerability, then=Value(SECURITY_CATEGORY.SCA)),
        When(license_, then=Value(SECURITY_CATEGORY.SCA)),
        When(
            Q(scan_id__in=scans(CONTAINER_MISCONFIGURATION_MODES)),
            then=Value(SECURITY_CATEGORY.CONTAINER),
        ),
        default=Value(SECURITY_CATEGORY.IAC),
        output_field=CharField(),
    )


def target_categories(mode: str, scanners: Iterable[str]) -> set[str]:
    """Categories a target with this mode and scanner list can report."""
    if mode == MODE.SAST:
        return {SECURITY_CATEGORY.SAST}
    categories: set[str] = set()
    for scanner in scanners:
        if scanner == "secret":
            categories.add(SECURITY_CATEGORY.SECRETS)
        elif scanner == "license":
            categories.add(SECURITY_CATEGORY.SCA)
        elif scanner == "vuln":
            categories.add(
                SECURITY_CATEGORY.CONTAINER
                if mode in CONTAINER_VULNERABILITY_MODES
                else SECURITY_CATEGORY.SCA
            )
        elif scanner in ("misconfig", "rbac"):
            categories.add(
                SECURITY_CATEGORY.CONTAINER
                if mode in CONTAINER_MISCONFIGURATION_MODES
                else SECURITY_CATEGORY.IAC
            )
    return categories
