"""Report data assemblers, one module per report type."""

from __future__ import annotations

from collections.abc import Callable

from cloudsneeker_api.reports import catalog
from cloudsneeker_api.reports.schema import ReportData, ReportFilters

Assembler = Callable[[str, ReportFilters], ReportData]


def get_assembler(report_type: str) -> Assembler:
    """Return the data assembler of a report type.

    Imports lazily so loading the catalog never pulls in the ORM queries.

    Args:
        report_type: Catalog key.

    Returns:
        ``assemble(tenant_id, filters) -> ReportData``.

    Raises:
        ReportParamsError: The report type is unknown.
    """
    catalog.get_report_type(report_type)
    from cloudsneeker_api.reports.data import (
        cloud_posture,
        compliance,
        container,
        executive,
        governance,
        iac,
        sast,
        sca,
        secrets,
    )

    modules = {
        catalog.EXECUTIVE: executive,
        catalog.CLOUD_POSTURE: cloud_posture,
        catalog.COMPLIANCE: compliance,
        catalog.SCA: sca,
        catalog.SAST: sast,
        catalog.CONTAINER: container,
        catalog.IAC: iac,
        catalog.SECRETS: secrets,
        catalog.GOVERNANCE: governance,
    }
    return modules[report_type].assemble


def assemble_report(tenant_id: str, report_type: str, filters: ReportFilters) -> ReportData:
    """Assemble the data of one report.

    Args:
        tenant_id: Tenant UUID string.
        report_type: Catalog key.
        filters: Report filters.

    Returns:
        The assembled ``ReportData``.
    """
    return get_assembler(report_type)(tenant_id, filters)
