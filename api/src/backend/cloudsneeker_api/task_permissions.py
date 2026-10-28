"""Revoke permissions for Cloudsneeker Celery tasks.

``api.rbac.permissions.TASK_REVOKE_PERMISSIONS`` merges this map so every
``RLSTask`` stays revocable only by the permission that queued it. This module
must not import ``api``; the RBAC module imports it while it is still loading.
"""


def cloudsneeker_task_revoke_permissions(permissions) -> dict:
    """Return the revoke permissions of each Cloudsneeker ``RLSTask``.

    Args:
        permissions: The ``api.rbac.permissions.Permissions`` enum.

    Returns:
        Task name to required permissions. ``None`` marks a task that is not
        revocable: alert evaluation follows every scan, and revoking it would
        drop notifications without a retry.
    """
    manage_scans = [permissions.MANAGE_SCANS]
    return {
        "cloudsneeker-process-finding-ingestion": manage_scans,
        "cloudsneeker-evaluate-alert-rules": None,
        "cloudsneeker-custodian-dry-run": manage_scans,
        "cloudsneeker-custodian-scheduled-dry-run": manage_scans,
        "cloudsneeker-trivy-scan": manage_scans,
        "cloudsneeker-trivy-scheduled-scan": manage_scans,
    }
