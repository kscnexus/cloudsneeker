import type { RolePermissionAttributes } from "@/types/users";

/**
 * Map Cloudsneeker edition permissions onto the optional cloud-only keys the
 * UI already checks. Scan managers can configure alerts and import CLI reports.
 */
export const withCloudsneekerPermissions = (
  permissions: RolePermissionAttributes,
): RolePermissionAttributes => ({
  ...permissions,
  // OSS roles always serialize cloud-only keys as false via toPermissions();
  // treat manage_scans as the edition grant for alerts and CLI import.
  manage_ingestions: Boolean(
    permissions.manage_ingestions || permissions.manage_scans,
  ),
  manage_alerts: Boolean(permissions.manage_alerts || permissions.manage_scans),
});
