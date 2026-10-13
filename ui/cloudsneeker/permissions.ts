import type { RolePermissionAttributes } from "@/types/users";

/**
 * Map Cloudsneeker edition permissions onto the optional cloud-only keys the
 * UI already checks. Scan managers can configure alerts and import CLI reports.
 */
export const withCloudsneekerPermissions = (
  permissions: RolePermissionAttributes,
): RolePermissionAttributes => ({
  ...permissions,
  manage_ingestions:
    permissions.manage_ingestions ?? permissions.manage_scans ?? false,
  manage_alerts: permissions.manage_alerts ?? permissions.manage_scans ?? false,
});
