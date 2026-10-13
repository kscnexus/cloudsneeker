import { describe, expect, it } from "vitest";

import { withCloudsneekerPermissions } from "./permissions";

describe("withCloudsneekerPermissions", () => {
  it("maps manage_scans onto alerts and ingestions when those keys are absent", () => {
    const result = withCloudsneekerPermissions({
      manage_users: false,
      manage_account: false,
      manage_providers: false,
      manage_scans: true,
      manage_integrations: false,
      unlimited_visibility: true,
    });

    expect(result.manage_ingestions).toBe(true);
    expect(result.manage_alerts).toBe(true);
  });

  it("grants alerts and ingestions from manage_scans even when keys are false", () => {
    const result = withCloudsneekerPermissions({
      manage_users: false,
      manage_account: false,
      manage_providers: false,
      manage_scans: true,
      manage_ingestions: false,
      manage_integrations: false,
      manage_alerts: false,
      unlimited_visibility: false,
    });

    expect(result.manage_ingestions).toBe(true);
    expect(result.manage_alerts).toBe(true);
  });

  it("does not grant alerts or ingestions without manage_scans", () => {
    const result = withCloudsneekerPermissions({
      manage_users: false,
      manage_account: false,
      manage_providers: false,
      manage_scans: false,
      manage_ingestions: false,
      manage_integrations: false,
      manage_alerts: false,
      unlimited_visibility: false,
    });

    expect(result.manage_ingestions).toBe(false);
    expect(result.manage_alerts).toBe(false);
  });
});
