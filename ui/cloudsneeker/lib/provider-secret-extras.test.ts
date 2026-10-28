import { describe, expect, it, vi } from "vitest";

// build-credentials reads two tiny helpers from the "@/lib" barrel, which also
// pulls in server-only auth. Provide the same semantics without the barrel.
vi.mock("@/lib", () => ({
  getFormValue: (formData: FormData, field: string) => formData.get(field),
  filterEmptyValues: (obj: Record<string, unknown>) =>
    Object.fromEntries(
      Object.entries(obj).filter(([, value]) => {
        if (value === 0 || value === false) return true;
        if (value === null || value === undefined) return false;
        if (typeof value === "string" && value.trim() === "") return false;
        return true;
      }),
    ),
}));

import {
  buildIacSecretExtras,
  buildImageSecretExtras,
  parseFormBoolean,
  REGISTRY_INSECURE_VALUE,
} from "@/cloudsneeker/lib/provider-secret-extras";
import {
  buildIacSecret,
  buildImageSecret,
} from "@/lib/provider-credentials/build-credentials";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { addCredentialsFormSchema } from "@/types/formSchemas";

const toFormData = (values: Record<string, string>) => {
  const formData = new FormData();
  Object.entries(values).forEach(([key, value]) => formData.append(key, value));
  return formData;
};

describe("parseFormBoolean", () => {
  it("reads checkbox strings as booleans and ignores anything else", () => {
    // Given / When / Then
    expect(parseFormBoolean("true")).toBe(true);
    expect(parseFormBoolean(" TRUE ")).toBe(true);
    expect(parseFormBoolean("false")).toBe(false);
    expect(parseFormBoolean("")).toBeUndefined();
    expect(parseFormBoolean("yes")).toBeUndefined();
    expect(parseFormBoolean(null)).toBeUndefined();
  });
});

describe("buildIacSecretExtras", () => {
  it("adds a trimmed username and omits it when empty", () => {
    // Given
    const withUser = toFormData({
      [ProviderCredentialFields.IAC_USERNAME]: "  build-bot ",
    });
    const empty = toFormData({ [ProviderCredentialFields.IAC_USERNAME]: "" });

    // When / Then
    expect(buildIacSecretExtras(withUser)).toEqual({ username: "build-bot" });
    expect(buildIacSecretExtras(empty)).toEqual({});
    expect(buildIacSecretExtras(new FormData())).toEqual({});
  });
});

describe("buildImageSecretExtras", () => {
  it("adds ECR role fields and the insecure flag as a boolean", () => {
    // Given
    const formData = toFormData({
      [ProviderCredentialFields.ECR_ROLE_ARN]:
        "arn:aws:iam::123456789012:role/ECRReadOnly",
      [ProviderCredentialFields.ECR_EXTERNAL_ID]: "ext-123",
      [ProviderCredentialFields.REGISTRY_INSECURE]: REGISTRY_INSECURE_VALUE.ON,
    });

    // When / Then
    expect(buildImageSecretExtras(formData)).toEqual({
      ecr_role_arn: "arn:aws:iam::123456789012:role/ECRReadOnly",
      ecr_external_id: "ext-123",
      registry_insecure: true,
    });
  });

  it("sends registry_insecure false and drops empty ECR strings", () => {
    // Given
    const formData = toFormData({
      [ProviderCredentialFields.ECR_ROLE_ARN]: "",
      [ProviderCredentialFields.ECR_EXTERNAL_ID]: "   ",
      [ProviderCredentialFields.REGISTRY_INSECURE]: REGISTRY_INSECURE_VALUE.OFF,
    });

    // When / Then
    expect(buildImageSecretExtras(formData)).toEqual({
      registry_insecure: false,
    });
  });
});

describe("provider secret payload builders", () => {
  it("includes the IaC username next to the token", () => {
    // Given
    const formData = toFormData({
      [ProviderCredentialFields.REPOSITORY_URL]:
        "https://bitbucket.org/acme/infra.git",
      [ProviderCredentialFields.ACCESS_TOKEN]: "fixture-app-password",
      [ProviderCredentialFields.IAC_USERNAME]: "acme-bot",
    });

    // When / Then
    expect(buildIacSecret(formData)).toEqual({
      repository_url: "https://bitbucket.org/acme/infra.git",
      access_token: "fixture-app-password",
      username: "acme-bot",
    });
  });

  it("keeps the IaC payload unchanged when no username is given", () => {
    // Given
    const formData = toFormData({
      [ProviderCredentialFields.REPOSITORY_URL]:
        "https://github.com/acme/infra",
    });

    // When / Then
    expect(buildIacSecret(formData)).toEqual({
      repository_url: "https://github.com/acme/infra",
    });
  });

  it("includes ECR and insecure fields in the image payload", () => {
    // Given
    const formData = toFormData({
      [ProviderCredentialFields.IMAGE_FILTER]: "^prod/.*",
      [ProviderCredentialFields.ECR_ROLE_ARN]:
        "arn:aws:iam::123456789012:role/ECRReadOnly",
      [ProviderCredentialFields.ECR_EXTERNAL_ID]: "",
      [ProviderCredentialFields.REGISTRY_INSECURE]: REGISTRY_INSECURE_VALUE.ON,
    });

    // When / Then
    expect(buildImageSecret(formData)).toEqual({
      image_filter: "^prod/.*",
      ecr_role_arn: "arn:aws:iam::123456789012:role/ECRReadOnly",
      registry_insecure: true,
    });
  });
});

describe("addCredentialsFormSchema extra secret fields", () => {
  it("keeps the IaC username after validation", () => {
    // Given
    const schema = addCredentialsFormSchema("iac");

    // When
    const result = schema.safeParse({
      [ProviderCredentialFields.PROVIDER_ID]: "provider-123",
      [ProviderCredentialFields.PROVIDER_TYPE]: "iac",
      [ProviderCredentialFields.ACCESS_TOKEN]: "fixture-app-password",
      [ProviderCredentialFields.IAC_USERNAME]: "acme-bot",
    });

    // Then
    expect(result.success).toBe(true);
    expect(result.data).toMatchObject({ username: "acme-bot" });
  });

  it("keeps ECR fields and the insecure flag for image providers", () => {
    // Given
    const schema = addCredentialsFormSchema("image");

    // When
    const result = schema.safeParse({
      [ProviderCredentialFields.PROVIDER_ID]: "provider-123",
      [ProviderCredentialFields.PROVIDER_TYPE]: "image",
      [ProviderCredentialFields.ECR_ROLE_ARN]:
        "arn:aws:iam::123456789012:role/ECRReadOnly",
      [ProviderCredentialFields.ECR_EXTERNAL_ID]: "ext-123",
      [ProviderCredentialFields.REGISTRY_INSECURE]: REGISTRY_INSECURE_VALUE.ON,
    });

    // Then
    expect(result.success).toBe(true);
    expect(result.data).toMatchObject({
      ecr_role_arn: "arn:aws:iam::123456789012:role/ECRReadOnly",
      ecr_external_id: "ext-123",
      registry_insecure: "true",
    });
  });

  it("rejects an unknown insecure flag value", () => {
    // Given
    const schema = addCredentialsFormSchema("image");

    // When
    const result = schema.safeParse({
      [ProviderCredentialFields.PROVIDER_ID]: "provider-123",
      [ProviderCredentialFields.PROVIDER_TYPE]: "image",
      [ProviderCredentialFields.REGISTRY_INSECURE]: "maybe",
    });

    // Then
    expect(result.success).toBe(false);
  });
});
