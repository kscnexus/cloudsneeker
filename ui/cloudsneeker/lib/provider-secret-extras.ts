import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";

/**
 * Extra provider-secret fields Cloudsneeker adds on top of the inherited
 * IaC and Image (Container Registry) credential forms so enterprise
 * customers can connect private Git hosts and registries.
 */

// The checkbox stores a string so the inherited credential schema stays a
// string-only record; the payload builder turns it back into a boolean.
export const REGISTRY_INSECURE_VALUE = {
  ON: "true",
  OFF: "false",
} as const;

export type RegistryInsecureValue =
  (typeof REGISTRY_INSECURE_VALUE)[keyof typeof REGISTRY_INSECURE_VALUE];

export const REGISTRY_INSECURE_VALUES = Object.values(
  REGISTRY_INSECURE_VALUE,
) as [RegistryInsecureValue, ...RegistryInsecureValue[]];

export interface IacSecretExtras {
  [ProviderCredentialFields.IAC_USERNAME]?: string;
}

export interface ImageSecretExtras {
  [ProviderCredentialFields.ECR_ROLE_ARN]?: string;
  [ProviderCredentialFields.ECR_EXTERNAL_ID]?: string;
  [ProviderCredentialFields.REGISTRY_INSECURE]?: boolean;
}

const readText = (formData: FormData, field: string): string | undefined => {
  const value = formData.get(field);
  if (typeof value !== "string") return undefined;
  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
};

export const parseFormBoolean = (
  value: FormDataEntryValue | null,
): boolean | undefined => {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim().toLowerCase();
  if (normalized === REGISTRY_INSECURE_VALUE.ON) return true;
  if (normalized === REGISTRY_INSECURE_VALUE.OFF) return false;
  return undefined;
};

export const buildIacSecretExtras = (formData: FormData): IacSecretExtras => {
  const username = readText(formData, ProviderCredentialFields.IAC_USERNAME);
  return username ? { [ProviderCredentialFields.IAC_USERNAME]: username } : {};
};

export const buildImageSecretExtras = (
  formData: FormData,
): ImageSecretExtras => {
  const extras: ImageSecretExtras = {};
  const roleArn = readText(formData, ProviderCredentialFields.ECR_ROLE_ARN);
  const externalId = readText(
    formData,
    ProviderCredentialFields.ECR_EXTERNAL_ID,
  );
  const insecure = parseFormBoolean(
    formData.get(ProviderCredentialFields.REGISTRY_INSECURE),
  );

  if (roleArn) extras[ProviderCredentialFields.ECR_ROLE_ARN] = roleArn;
  if (externalId) extras[ProviderCredentialFields.ECR_EXTERNAL_ID] = externalId;
  if (insecure !== undefined) {
    extras[ProviderCredentialFields.REGISTRY_INSECURE] = insecure;
  }
  return extras;
};
