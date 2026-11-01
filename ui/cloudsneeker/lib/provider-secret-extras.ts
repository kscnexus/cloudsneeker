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
  [ProviderCredentialFields.SSH_PRIVATE_KEY]?: string;
  [ProviderCredentialFields.SSH_KNOWN_HOSTS]?: string;
  [ProviderCredentialFields.SSH_KEY_PASSPHRASE]?: string;
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

// The SSH key and known-hosts lines keep their line breaks; the passphrase is
// sent exactly as typed.
const IAC_SSH_FIELDS = [
  ProviderCredentialFields.SSH_PRIVATE_KEY,
  ProviderCredentialFields.SSH_KNOWN_HOSTS,
  ProviderCredentialFields.SSH_KEY_PASSPHRASE,
] as const;

export const buildIacSecretExtras = (formData: FormData): IacSecretExtras => {
  const extras: IacSecretExtras = {};
  const username = readText(formData, ProviderCredentialFields.IAC_USERNAME);
  if (username) extras[ProviderCredentialFields.IAC_USERNAME] = username;
  for (const field of IAC_SSH_FIELDS) {
    const value = formData.get(field);
    if (typeof value === "string" && value.trim() !== "") {
      extras[field] =
        field === ProviderCredentialFields.SSH_KEY_PASSPHRASE
          ? value
          : value.trim();
    }
  }
  return extras;
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
