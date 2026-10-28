import { TriangleAlert } from "lucide-react";
import { Control } from "react-hook-form";

import { BRAND } from "@/cloudsneeker/brand";
import { REGISTRY_INSECURE_VALUE } from "@/cloudsneeker/lib/provider-secret-extras";
import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { Checkbox } from "@/components/shadcn/checkbox/checkbox";
import { FormControl, FormField } from "@/components/shadcn/form";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { ImageCredentials } from "@/types";

export const ECR_HELP_TEXT = `For private Amazon ECR, leave username/password empty. ${BRAND.name} mints a short-lived ECR token with this IAM role (or its own task role when empty).`;

export const REGISTRY_INSECURE_LABEL =
  "Allow self-signed / insecure registry (TLS verification off)";

const REGISTRY_INSECURE_ID = "registry_insecure";

export const ImageRegistryExtraFields = ({
  control,
}: {
  control: Control<ImageCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col pt-2">
        <div className="text-md text-text-neutral-primary leading-9 font-bold">
          Amazon ECR (IAM)
        </div>
        <div className="text-text-neutral-tertiary text-sm">
          {ECR_HELP_TEXT}
        </div>
      </div>
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.ECR_ROLE_ARN}
        label="ECR Role ARN (Optional)"
        labelPlacement="inside"
        placeholder="arn:aws:iam::123456789012:role/ECRReadOnly"
        variant="bordered"
        type="text"
        isRequired={false}
        autoCapitalize="off"
        autoCorrect="off"
        spellCheck={false}
      />
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.ECR_EXTERNAL_ID}
        label="ECR External ID (Optional)"
        labelPlacement="inside"
        placeholder="External ID required by the role trust policy"
        variant="bordered"
        type="text"
        isRequired={false}
        autoCapitalize="off"
        autoCorrect="off"
        spellCheck={false}
      />

      <FormField
        control={control}
        name={ProviderCredentialFields.REGISTRY_INSECURE}
        render={({ field }) => (
          <FormControl>
            <div className="flex flex-col gap-2 pt-2">
              <div className="flex items-center gap-2">
                <Checkbox
                  id={REGISTRY_INSECURE_ID}
                  size="sm"
                  checked={field.value === REGISTRY_INSECURE_VALUE.ON}
                  onCheckedChange={(checked) =>
                    field.onChange(
                      checked === true
                        ? REGISTRY_INSECURE_VALUE.ON
                        : REGISTRY_INSECURE_VALUE.OFF,
                    )
                  }
                />
                <label
                  htmlFor={REGISTRY_INSECURE_ID}
                  className="cursor-pointer text-sm"
                >
                  {REGISTRY_INSECURE_LABEL}
                </label>
              </div>
              <div className="bg-bg-warning-secondary border-border-neutral-secondary flex items-start gap-2 rounded-lg border p-3">
                <TriangleAlert
                  size={16}
                  className="text-text-warning-primary mt-0.5 shrink-0"
                />
                <p className="text-text-warning-primary text-xs">
                  Only enable for internal registries with self-signed
                  certificates. Image pulls skip TLS verification, so traffic
                  can be intercepted.
                </p>
              </div>
            </div>
          </FormControl>
        )}
      />
    </>
  );
};
