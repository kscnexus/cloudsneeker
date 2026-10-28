import { Control } from "react-hook-form";

import { WizardInputField } from "@/components/providers/workflow/forms/fields";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { IacCredentials } from "@/types";

export const IAC_SUPPORTED_GIT_HOSTS =
  "GitHub / GitHub Enterprise, GitLab, Bitbucket Cloud & Server, Azure DevOps and other HTTPS Git servers";

export const IacCredentialsForm = ({
  control,
}: {
  control: Control<IacCredentials>;
}) => {
  return (
    <>
      <div className="flex flex-col">
        <div className="text-md text-text-neutral-primary leading-9 font-bold">
          Connect via Repository
        </div>
        <div className="text-text-neutral-tertiary text-sm">
          Supports {IAC_SUPPORTED_GIT_HOSTS}. Public repositories need no
          credentials. For private repositories provide an access token, or a
          username with an app password.
        </div>
      </div>
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.ACCESS_TOKEN}
        label="Access token / app password (optional for public repos)"
        labelPlacement="inside"
        placeholder="Personal access token or app password"
        variant="bordered"
        type="password"
        isRequired={false}
      />
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.IAC_USERNAME}
        label="Username (Bitbucket app passwords, Azure DevOps, Bitbucket Server)"
        labelPlacement="inside"
        placeholder="Leave empty for GitHub and GitLab tokens"
        variant="bordered"
        type="text"
        isRequired={false}
        autoCapitalize="off"
        autoCorrect="off"
        spellCheck={false}
      />
    </>
  );
};
