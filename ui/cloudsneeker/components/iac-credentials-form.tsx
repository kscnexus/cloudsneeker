import Link from "next/link";
import { Control } from "react-hook-form";

import { BITBUCKET_IMPORT_ROUTE } from "@/cloudsneeker/routes";
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
          credentials. For private repositories provide a read-only access
          token, plus a username where the host needs one. Adding a whole
          Bitbucket workspace?{" "}
          <Link href={BITBUCKET_IMPORT_ROUTE} className="underline">
            Import its repositories
          </Link>
          .
        </div>
      </div>
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.ACCESS_TOKEN}
        label="Access token (optional for public repos)"
        labelPlacement="inside"
        placeholder="Access token, personal access token or API token"
        variant="bordered"
        type="password"
        isRequired={false}
      />
      <WizardInputField
        control={control}
        name={ProviderCredentialFields.IAC_USERNAME}
        label="Username (Bitbucket API tokens and personal tokens, Azure DevOps)"
        labelPlacement="inside"
        placeholder="Leave empty for GitHub, GitLab and Bitbucket access tokens"
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
