// Sign-in and sign-up field hints for browsers and password managers. Read by
// the upstream `CustomInput` through one `cloudsneeker-hook`.

interface AutoCompleteInput {
  type?: string;
  password?: boolean;
  confirmPassword?: boolean;
}

/** `autocomplete` value for an auth field, or `undefined` for other inputs. */
export const authAutoComplete = ({
  type,
  password,
  confirmPassword,
}: AutoCompleteInput): string | undefined => {
  if (confirmPassword) return "new-password";
  if (password) return "current-password";
  if (type === "email") return "email";
  return undefined;
};
