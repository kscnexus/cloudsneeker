// Social sign-in buttons that are not set up point at upstream docs and
// cannot be used, so the sign-in page leaves them out. Read by the upstream
// `SocialButtons` through one `cloudsneeker-hook`.

interface SocialProviderState {
  isOAuthEnabled?: boolean;
  url?: string;
}

/** The provider is configured and has a sign-in URL. */
export const isSocialProviderReady = ({
  isOAuthEnabled,
  url,
}: SocialProviderState): boolean => Boolean(isOAuthEnabled && url);

/** Visible button text from the upstream label ("Continue with Github"). */
export const socialProviderName = (label: string): string =>
  label.replace(/^Continue with /, "").replace(/^Github$/, "GitHub");
