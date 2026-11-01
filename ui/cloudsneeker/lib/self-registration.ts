// Switch to close self sign-up (EB-002). The API refuses uninvited sign-ups
// with the same env var (`cloudsneeker_api/signup.py`); this hides the
// sign-up link and page to match. Read on the server only: the sign-in and
// sign-up pages and the memberships card are server components.

export const SELF_REGISTRATION_ENV = "CLOUDSNEEKER_SELF_REGISTRATION_ENABLED";

/** On unless the env var is "false". */
export const isCloudsneekerSelfRegistrationEnabled = (): boolean =>
  (process.env[SELF_REGISTRATION_ENV] ?? "").trim().toLowerCase() !== "false";
