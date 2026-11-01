// Types for the MFA API (`/mfa`, EB-008). Keys match
// `cloudsneeker_api.services.mfa.status`.

export interface MfaStatusAttributes {
  enabled: boolean;
  pending: boolean;
  /** False for SAML and social sign-in users: their identity provider owns MFA. */
  applies: boolean;
  tenant_requires_mfa: boolean;
  enrolment_required: boolean;
  recovery_codes_remaining: number;
  confirmed_at: string | null;
}

export interface MfaStatusResource {
  type: "cloudsneeker-mfa-status";
  id: string;
  attributes: MfaStatusAttributes;
}

export interface MfaEnrolmentAttributes {
  secret: string;
  otpauth_uri: string;
}

export interface MfaRecoveryCodesAttributes {
  codes: string[];
}
