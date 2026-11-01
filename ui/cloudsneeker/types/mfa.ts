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

/** `GET /sso/policy` (EB-009). */
export interface SsoPolicyAttributes {
  reject_idp_initiated_sso: boolean;
  /** AuthnRequests are signed with the platform's SP key. */
  signed_requests: boolean;
  signed_assertions_required: boolean;
}

export interface SsoPolicyResource {
  type: "cloudsneeker-sso-policies";
  id: string;
  attributes: SsoPolicyAttributes;
}
