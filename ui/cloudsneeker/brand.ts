// Product identity for the web app. Upstream files read these values through
// one-line `cloudsneeker-hook` registrations; no other file hard-codes a name
// or an external URL. Keep this file free of upstream names.

export const BRAND = {
  name: "Cloudsneeker",
  // In-app assistant. Chat routes and component names stay unchanged.
  assistantName: "Seeker AI",
  shortName: "Cloudsneeker",
  vendor: "Cloudsneeker",
  tagline: "Cloud security posture, continuously.",
  websiteUrl: "https://cloudsneeker.example",
  docsUrl: "https://docs.cloudsneeker.example",
  supportUrl: "https://support.cloudsneeker.example",
  statusUrl: "",
  termsUrl: "https://cloudsneeker.example/terms",
  privacyUrl: "https://cloudsneeker.example/privacy",
  pricingUrl: "",
  // Served from ui/public; replace the files with the final artwork.
  logoMarkPath: "/brand/cloudsneeker-mark.svg",
  logoWordmarkPath: "/brand/cloudsneeker-wordmark.svg",
  faviconPath: "/brand/cloudsneeker-mark.svg",
  // CloudFormation template used by the AWS quick-create links.
  cloudformationTemplateUrl:
    "https://docs.cloudsneeker.example/templates/cloudsneeker-scan-role.yml",
  cloudformationStackName: "Cloudsneeker",
  // Name pre-filled in third-party token creation forms.
  credentialDisplayName: "Cloudsneeker Security Scanner",
  // Service identifier reported by /api/health.
  serviceId: "cloudsneeker-ui",
  // SAML service-provider entity ID; must match the API's `saml_sp_entity_id`.
  samlSpEntityId: "urn:cloudsneeker:sp",
  // Analytics survey name.
  surveyName: "Cloudsneeker Feedback",
  // Copy for controls that the current edition does not enable.
  unavailableFeatureCopy: "Not available in this edition",
  // Hosted-tier upsell. The product has one edition, so prompts stay hidden.
  showUpsell: false,
  // In-product "Learn more" / docs catalog links stay off for this edition.
  showDocumentationLinks: false,
} as const;

export type Brand = typeof BRAND;

export const docsUrl = (path = ""): string => {
  const base = BRAND.docsUrl.replace(/\/$/, "");
  if (!path) return base;
  return `${base}/${path.replace(/^\//, "")}`;
};

export const checkDocsUrl = (checkId: string): string =>
  docsUrl(`checks/${encodeURIComponent(checkId)}`);
