import { BRAND, docsUrl } from "@/cloudsneeker/brand"; // cloudsneeker-hook

import type { IntegrationType } from "../types/integrations";
import {
  PROVIDER_WIZARD_STEP,
  type ProviderWizardStep,
} from "../types/provider-wizard";

// Documentation URLs
export const DOCS_URLS = {
  FINDINGS_ANALYSIS: docsUrl(
    "user-guide/tutorials/app#step-8:-analyze-the-findings",
  ),
  FINDINGS_INGESTION: docsUrl("user-guide/tutorials/app-import-findings"),
  FINDINGS_TRIAGE: docsUrl("user-guide/tutorials/app-findings-triage"),
  AWS_ORGANIZATIONS: docsUrl("user-guide/tutorials/aws-organizations"),
  AZURE_ORGANIZATIONS: docsUrl("user-guide/tutorials/azure-management-groups"),
  GCP_ORGANIZATIONS: docsUrl("user-guide/tutorials/gcp-organizations"),
  ALERTS: docsUrl("user-guide/tutorials/app-alerts"),
  SLACK_INTEGRATION: docsUrl("user-guide/tutorials/app-slack-integration"),
  SLACK_INTEGRATION_PRIVATE_CHANNELS: docsUrl(
    "user-guide/tutorials/app-slack-integration#why-a-private-channel-is-missing-from-the-channel-list",
  ),
  SCAN_CONFIGURATION: docsUrl("user-guide/tutorials/app-scan-configuration"),
  ATTACK_PATHS_CUSTOM_QUERIES: docsUrl(
    "user-guide/tutorials/app-attack-paths#writing-custom-opencypher-queries",
  ),
  AI_AGENTS: docsUrl("user-guide/ai-agents/"),
} as const;

// Prowler Hub — the public catalog of Prowler artifacts (checks, compliance,
// attack paths). Every built-in Attack Paths query has a page keyed by its
// query id, e.g. https://hub.prowler.com/attack-paths/aws-sts-privesc-assume-role
export const PROWLER_HUB_URL = BRAND.docsUrl; // cloudsneeker-hook

export const getAttackPathHubUrl = (queryId: string): string =>
  `${PROWLER_HUB_URL}/attack-paths/${encodeURIComponent(queryId)}`;

// CloudFormation template URL for the ProwlerScan role.
// Also used (URL-encoded) as the templateURL param in the quick-create links
// built by getAWSCredentialsTemplateLinks and getAWSOrgDeploymentQuickLink below.
export const PROWLER_CF_TEMPLATE_URL = BRAND.cloudformationTemplateUrl; // cloudsneeker-hook

// Prowler Cloud billing/subscription management page.
export const BILLING_URL = `${BRAND.websiteUrl}/billing`; // cloudsneeker-hook

// Base URL for the CloudFormation "quick create stack" console flow.
// Hardcoded to us-east-1 because the public template is hosted for that flow.
const CF_QUICKCREATE_BASE_URL =
  "https://us-east-1.console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/quickcreate";

// Deep links that open each provider's cloud console with the credential
// creation form pre-filled with the exact permissions, scopes and name
// Prowler needs. The full 16-provider audit (which providers support this and
// which do not) lives in the PROWLER-2187 PR description; keep both in sync
// when adding or removing entries here.
// AWS has its own CloudFormation quick-create link built in
// `getAWSCredentialsTemplateLinks` below.
export const PRECONFIGURED_CREDENTIAL_URLS = {
  // Opens the Cloudflare "Create Custom Token" form under the user profile
  // pre-filled with the seven read-only scopes Prowler needs (`Account
  // Settings`, `Zone`, `Zone Settings`, `DNS`, `SSL and Certificates`,
  // `Bot Management`, `Zone WAF`) and the token name.
  // Kept in sync with the "User API Token" URL published in
  // docs/user-guide/providers/cloudflare/authentication.mdx.
  CLOUDFLARE_API_TOKEN_USER: `https://dash.cloudflare.com/profile/api-tokens?permissionGroupKeys=%5B%7B%22key%22%3A%22account_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22zone%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22zone_settings%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22dns%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22ssl_and_certificates%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22bot_management%22%2C%22type%22%3A%22read%22%7D%2C%7B%22key%22%3A%22zone_waf%22%2C%22type%22%3A%22read%22%7D%5D&accountId=%2A&zoneId=all&name=${encodeURIComponent(BRAND.credentialDisplayName)}`,
  // Opens the GitHub fine-grained PAT creation form pre-filled with the four
  // read-only permissions Prowler needs to scan a user's own repositories.
  // Kept in sync with the "user repositories" URL published in
  // docs/user-guide/providers/github/authentication.mdx.
  GITHUB_PERSONAL_ACCESS_TOKEN_USER: `https://github.com/settings/personal-access-tokens/new?name=${encodeURIComponent(BRAND.credentialDisplayName)}&description=${encodeURIComponent(`Fine-grained PAT for ${BRAND.name} security scanning`)}&expires_in=90&administration=read&contents=read&vulnerability_alerts=read&emails=read`,
} as const;

// Builds the account-owned Cloudflare API Token URL for the given account.
// Uses the dashboard router pattern (`?to=/<accountId>/api-tokens&...`)
// published in docs/user-guide/providers/cloudflare/authentication.mdx, with
// the account id substituted in place of the docs' `:account` placeholder to
// avoid ambiguity when the user is signed into multiple accounts. Navigating
// directly to `/<accountId>/api-tokens/create` does NOT pre-fill the form —
// Cloudflare only reads the pre-fill params when they arrive via the router.
// Same seven read-only scopes as the user token URL.
export const buildCloudflareAccountOwnedApiTokenUrl = (
  accountId: string,
): string => {
  // Cloudflare's router expects the `to=` value with unencoded slashes; using
  // URLSearchParams would percent-encode them and break the redirect, so we
  // assemble the query string manually and only encode the pieces that need
  // it.
  const encodedAccountId = encodeURIComponent(accountId);
  const permissionGroupKeys = encodeURIComponent(
    JSON.stringify([
      { key: "account_settings", type: "read" },
      { key: "zone", type: "read" },
      { key: "zone_settings", type: "read" },
      { key: "dns", type: "read" },
      { key: "ssl_and_certificates", type: "read" },
      { key: "bot_management", type: "read" },
      { key: "zone_waf", type: "read" },
    ]),
  );
  const name = encodeURIComponent(BRAND.credentialDisplayName);
  return `https://dash.cloudflare.com/?to=/${encodedAccountId}/api-tokens&permissionGroupKeys=${permissionGroupKeys}&name=${name}`;
};

// Builds the organization-scoped GitHub fine-grained PAT URL. GitHub validates
// permissions against the token's Resource Owner and only surfaces
// `organization_administration` and `members` when it is an organization, so
// we pin the owner via `target_name` and skip account-only permissions
// (`emails`) that the docs' org template does not request. Kept in sync with
// the "organization scanning" URL published in
// docs/user-guide/providers/github/authentication.mdx.
export const buildGitHubPersonalAccessTokenOrgUrl = (
  targetName: string,
): string => {
  const params = new URLSearchParams({
    name: BRAND.credentialDisplayName,
    description: `Fine-grained PAT for ${BRAND.name} organization security scanning`,
    expires_in: "90",
    target_name: targetName,
    administration: "read",
    contents: "read",
    vulnerability_alerts: "read",
    organization_administration: "read",
    members: "read",
  });
  return `https://github.com/settings/personal-access-tokens/new?${params.toString()}`;
};

export interface AWSOrgDeploymentQuickLinkParams {
  externalId: string;
  organizationalUnitId: string;
  deployFromDelegatedAdmin?: boolean;
}

const buildCloudFormationQuickCreateLink = (
  parameters: Record<string, string>,
): string => {
  const searchParams = new URLSearchParams({
    templateURL: PROWLER_CF_TEMPLATE_URL,
    stackName: BRAND.cloudformationStackName,
    ...parameters,
  });

  return `${CF_QUICKCREATE_BASE_URL}?${searchParams.toString()}`;
};

// Shortlinks are used for all wizard steps except credentials so link
// ownership stays with the docs/marketing team: they can retarget
// destinations from the shortener panel without a UI PR.
const PROVIDER_DOCS_SHORTLINK: Record<string, string> = {
  aws: docsUrl("user-guide/providers/aws"),
  azure: docsUrl("user-guide/providers/azure"),
  m365: docsUrl("user-guide/providers/m365"),
  gcp: docsUrl("user-guide/providers/gcp"),
  kubernetes: docsUrl("user-guide/providers/k8s"),
  github: docsUrl("user-guide/providers/github"),
  iac: docsUrl("user-guide/providers/iac"),
  image: docsUrl("user-guide/providers/image"),
  oraclecloud: docsUrl("user-guide/providers/oraclecloud"),
  mongodbatlas: docsUrl("user-guide/providers/mongodbatlas"),
  alibabacloud: docsUrl("user-guide/providers/alibabacloud"),
  cloudflare: docsUrl("user-guide/providers/cloudflare"),
  openstack: docsUrl("user-guide/providers/openstack"),
  googleworkspace: docsUrl("user-guide/providers/googleworkspace"),
  vercel: docsUrl("user-guide/providers/vercel"),
  okta: docsUrl("user-guide/providers/okta"),
};

// Default target for the credentials step: the section of the provider's
// getting-started page that introduces the credentials flow. The getting-
// started page keeps the user in the same mental model as the wizard, and
// each section already links to `authentication.mdx` for readers who need
// deeper detail. That indirection is intentional — we do NOT deep-link into
// `authentication.mdx` from the wizard, otherwise the user is jumped into
// low-level docs before they have the context to make sense of them.
const PROVIDER_CREDENTIALS_STEP_DOCS_URL: Record<string, string> = {
  aws: docsUrl(
    "user-guide/providers/aws/getting-started-aws#step-3-set-up-aws-authentication",
  ),
  azure: docsUrl(
    "user-guide/providers/azure/getting-started-azure#step-3-add-credentials",
  ),
  m365: docsUrl(
    "user-guide/providers/microsoft365/getting-started-m365#step-3-choose-and-provide-authentication",
  ),
  gcp: docsUrl(
    "user-guide/providers/gcp/getting-started-gcp#step-3-set-up-gcp-authentication",
  ),
  kubernetes: docsUrl(
    "user-guide/providers/kubernetes/getting-started-k8s#step-2-configure-kubernetes-authentication",
  ),
  github: docsUrl(
    "user-guide/providers/github/getting-started-github#step-3-choose-authentication-method",
  ),
  iac: docsUrl(
    "user-guide/providers/iac/getting-started-iac#step-2-enter-authentication-details",
  ),
  image: docsUrl(
    "user-guide/providers/image/getting-started-image#step-2-enter-authentication-and-scan-filters",
  ),
  oraclecloud: docsUrl(
    "user-guide/providers/oci/getting-started-oci#step-3-add-oci-api-key-credentials",
  ),
  mongodbatlas: docsUrl(
    "user-guide/providers/mongodbatlas/getting-started-mongodbatlas#step-2-provide-api-credentials",
  ),
  alibabacloud: docsUrl(
    "user-guide/providers/alibabacloud/getting-started-alibabacloud#step-3-choose-and-provide-authentication",
  ),
  cloudflare: docsUrl(
    "user-guide/providers/cloudflare/getting-started-cloudflare#step-3-choose-and-provide-authentication",
  ),
  openstack: docsUrl(
    "user-guide/providers/openstack/getting-started-openstack#step-2-provide-credentials",
  ),
  googleworkspace: docsUrl(
    "user-guide/providers/googleworkspace/getting-started-googleworkspace#step-3-provide-credentials",
  ),
  vercel: docsUrl(
    "user-guide/providers/vercel/getting-started-vercel#step-2-provide-credentials",
  ),
  okta: docsUrl(
    "user-guide/providers/okta/getting-started-okta#step-2-provide-credentials",
  ),
};

// When the user has picked a specific auth method inside the credentials
// step, jump directly to that method's subsection in the getting-started
// page. Only providers whose docs have a heading per method are listed —
// GCP and GitHub render their methods inside a Mintlify `<Tabs>` component
// so a per-method anchor isn't available today; they fall back to the
// general step URL above.
const PROVIDER_CREDENTIALS_METHOD_DOCS_URL: Record<
  string,
  Record<string, string>
> = {
  aws: {
    role: docsUrl(
      "user-guide/providers/aws/getting-started-aws#assume-role-recommended",
    ),
    credentials: docsUrl(
      "user-guide/providers/aws/getting-started-aws#credentials-static-access-keys",
    ),
  },
  m365: {
    app_certificate: docsUrl(
      "user-guide/providers/microsoft365/getting-started-m365#application-certificate-authentication-recommended",
    ),
    app_client_secret: docsUrl(
      "user-guide/providers/microsoft365/getting-started-m365#application-client-secret-authentication",
    ),
  },
  alibabacloud: {
    role: docsUrl(
      "user-guide/providers/alibabacloud/getting-started-alibabacloud#ram-role-assumption-recommended",
    ),
    credentials: docsUrl(
      "user-guide/providers/alibabacloud/getting-started-alibabacloud#credentials-static-access-keys",
    ),
  },
  cloudflare: {
    api_token: docsUrl(
      "user-guide/providers/cloudflare/getting-started-cloudflare#user-api-token-authentication-recommended",
    ),
    api_key: docsUrl(
      "user-guide/providers/cloudflare/getting-started-cloudflare#api-key-and-email-authentication-legacy",
    ),
  },
};

const PROVIDER_HELP_FALLBACK_URL = docsUrl("user-guide/providers");

const getOwnRecordValue = <T>(
  record: Readonly<Record<string, T>>,
  key: string,
): T | undefined => (Object.hasOwn(record, key) ? record[key] : undefined);

const resolveDocsLink = (
  provider: string,
  step?: ProviderWizardStep,
  credentialsMethod?: string | null,
) => {
  const shortlink = getOwnRecordValue(PROVIDER_DOCS_SHORTLINK, provider);

  if (step === PROVIDER_WIZARD_STEP.CREDENTIALS) {
    if (credentialsMethod) {
      const methodDocs = getOwnRecordValue(
        PROVIDER_CREDENTIALS_METHOD_DOCS_URL,
        provider,
      );
      const methodUrl = methodDocs
        ? getOwnRecordValue(methodDocs, credentialsMethod)
        : undefined;
      if (methodUrl) return methodUrl;
    }

    const stepUrl = getOwnRecordValue(
      PROVIDER_CREDENTIALS_STEP_DOCS_URL,
      provider,
    );
    if (stepUrl) return stepUrl;
  }

  return shortlink;
};

const PROVIDER_HELP_TEXT: Record<string, string> = {
  aws: "Need help connecting your AWS account?",
  azure: "Need help connecting your Azure subscription?",
  m365: "Need help connecting your Microsoft 365 account?",
  gcp: "Need help connecting your GCP project?",
  kubernetes: "Need help connecting your Kubernetes cluster?",
  github: "Need help connecting your GitHub account?",
  iac: "Need help scanning your Infrastructure as Code repository?",
  image: "Need help scanning your container registry?",
  oraclecloud: "Need help connecting your Oracle Cloud account?",
  mongodbatlas: "Need help connecting your MongoDB Atlas organization?",
  alibabacloud: "Need help connecting your Alibaba Cloud account?",
  cloudflare: "Need help connecting your Cloudflare account?",
  openstack: "Need help connecting your OpenStack cloud?",
  googleworkspace: "Need help connecting your Google Workspace account?",
  vercel: "Need help connecting your Vercel team?",
  okta: "Need help connecting your Okta organization?",
};

export const getProviderHelpText = (
  provider: string,
  step?: ProviderWizardStep,
  credentialsMethod?: string | null,
) => {
  const link = resolveDocsLink(provider, step, credentialsMethod);

  if (!link) {
    // Unknown provider: hand off to the generic help shortlink instead of
    // deep-linking into a page that may not exist.
    return {
      text: "How to setup a provider?",
      link: PROVIDER_HELP_FALLBACK_URL,
    };
  }

  return {
    text:
      getOwnRecordValue(PROVIDER_HELP_TEXT, provider) ??
      "Need help connecting your provider?",
    link,
  };
};

export const getAWSCredentialsTemplateLinks = (
  externalId: string,
  bucketName?: string,
  integrationType?: IntegrationType,
  bucketAccountId?: string,
): {
  cloudformation: string;
  terraform: string;
  cloudformationQuickLink: string;
} => {
  let links = {};

  if (integrationType === undefined || integrationType === "aws_security_hub") {
    links = {
      cloudformation: BRAND.cloudformationTemplateUrl,
      terraform: docsUrl("user-guide/providers/aws/templates/terraform"),
    };
  }

  if (integrationType === "amazon_s3") {
    links = {
      cloudformation: docsUrl("user-guide/tutorials/app-s3-integration"),
      terraform: docsUrl("user-guide/tutorials/app-s3-integration#terraform"),
    };
  }

  // The template requires S3IntegrationBucketAccountId (owner account of the
  // bucket) whenever EnableS3Integration is true. Only enable S3 when both the
  // bucket name and its account id are known, otherwise an incomplete link
  // would fail stack validation on the quick-create flow (reachable from the
  // edit-credentials flow, where the account id can resolve to an empty value).
  const parameters: Record<string, string> = {
    param_ExternalId: externalId,
  };

  if (bucketName && bucketAccountId) {
    parameters.param_EnableS3Integration = "true";
    parameters.param_S3IntegrationBucketName = bucketName;
    parameters.param_S3IntegrationBucketAccountId = bucketAccountId;
  }

  return {
    ...(links as {
      cloudformation: string;
      terraform: string;
    }),
    cloudformationQuickLink: buildCloudFormationQuickCreateLink(parameters),
  };
};

// Builds the CloudFormation quick-create link that onboards an entire AWS
// Organization in a single stack: it creates the ProwlerScan role in the
// account launching the stack (DeployLocalRole) and a service-managed StackSet
// that rolls the role out to the member accounts under the given OU/root
// (DeployStackSet). By default the stack is launched from the management
// account; set deployFromDelegatedAdmin when launching from a delegated
// administrator account instead, where the local role lands in that account.
export const getAWSOrgDeploymentQuickLink = ({
  externalId,
  organizationalUnitId,
  deployFromDelegatedAdmin = false,
}: AWSOrgDeploymentQuickLinkParams): string => {
  const parameters: Record<string, string> = {
    param_ExternalId: externalId,
    param_EnableOrganizations: "true",
    param_DeployLocalRole: "true",
    param_DeployStackSet: "true",
    param_AWSOrganizationalUnitId: organizationalUnitId,
  };

  if (deployFromDelegatedAdmin) {
    parameters.param_DeployFromDelegatedAdmin = "true";
  }

  return buildCloudFormationQuickCreateLink(parameters);
};
