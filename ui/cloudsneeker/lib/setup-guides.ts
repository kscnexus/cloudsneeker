import { BRAND } from "@/cloudsneeker/brand";
import { getProviderDisplayName } from "@/types/providers";

// In-app setup guides: how to create the credential each provider or
// integration form asks for, the URLs to register on the other side, and how
// to keep the connection least-privilege. Copy lives here so the forms only
// mount one button.

/** Placeholders replaced with this deployment's URLs when a guide renders. */
export const SETUP_GUIDE_URL_TOKEN = {
  APP: "{appUrl}",
  API: "{apiUrl}",
} as const;

export interface SetupGuideUrls {
  appUrl: string;
  apiUrl: string;
}

/** A value the user copies into the other system (redirect URL, scope list). */
export interface SetupGuideValue {
  label: string;
  value: string;
  note?: string;
}

export interface SetupGuideLink {
  label: string;
  href: string;
}

export interface SetupGuideStep {
  title: string;
  body: string;
  points?: readonly string[];
  link?: SetupGuideLink;
}

export interface SetupGuide {
  title: string;
  summary: string;
  values?: readonly SetupGuideValue[];
  steps: readonly SetupGuideStep[];
  security: readonly string[];
}

const { APP, API } = SETUP_GUIDE_URL_TOKEN;
const PRODUCT = BRAND.name;

const ROTATE =
  "Rotate the credential on a schedule and after any staff change.";
const DEDICATED = `Create a dedicated identity for ${PRODUCT}; do not reuse a personal or administrator account.`;
const STORED = `${PRODUCT} stores the secret encrypted and never shows it again after you save.`;

const PROVIDER_GUIDES = {
  "aws:role": {
    title: "AWS: IAM role (recommended)",
    summary: `${PRODUCT} assumes a read-only role in your account. No long-lived key leaves AWS.`,
    steps: [
      {
        title: "Create the scan role",
        body: "In IAM, create a role for another AWS account, or launch the CloudFormation / Terraform template linked in the form.",
        points: [
          "Attach the AWS managed policies SecurityAudit and ViewOnlyAccess.",
          "Require the External ID shown in the form in the role's trust policy.",
        ],
        link: {
          label: "Open IAM roles",
          href: "https://console.aws.amazon.com/iam/home#/roles",
        },
      },
      {
        title: "Copy the role ARN",
        body: "Open the role and copy its ARN (arn:aws:iam::<account-id>:role/<name>).",
      },
      {
        title: "Paste it in the form",
        body: "Enter the Role ARN. Keep the External ID exactly as shown; it ties the role to your tenant.",
      },
    ],
    security: [
      "Never remove the External ID condition from the trust policy: it prevents another tenant from using your role.",
      "Keep the role read-only. Do not attach AdministratorAccess or write policies.",
    ],
  },
  "aws:credentials": {
    title: "AWS: access keys",
    summary:
      "A read-only IAM user's access key. Use the role method when you can.",
    steps: [
      {
        title: "Create an IAM user",
        body: "Create a user without console access and attach SecurityAudit and ViewOnlyAccess.",
        link: {
          label: "Open IAM users",
          href: "https://console.aws.amazon.com/iam/home#/users",
        },
      },
      {
        title: "Create an access key",
        body: "Under Security credentials, create an access key and copy the Access Key ID and Secret Access Key. AWS shows the secret once.",
      },
      {
        title: "Paste both values",
        body: "Add a session token only when you use temporary credentials.",
      },
    ],
    security: [DEDICATED, ROTATE, "Never use root account keys."],
  },
  azure: {
    title: "Azure: app registration",
    summary:
      "A Microsoft Entra app (service principal) with read access to the subscriptions you scan.",
    steps: [
      {
        title: "Register an application",
        body: "Microsoft Entra ID > App registrations > New registration. Copy the Application (client) ID and Directory (tenant) ID.",
        link: {
          label: "Open App registrations",
          href: "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
        },
      },
      {
        title: "Create a client secret",
        body: "Certificates & secrets > New client secret. Copy the secret Value (not the Secret ID); it is shown once.",
      },
      {
        title: "Grant Microsoft Graph permissions",
        body: "API permissions > Microsoft Graph > Application permissions, then grant admin consent:",
        points: ["AuditLog.Read.All", "Directory.Read.All", "Policy.Read.All"],
      },
      {
        title: "Assign Reader on each subscription",
        body: "Subscription > Access control (IAM) > Add role assignment > Reader, and select the application.",
      },
    ],
    security: [
      "Set an expiry on the client secret and renew it before it lapses.",
      "Grant Reader only on the subscriptions you want scanned.",
      STORED,
    ],
  },
  "m365:app_certificate": {
    title: "Microsoft 365: app certificate (recommended)",
    summary:
      "A Microsoft Entra app that authenticates with a certificate. Covers every check, including the PowerShell ones.",
    steps: [
      {
        title: "Register an application",
        body: "Microsoft Entra ID > App registrations > New registration. Copy the Application (client) ID and Directory (tenant) ID.",
        link: {
          label: "Open App registrations",
          href: "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
        },
      },
      {
        title: "Grant read permissions",
        body: "Add these application permissions and grant admin consent:",
        points: [
          "Microsoft Graph: AuditLog.Read.All, Directory.Read.All, Policy.Read.All, SharePointTenantSettings.Read.All",
          "Office 365 Exchange Online: Exchange.ManageAsApp",
          "Assign the Global Reader role to the application.",
        ],
      },
      {
        title: "Upload a certificate",
        body: "Create a certificate, upload its public part (.cer) under Certificates & secrets > Certificates, and keep the private part (.pfx) for the form.",
      },
      {
        title: "Paste the certificate",
        body: "Enter the Base64-encoded content of the certificate with its private key, plus the client ID and tenant ID.",
      },
    ],
    security: [
      "Generate the certificate for this connection only and give it an expiry.",
      "Keep the private key out of email and chat; paste it straight into the form.",
      STORED,
    ],
  },
  "m365:app_client_secret": {
    title: "Microsoft 365: client secret",
    summary:
      "A Microsoft Entra app that authenticates with a client secret. Prefer the certificate method.",
    steps: [
      {
        title: "Register an application",
        body: "Microsoft Entra ID > App registrations > New registration. Copy the Application (client) ID and Directory (tenant) ID.",
        link: {
          label: "Open App registrations",
          href: "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
        },
      },
      {
        title: "Grant read permissions",
        body: "Add these application permissions and grant admin consent:",
        points: [
          "Microsoft Graph: AuditLog.Read.All, Directory.Read.All, Policy.Read.All, SharePointTenantSettings.Read.All",
          "Office 365 Exchange Online: Exchange.ManageAsApp",
          "Assign the Global Reader role to the application.",
        ],
      },
      {
        title: "Create a client secret",
        body: "Certificates & secrets > New client secret. Copy the secret Value; it is shown once.",
      },
    ],
    security: [
      "Set an expiry on the client secret and renew it before it lapses.",
      STORED,
    ],
  },
  "gcp:service-account": {
    title: "Google Cloud: service account key",
    summary: "A read-only service account and its JSON key.",
    steps: [
      {
        title: "Create a service account",
        body: "IAM & Admin > Service Accounts > Create service account, in the project you scan.",
        link: {
          label: "Open Service Accounts",
          href: "https://console.cloud.google.com/iam-admin/serviceaccounts",
        },
      },
      {
        title: "Grant read access",
        body: "Give it the Viewer role (roles/viewer) on each project to scan.",
      },
      {
        title: "Create a JSON key",
        body: "Open the service account > Keys > Add key > Create new key > JSON. A file downloads.",
      },
      {
        title: "Paste the key",
        body: "Paste the whole JSON file content into the form.",
      },
    ],
    security: [
      "Delete the downloaded key file once it is saved here.",
      "Grant Viewer only; never Editor or Owner.",
      ROTATE,
    ],
  },
  "gcp:credentials": {
    title: "Google Cloud: application default credentials",
    summary:
      "The client ID, client secret and refresh token of a user signed in with gcloud.",
    steps: [
      {
        title: "Sign in with gcloud",
        body: "Run `gcloud auth application-default login` with a user that has the Viewer role on the projects to scan.",
      },
      {
        title: "Open the credentials file",
        body: "gcloud writes application_default_credentials.json to its config folder (~/.config/gcloud on Linux and macOS, %APPDATA%\\gcloud on Windows).",
      },
      {
        title: "Copy the three values",
        body: "Paste client_id, client_secret and refresh_token into the form.",
      },
    ],
    security: [
      "These credentials act as the signed-in user. Prefer a service account for a lasting connection.",
      "Revoke them with `gcloud auth application-default revoke` when no longer needed.",
    ],
  },
  "github:personal_access_token": {
    title: "GitHub: fine-grained personal access token",
    summary:
      "A read-only fine-grained token. Fastest to set up; tied to one user.",
    steps: [
      {
        title: "Start a fine-grained token",
        body: "GitHub > Settings > Developer settings > Personal access tokens > Fine-grained tokens > Generate new token.",
        link: {
          label: "Open GitHub token settings",
          href: "https://github.com/settings/personal-access-tokens",
        },
      },
      {
        title: "Choose the resource owner",
        body: "Pick the organization to scan as Resource owner (organization permissions only appear then), and select the repositories.",
      },
      {
        title: "Set read-only permissions",
        body: "Grant Read access, nothing more:",
        points: [
          "Repository: Administration, Contents, Metadata, Dependabot alerts",
          "Organization: Administration, Members",
        ],
      },
      {
        title: "Generate and paste",
        body: "Set an expiration, generate the token and paste it into the form. GitHub shows it once.",
      },
    ],
    security: [
      "Use fine-grained tokens; classic tokens grant far broader access.",
      "Always set an expiration and renew before it lapses.",
      "An organization owner may need to approve the token before it works.",
    ],
  },
  "github:oauth_app": {
    title: "GitHub: OAuth App token",
    summary:
      "An access token issued through an OAuth App your organization owns.",
    steps: [
      {
        title: "Register an OAuth App",
        body: "Organization settings > Developer settings > OAuth Apps > New OAuth App. Enable Device Flow so a token can be issued without a web callback.",
        link: {
          label: "Open GitHub developer settings",
          href: "https://github.com/settings/developers",
        },
      },
      {
        title: "Authorize a user",
        body: "Run the device flow (or your own authorization flow) with the read:org and repo scopes to get a user access token.",
      },
      {
        title: "Paste the access token",
        body: `Enter the issued token. ${PRODUCT} only needs the token; it is not the OAuth callback for this app, so no ${PRODUCT} redirect URL is required.`,
      },
    ],
    security: [
      "OAuth App scopes are coarse (repo grants write). Prefer a GitHub App or a fine-grained token.",
      "Revoke the authorization in GitHub when the connection is removed.",
    ],
  },
  "github:github_app": {
    title: "GitHub: GitHub App (recommended for organizations)",
    summary:
      "An app installed on your organization. Not tied to a person, read-only by permission.",
    steps: [
      {
        title: "Create a GitHub App",
        body: "Organization settings > Developer settings > GitHub Apps > New GitHub App. Disable the webhook; no callback URL is needed.",
        link: {
          label: "Open GitHub Apps",
          href: "https://github.com/settings/apps",
        },
      },
      {
        title: "Set read-only permissions",
        body: "Grant Read access, nothing more:",
        points: [
          "Repository: Administration, Contents, Metadata, Dependabot alerts",
          "Organization: Administration, Members",
        ],
      },
      {
        title: "Generate a private key",
        body: "On the app page, copy the App ID, then Generate a private key. A .pem file downloads.",
      },
      {
        title: "Install the app",
        body: "Install App > choose the organization and the repositories to scan.",
      },
      {
        title: "Paste App ID and key",
        body: "Enter the App ID and the full content of the .pem file, including the BEGIN and END lines.",
      },
      {
        title: "Use the exact account name",
        body: "The provider's account must be the login the app is installed on: the name in github.com/<login>, not a display name. A pending installation request does not count; an organization owner has to approve it.",
      },
      {
        title: "Scan code with the same connection",
        body: "For code scanning, also allow Contents: Read, then go to Integrations > GitHub repositories and pick the repositories. They need no token of their own.",
      },
    ],
    security: [
      "Delete the downloaded .pem once it is saved here.",
      "Install the app only on the repositories you want scanned.",
      "Generate a new private key and remove the old one to rotate.",
    ],
  },
  kubernetes: {
    title: "Kubernetes: kubeconfig",
    summary:
      "A kubeconfig for a read-only service account that reaches the cluster API from outside.",
    steps: [
      {
        title: "Create a read-only service account",
        body: "Create a ServiceAccount and bind it to a ClusterRole limited to get, list and watch.",
      },
      {
        title: "Build a kubeconfig for it",
        body: "Use the cluster's public API server address, its CA certificate and the service account token.",
      },
      {
        title: "Paste the kubeconfig",
        body: "Paste the whole YAML. It must hold one usable context.",
      },
    ],
    security: [
      "Do not paste your personal admin kubeconfig.",
      "Avoid kubeconfigs that call a local exec plugin (aws, gcloud, az): the scanner cannot run it.",
      "Allow the scanner's address on the API server if access is IP-restricted.",
    ],
  },
  iac: {
    title: "Infrastructure as code: repository access",
    summary:
      "Read access to the Git repository. Public repositories need no credential.",
    steps: [
      {
        title: "GitHub: reuse your GitHub connection",
        body: "A github.com repository of an organization or user you already connected as a GitHub provider needs no token: leave the access token empty, or pick repositories under Integrations > GitHub repositories.",
      },
      {
        title: "HTTPS: create a read-only token",
        body: "Create a token that can only read the repository:",
        points: [
          "GitHub: fine-grained token with Contents: Read",
          "GitLab: project access token with read_repository",
          "Bitbucket: repository access token with Repositories: Read",
          "Azure DevOps: personal access token with Code: Read",
        ],
      },
      {
        title: "Add the username when the host needs one",
        body: "Bitbucket app passwords and some self-hosted servers require a username next to the token.",
      },
      {
        title: "SSH: use a deploy key",
        body: "Generate a key pair for this repository only (ssh-keygen -t ed25519), add the public key as a read-only deploy key, and paste the private key. Add the host's known_hosts line so the server is verified.",
      },
    ],
    security: [
      "Scope the token or deploy key to the single repository, read-only.",
      "Always supply known hosts for SSH; without it the server identity is not checked.",
      ROTATE,
    ],
  },
  image: {
    title: "Container images: registry access",
    summary: "Pull-only access to the registry that holds the images.",
    steps: [
      {
        title: "Create a pull-only credential",
        body: "Use a robot account or access token limited to read / pull:",
        points: [
          "Docker Hub: access token with Read-only scope",
          "GitHub Container Registry: token with read:packages",
          "GitLab: deploy token with read_registry",
          "Harbor, Quay, Artifactory: robot account with pull",
        ],
      },
      {
        title: "Amazon ECR: use an IAM role",
        body: "Create a role with AmazonEC2ContainerRegistryReadOnly, trust it with an External ID, and enter the Role ARN and External ID instead of a password.",
      },
      {
        title: "Enter the credential",
        body: "Fill in username and password, or the token, and limit the scan with the image and tag filters.",
      },
    ],
    security: [
      "Never use an account that can push or delete images.",
      "Leave the insecure-registry option off unless the registry has no valid TLS certificate.",
    ],
  },
  oraclecloud: {
    title: "Oracle Cloud: API signing key",
    summary: "An API key for a user that can only inspect the tenancy.",
    steps: [
      {
        title: "Create a user and group",
        body: "Identity > Users: create a user, add it to a group, and add a policy such as `Allow group <group> to read all-resources in tenancy`.",
      },
      {
        title: "Add an API key",
        body: "User > API keys > Add API key > Generate API key pair. Download the private key and copy the configuration preview.",
      },
      {
        title: "Fill in the form",
        body: "From the preview: user OCID, tenancy OCID, fingerprint and region. Paste the private key content, and its passphrase if it has one.",
      },
    ],
    security: [DEDICATED, "Grant read / inspect verbs only.", ROTATE],
  },
  mongodbatlas: {
    title: "MongoDB Atlas: organization API key",
    summary: "A programmatic API key with the Organization Read Only role.",
    steps: [
      {
        title: "Create an API key",
        body: "Organization > Access Manager > Applications > API Keys > Create API Key, with the Organization Read Only permission.",
        link: {
          label: "Open MongoDB Atlas",
          href: "https://cloud.mongodb.com",
        },
      },
      {
        title: "Copy both keys",
        body: "Copy the public key and the private key. Atlas shows the private key once.",
      },
      {
        title: "Allow the scanner's address",
        body: "Add the scanner's IP address to the API key's access list, or the API calls are refused.",
      },
    ],
    security: [
      "Keep the API access list enabled; do not open the key to every address.",
      ROTATE,
    ],
  },
  "alibabacloud:role": {
    title: "Alibaba Cloud: RAM role (recommended)",
    summary:
      "A RAM user's AccessKey that assumes a read-only RAM role through STS.",
    steps: [
      {
        title: "Create the RAM role",
        body: "RAM > Roles > Create role, trusted by your account, with read-only policies (for example ReadOnlyAccess).",
      },
      {
        title: "Create a RAM user",
        body: "Create a user with API access only and allow it sts:AssumeRole on that role. Create its AccessKey pair.",
      },
      {
        title: "Fill in the form",
        body: "Enter the AccessKey ID, AccessKey secret, the Role ARN and a session name.",
      },
    ],
    security: [
      "Never use the main account's AccessKey pair.",
      "Give the RAM user no permission other than assuming the role.",
      ROTATE,
    ],
  },
  "alibabacloud:credentials": {
    title: "Alibaba Cloud: AccessKey pair",
    summary: "A read-only RAM user's AccessKey pair.",
    steps: [
      {
        title: "Create a RAM user",
        body: "RAM > Users > Create user with API access only, and attach read-only policies (for example ReadOnlyAccess).",
      },
      {
        title: "Create an AccessKey pair",
        body: "Copy the AccessKey ID and secret. The secret is shown once.",
      },
    ],
    security: ["Never use the main account's AccessKey pair.", ROTATE],
  },
  "cloudflare:api_token": {
    title: "Cloudflare: API token (recommended)",
    summary: "A user API token scoped to read-only permissions.",
    steps: [
      {
        title: "Create a user API token",
        body: "My Profile > API Tokens > Create Token > Create Custom Token. Use a User token, not an Account token.",
        link: {
          label: "Open Cloudflare API tokens",
          href: "https://dash.cloudflare.com/profile/api-tokens",
        },
      },
      {
        title: "Set read-only permissions",
        body: "Add these with Read access:",
        points: [
          "Account: Account Settings",
          "Zone: Zone, Zone Settings, DNS, SSL and Certificates, Bot Management, Zone WAF",
        ],
      },
      {
        title: "Choose the zones",
        body: "Include every zone you want scanned, then create the token and paste it. Cloudflare shows it once.",
      },
    ],
    security: [
      "Set a TTL on the token.",
      "Restrict the token to the scanner's IP address when you can.",
    ],
  },
  "cloudflare:api_key": {
    title: "Cloudflare: Global API key",
    summary:
      "The account's Global API Key and email. It has full account access; prefer an API token.",
    steps: [
      {
        title: "View the Global API Key",
        body: "My Profile > API Tokens > API Keys > Global API Key > View.",
        link: {
          label: "Open Cloudflare API tokens",
          href: "https://dash.cloudflare.com/profile/api-tokens",
        },
      },
      {
        title: "Enter key and email",
        body: "Paste the key with the email address of the Cloudflare user that owns it.",
      },
    ],
    security: [
      "The Global API Key cannot be scoped or limited to read-only. Use it only when a token is not possible.",
      "Roll the key in Cloudflare after the connection is removed.",
    ],
  },
  openstack: {
    title: "OpenStack: clouds.yaml",
    summary: "A clouds.yaml entry for a user with a read-only role.",
    steps: [
      {
        title: "Create a reader user",
        body: "Create a user (or application credential) with the Reader role, or your provider's read-only equivalent.",
      },
      {
        title: "Download clouds.yaml",
        body: "Horizon > API Access > Download OpenStack clouds.yaml file, then add the password or application credential secret to it.",
      },
      {
        title: "Paste it and name the cloud",
        body: "Paste the YAML and enter the cloud name to use: the key under `clouds:`.",
      },
    ],
    security: [
      "Do not use an admin or member role.",
      "Prefer an application credential; it can be revoked without changing the user's password.",
    ],
  },
  googleworkspace: {
    title: "Google Workspace: service account with domain-wide delegation",
    summary:
      "A Google Cloud service account allowed to read Workspace settings on behalf of an administrator.",
    values: [
      {
        label: "OAuth scopes for domain-wide delegation",
        value: [
          "https://www.googleapis.com/auth/admin.directory.user.readonly",
          "https://www.googleapis.com/auth/admin.directory.domain.readonly",
          "https://www.googleapis.com/auth/admin.directory.customer.readonly",
          "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
          "https://www.googleapis.com/auth/cloud-identity.policies.readonly",
          "https://www.googleapis.com/auth/admin.directory.rolemanagement.readonly",
        ].join(","),
      },
    ],
    steps: [
      {
        title: "Create a service account and key",
        body: "In a Google Cloud project, enable the Admin SDK and Cloud Identity APIs, create a service account and a JSON key. Copy the account's Client ID.",
        link: {
          label: "Open Service Accounts",
          href: "https://console.cloud.google.com/iam-admin/serviceaccounts",
        },
      },
      {
        title: "Authorize domain-wide delegation",
        body: "Admin console > Security > API controls > Domain-wide delegation > Add new. Enter the Client ID and paste the scopes above.",
        link: {
          label: "Open Google Admin console",
          href: "https://admin.google.com/ac/owl/domainwidedelegation",
        },
      },
      {
        title: "Fill in the form",
        body: "Paste the JSON key, the Customer ID (Admin console > Account > Account settings) and the email of a super administrator to act as.",
      },
    ],
    security: [
      "Use a dedicated super administrator as the delegated user, not a personal account.",
      "Authorize only the read-only scopes listed.",
      "Delete the downloaded key file once it is saved here.",
    ],
  },
  vercel: {
    title: "Vercel: API token",
    summary: "An access token for a user with at least the Viewer role.",
    steps: [
      {
        title: "Create a token",
        body: "Account Settings > Tokens > Create Token. Name it, choose the team to scan as Scope, and set an expiration.",
        link: {
          label: "Open Vercel tokens",
          href: "https://vercel.com/account/tokens",
        },
      },
      {
        title: "Paste the token",
        body: "Vercel shows the token once. Paste it into the form.",
      },
    ],
    security: [
      "The token inherits its creator's permissions. Create it from a user that is only a Viewer on the team.",
      "Scope it to one team instead of Full Account.",
    ],
  },
  okta: {
    title: "Okta: API service app (private key)",
    summary:
      "An OAuth 2.0 service app that signs in with a private-key JWT. No user password or API token.",
    values: [
      {
        label: "Okta API scopes to grant",
        value: [
          "okta.policies.read",
          "okta.brands.read",
          "okta.apps.read",
          "okta.authenticators.read",
          "okta.networkZones.read",
          "okta.apiTokens.read",
          "okta.roles.read",
          "okta.groups.read",
          "okta.logStreams.read",
          "okta.idps.read",
        ].join(" "),
      },
    ],
    steps: [
      {
        title: "Create an API Services app",
        body: "Admin Console > Applications > Create App Integration > API Services. Copy the Client ID.",
      },
      {
        title: "Use a public / private key",
        body: "Under Client Credentials choose Public key / Private key, add a key, generate it in Okta and copy the private key (PEM). The DPoP requirement can stay on.",
      },
      {
        title: "Grant scopes and a role",
        body: "Okta API Scopes: grant the scopes above. Admin roles: assign Read-Only Administrator, or the scopes return no data.",
      },
      {
        title: "Fill in the form",
        body: "Enter the Client ID and paste the private key.",
      },
    ],
    security: [
      "Grant read scopes only.",
      "Generate a new key and delete the old one in Okta to rotate.",
    ],
  },
} as const satisfies Record<string, SetupGuide>;

type ProviderGuideKey = keyof typeof PROVIDER_GUIDES;

const isProviderGuideKey = (key: string): key is ProviderGuideKey =>
  Object.hasOwn(PROVIDER_GUIDES, key);

const genericProviderGuide = (providerType: string): SetupGuide => ({
  title: `${getProviderDisplayName(providerType)}: read-only credential`,
  summary: `${PRODUCT} only reads configuration. Create a credential that cannot change anything.`,
  steps: [
    {
      title: "Create a dedicated identity",
      body: "Add a service account or API user used only for this connection.",
    },
    {
      title: "Grant read-only access",
      body: "Give it the provider's read-only or auditor role on the scope you want scanned.",
    },
    {
      title: "Enter the credential",
      body: "Copy each value the form asks for from the provider's console.",
    },
  ],
  security: [DEDICATED, ROTATE, STORED],
});

/**
 * Guides for a provider's credentials form. With a known method (`via`) it
 * returns that method's guide; before a method is chosen it returns one guide
 * per method so the user can compare them.
 */
export const getProviderSetupGuides = (
  providerType: string | null | undefined,
  via?: string | null,
): readonly SetupGuide[] => {
  if (!providerType) return [];
  const type = providerType.toLowerCase();

  const methodKey = `${type}:${via ?? ""}`;
  if (isProviderGuideKey(methodKey)) return [PROVIDER_GUIDES[methodKey]];
  if (isProviderGuideKey(type)) return [PROVIDER_GUIDES[type]];

  const methods = Object.keys(PROVIDER_GUIDES)
    .filter((key) => key.startsWith(`${type}:`))
    .filter(isProviderGuideKey)
    .map((key) => PROVIDER_GUIDES[key]);
  return methods.length > 0 ? methods : [genericProviderGuide(type)];
};

export const SETUP_GUIDE_INTEGRATION = {
  S3: "s3",
  SECURITY_HUB: "security-hub",
  JIRA: "jira",
  SLACK: "slack",
  SAML: "saml",
  API_KEY: "api-key",
  EMAIL: "email",
  BITBUCKET: "bitbucket",
} as const;

export type SetupGuideIntegration =
  (typeof SETUP_GUIDE_INTEGRATION)[keyof typeof SETUP_GUIDE_INTEGRATION];

/** OAuth scopes the Slack app needs; the API requests the same list. */
export const SLACK_BOT_SCOPES =
  "channels:read,groups:read,chat:write,channels:join";

const INTEGRATION_GUIDES = {
  s3: {
    title: "Amazon S3: export bucket",
    summary: `${PRODUCT} writes scan reports to a bucket you own, through an IAM role or access keys.`,
    steps: [
      {
        title: "Choose the bucket",
        body: "Use a private bucket in your account. Note its name and the 12-digit ID of the account that owns it.",
      },
      {
        title: "Create a write-only role",
        body: "Create an IAM role with the External ID shown in the form and a policy limited to this bucket:",
        points: [
          "s3:PutObject and s3:DeleteObject on arn:aws:s3:::<bucket>/*",
          "s3:ListBucket and s3:GetBucketLocation on arn:aws:s3:::<bucket>",
        ],
      },
      {
        title: "Fill in the form",
        body: "Enter the bucket name, the owner account ID, an output folder, then the Role ARN and External ID.",
      },
    ],
    security: [
      "Keep Block Public Access on for the bucket.",
      "Limit the role to this one bucket; it needs no read access to other data.",
      "Prefer the role over access keys.",
    ],
  },
  "security-hub": {
    title: "AWS Security Hub: findings import",
    summary: `${PRODUCT} sends findings to Security Hub in the regions where it is enabled.`,
    steps: [
      {
        title: "Enable Security Hub",
        body: "Turn on Security Hub in each region that should receive findings.",
      },
      {
        title: "Accept findings from the scanner",
        body: "Security Hub > Integrations: find the partner integration for this scanner and choose Accept findings. Ask support for its listing name if you cannot find it.",
      },
      {
        title: "Allow the import",
        body: "The provider's scan role works when it can also call these actions. Otherwise enter custom credentials that can:",
        points: ["securityhub:BatchImportFindings", "securityhub:GetFindings"],
      },
    ],
    security: [
      "Grant only the two Security Hub actions above for this integration.",
      "Prefer a role with an External ID over access keys.",
    ],
  },
  jira: {
    title: "Jira: API token",
    summary: `${PRODUCT} creates issues in Jira Cloud as the user that owns the API token.`,
    steps: [
      {
        title: "Create an API token",
        body: "Atlassian account > Security > Create and manage API tokens > Create API token. Give it an expiry.",
        link: {
          label: "Open Atlassian API tokens",
          href: "https://id.atlassian.com/manage-profile/security/api-tokens",
        },
      },
      {
        title: "Fill in the form",
        body: "Domain is the site name only: for https://acme.atlassian.net enter acme. Email is the address of the token's owner.",
      },
      {
        title: "Check project permissions",
        body: "The user needs Browse projects and Create issues in each project you send findings to.",
      },
    ],
    security: [
      "Use a service user that can only create issues in the target projects, not a Jira administrator.",
      "Renew the token before it expires; issue creation stops when it lapses.",
    ],
  },
  slack: {
    title: "Slack: your own Slack app",
    summary:
      "You create a Slack app in your workspace, then connect it here with OAuth.",
    values: [
      {
        label: "Redirect URL",
        value: `${APP}/integrations/slack/callback`,
        note: "Add it under OAuth & Permissions > Redirect URLs, exactly as shown.",
      },
      { label: "Bot token scopes", value: SLACK_BOT_SCOPES },
    ],
    steps: [
      {
        title: "Create the app",
        body: "Create New App > From scratch, and pick your workspace.",
        link: { label: "Open Slack apps", href: "https://api.slack.com/apps" },
      },
      {
        title: "Add the redirect URL and scopes",
        body: "OAuth & Permissions: add the Redirect URL above, then add each Bot Token Scope.",
      },
      {
        title: "Save the app credentials here",
        body: "Basic Information > App Credentials: copy the Client ID and Client Secret into the form and save.",
      },
      {
        title: "Connect the workspace",
        body: "Choose Add to Slack, approve the app, then pick the channels that receive alerts.",
      },
    ],
    security: [
      "The Redirect URL must match exactly, including https and no trailing slash, or Slack rejects the sign-in.",
      "Invite the app to a private channel before it can post there.",
      "Regenerate the Client Secret in Slack if it is ever exposed, then save the new one here.",
    ],
  },
  saml: {
    title: "SAML single sign-on",
    summary:
      "Connect your identity provider (Okta, Microsoft Entra ID, Google Workspace and others) so users sign in with company accounts.",
    values: [
      {
        label: "ACS URL (reply URL)",
        value: `${API}/accounts/saml/<your-email-domain>/acs/`,
        note: "Replace <your-email-domain> with the domain you enter in the form, for example acme.com.",
      },
      {
        label: "Audience / SP entity ID",
        value: BRAND.samlSpEntityId,
      },
      {
        label: "Sign-in page for your users",
        value: `${APP}/sign-in`,
      },
    ],
    steps: [
      {
        title: "Create a SAML app in your identity provider",
        body: "Add a custom SAML 2.0 application and enter the ACS URL and Audience above. Use the email address as Name ID.",
      },
      {
        title: "Map the attributes",
        body: "Send these attributes in the assertion:",
        points: [
          "firstName",
          "lastName",
          "userType: the role name the user receives here",
          "organization (optional)",
        ],
      },
      {
        title: "Upload the metadata",
        body: "Download the identity provider's metadata XML, enter your email domain in the form and upload the file.",
      },
      {
        title: "Test the sign-in",
        body: "Keep this session open, and in a private window sign in with SAML SSO using an address on your domain.",
      },
    ],
    security: [
      "Only add email domains your organization owns.",
      "userType decides the role: create the roles first and check the mapping, or users may get the wrong access.",
      "Keep one administrator able to sign in with a password until SSO is verified.",
      "Upload fresh metadata when the identity provider's signing certificate is renewed.",
    ],
  },
  "api-key": {
    title: "API keys",
    summary: `Keys for scripts and CI that call the ${PRODUCT} API on your behalf.`,
    values: [
      { label: "API base URL", value: API },
      {
        label: "Request header",
        value: "Authorization: Api-Key <your-key>",
      },
    ],
    steps: [
      {
        title: "Create the key",
        body: "Name it after the system that will use it and choose an expiry.",
      },
      {
        title: "Copy it now",
        body: "The key is shown once. Store it in your secret manager or CI secret store.",
      },
      {
        title: "Send it on each request",
        body: "Add the header above to every API call.",
      },
    ],
    security: [
      "A key has the same permissions as the user that created it.",
      "Use one key per system so each can be revoked alone.",
      "Never commit a key to a repository; revoke it at once if that happens.",
    ],
  },
  email: {
    title: "Email: SMTP server",
    summary: `${PRODUCT} sends alert emails through your SMTP server.`,
    steps: [
      {
        title: "Create an SMTP credential",
        body: "Use a credential made for sending only:",
        points: [
          "Amazon SES: SMTP credentials from the SES console",
          "Microsoft 365: a mailbox with SMTP AUTH enabled",
          "Google Workspace: an app password, or the SMTP relay service",
          "SendGrid, Mailgun, Postmark: an SMTP API key",
        ],
      },
      {
        title: "Pick the port and encryption",
        body: "Port 587 with TLS (STARTTLS) is the usual choice. Use port 465 with SSL only when the server requires it. Do not enable both.",
      },
      {
        title: "Set the From address",
        body: "Use an address on a domain the server may send for, with SPF and DKIM set up, or messages land in spam.",
      },
    ],
    security: [
      "Never send without TLS or SSL: the password would travel in clear text.",
      "Use an app password or API key, not a person's mailbox password.",
    ],
  },
  bitbucket: {
    title: "Bitbucket: workspace import",
    summary:
      "List the repositories of a Bitbucket workspace or project and add them as scan targets.",
    steps: [
      {
        title: "Bitbucket Cloud: create an access token",
        body: "Workspace settings > Access tokens (or an Atlassian API token with scopes) with read access to repositories. Enter the workspace ID from the URL bitbucket.org/<workspace>.",
        link: {
          label: "Open Bitbucket",
          href: "https://bitbucket.org/account/workspaces/",
        },
      },
      {
        title: "Bitbucket Data Center: create an HTTP access token",
        body: "Profile > Manage account > HTTP access tokens, with Repository read. Enter the server's base URL.",
      },
      {
        title: "Choose how to clone",
        body: "HTTPS reuses the token. For SSH, add a read-only access key to the workspace or project and paste its private key with the host's known_hosts line.",
      },
    ],
    security: [
      "Grant repository read only; no write or admin scope.",
      "Give the token an expiry.",
      "Always supply known hosts for SSH; without it the server identity is not checked.",
    ],
  },
} as const satisfies Record<SetupGuideIntegration, SetupGuide>;

export const getIntegrationSetupGuides = (
  integration: SetupGuideIntegration,
): readonly SetupGuide[] => [INTEGRATION_GUIDES[integration]];

const FALLBACK_API_URL = "<API URL>";

/** Replaces the URL placeholders with this deployment's addresses. */
export const resolveSetupGuideText = (
  text: string,
  urls: SetupGuideUrls,
): string =>
  text
    .replaceAll(APP, urls.appUrl.replace(/\/$/, ""))
    .replaceAll(API, urls.apiUrl.replace(/\/$/, "") || FALLBACK_API_URL);
