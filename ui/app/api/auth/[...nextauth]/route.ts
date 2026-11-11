import { handlers } from "@/auth.config";
import { withoutSessionTokens } from "@/cloudsneeker/lib/session-response"; // cloudsneeker-hook

// cloudsneeker-hook: the browser's session JSON carries no API tokens.
export const GET = withoutSessionTokens(handlers.GET);
export const POST = withoutSessionTokens(handlers.POST);
