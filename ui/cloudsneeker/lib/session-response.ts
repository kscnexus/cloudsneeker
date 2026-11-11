// Keeps API tokens out of the browser. Auth.js answers GET and POST
// `/api/auth/session` with the whole session object, including the API access
// and refresh tokens upstream stores on it, so any script on the page could
// read a 24-hour refresh token. Browser code only reads `user`, `tenantId` and
// `error`; server code calls `auth()`, which reads the encrypted cookie and is
// not affected. This strips the tokens from that one HTTP response.

export const SESSION_TOKEN_FIELDS = ["accessToken", "refreshToken"] as const;

type RouteHandler<Req extends Request, Args extends unknown[]> = (
  request: Req,
  ...args: Args
) => Promise<Response> | Response;

const isSessionPath = (url: string): boolean => {
  try {
    return new URL(url).pathname.replace(/\/+$/, "").endsWith("/session");
  } catch {
    return false;
  }
};

export const stripSessionTokens = async (
  response: Response,
): Promise<Response> => {
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("application/json")) return response;

  let body: unknown;
  try {
    body = await response.clone().json();
  } catch {
    return response;
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return response;
  }
  const record = body as Record<string, unknown>;
  if (!SESSION_TOKEN_FIELDS.some((field) => field in record)) return response;

  const safe = { ...record };
  for (const field of SESSION_TOKEN_FIELDS) delete safe[field];

  const headers = new Headers(response.headers);
  headers.delete("content-length");
  return new Response(JSON.stringify(safe), {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
};

export const withoutSessionTokens =
  <Req extends Request, Args extends unknown[]>(
    handler: RouteHandler<Req, Args>,
  ) =>
  async (request: Req, ...args: Args): Promise<Response> => {
    const response = await handler(request, ...args);
    return isSessionPath(request.url) ? stripSessionTokens(response) : response;
  };
