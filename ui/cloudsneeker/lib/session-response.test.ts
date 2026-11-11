import { describe, expect, it, vi } from "vitest";

import { stripSessionTokens, withoutSessionTokens } from "./session-response";

const SESSION = {
  user: { name: "Ada", email: "ada@example.com" },
  tenantId: "tenant-1",
  userId: "user-1",
  accessToken: "access-secret",
  refreshToken: "refresh-secret",
  expires: "2026-11-09T00:00:00.000Z",
};

const jsonResponse = (body: unknown, init: ResponseInit = {}) => {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json");
  return new Response(JSON.stringify(body), { ...init, headers });
};

describe("stripSessionTokens", () => {
  it("drops the API tokens and keeps the rest of the session", async () => {
    const response = await stripSessionTokens(jsonResponse(SESSION));
    const body = await response.json();

    expect(body).not.toHaveProperty("accessToken");
    expect(body).not.toHaveProperty("refreshToken");
    expect(body).toMatchObject({
      user: SESSION.user,
      tenantId: "tenant-1",
      userId: "user-1",
      expires: SESSION.expires,
    });
  });

  it("keeps status and session cookies", async () => {
    const headers = new Headers();
    headers.append("set-cookie", "authjs.session-token=abc; Path=/; HttpOnly");
    headers.append("set-cookie", "authjs.csrf-token=def; Path=/; HttpOnly");
    const response = await stripSessionTokens(
      jsonResponse(SESSION, { status: 200, headers }),
    );

    expect(response.status).toBe(200);
    expect(response.headers.getSetCookie()).toHaveLength(2);
  });

  it("leaves a signed-out (null) session alone", async () => {
    const original = jsonResponse(null);
    expect(await stripSessionTokens(original)).toBe(original);
  });

  it("leaves non-JSON responses alone", async () => {
    const original = new Response("<html></html>", {
      headers: { "content-type": "text/html" },
    });
    expect(await stripSessionTokens(original)).toBe(original);
  });
});

describe("withoutSessionTokens", () => {
  it("strips the session endpoint", async () => {
    const handler = withoutSessionTokens(async () => jsonResponse(SESSION));
    const response = await handler(
      new Request("https://app.test/api/auth/session"),
    );

    expect(await response.json()).not.toHaveProperty("accessToken");
  });

  it("passes other Auth.js endpoints through untouched", async () => {
    const original = jsonResponse({ csrfToken: "x" });
    const inner = vi.fn(async () => original);
    const handler = withoutSessionTokens(inner);

    const response = await handler(
      new Request("https://app.test/api/auth/csrf"),
    );

    expect(response).toBe(original);
    expect(inner).toHaveBeenCalledOnce();
  });
});
