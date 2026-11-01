import { CredentialsSignin } from "next-auth";
import { describe, expect, it, vi } from "vitest";

import { MFA_CODE } from "./mfa";
import {
  isMfaChallengeError,
  mfaChallengeError,
  mfaSignInResult,
  rethrowMfaChallenge,
  throwIfMfaChallenge,
} from "./mfa-server";

vi.mock("next-auth", () => ({
  CredentialsSignin: class CredentialsSignin extends Error {
    code = "credentials";
  },
}));

const jsonResponse = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/vnd.api+json" },
  });

describe("throwIfMfaChallenge", () => {
  it("throws a CredentialsSignin carrying the code", async () => {
    const response = jsonResponse(401, {
      errors: [{ code: MFA_CODE.INVALID }],
    });
    const error = await throwIfMfaChallenge(response).catch((e) => e);
    expect(error).toBeInstanceOf(CredentialsSignin);
    expect(isMfaChallengeError(error)).toBe(true);
    expect(error.code).toBe(MFA_CODE.INVALID);
  });

  it("ignores a plain failed sign-in", async () => {
    const response = jsonResponse(401, {
      errors: [{ code: "no_active_account" }],
    });
    await expect(throwIfMfaChallenge(response)).resolves.toBeUndefined();
  });

  it("ignores other statuses and unreadable bodies", async () => {
    await expect(
      throwIfMfaChallenge(
        jsonResponse(400, { errors: [{ code: "mfa_required" }] }),
      ),
    ).resolves.toBeUndefined();
    await expect(
      throwIfMfaChallenge(new Response("oops", { status: 401 })),
    ).resolves.toBeUndefined();
  });
});

describe("rethrowMfaChallenge", () => {
  it("rethrows only MFA challenges", () => {
    const challenge = mfaChallengeError(MFA_CODE.REQUIRED);
    expect(() => rethrowMfaChallenge(challenge)).toThrow(challenge);
    expect(() => rethrowMfaChallenge(new Error("network"))).not.toThrow();
  });
});

describe("mfaSignInResult", () => {
  it("turns a challenge into an authenticate result", () => {
    expect(mfaSignInResult(mfaChallengeError(MFA_CODE.REQUIRED))).toEqual({
      message: MFA_CODE.REQUIRED,
    });
  });

  it("returns null for other errors", () => {
    expect(mfaSignInResult(new CredentialsSignin())).toBeNull();
    expect(isMfaChallengeError(new CredentialsSignin())).toBe(false);
    expect(mfaSignInResult(undefined)).toBeNull();
  });
});
