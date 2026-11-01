import { describe, expect, it } from "vitest";

import {
  actionError,
  formatSecret,
  isMfaChallengeCode,
  MFA_CODE,
  mfaChallengeFromBody,
  otpCodeAttribute,
  recoveryCodesFromResult,
  recoveryCodesText,
  withOtpCode,
} from "./mfa";

describe("isMfaChallengeCode", () => {
  it.each([MFA_CODE.REQUIRED, MFA_CODE.INVALID])("accepts %s", (code) => {
    expect(isMfaChallengeCode(code)).toBe(true);
  });

  it.each([MFA_CODE.ENROLMENT_REQUIRED, "Success", undefined, 1])(
    "rejects %s",
    (value) => {
      expect(isMfaChallengeCode(value)).toBe(false);
    },
  );
});

describe("mfaChallengeFromBody", () => {
  it("finds the challenge code in a JSON:API error body", () => {
    expect(
      mfaChallengeFromBody({
        errors: [{ status: "401", code: MFA_CODE.REQUIRED }],
      }),
    ).toBe(MFA_CODE.REQUIRED);
  });

  it.each([
    null,
    {},
    { errors: "nope" },
    { errors: [{ code: "token_not_valid" }] },
  ])("returns null for %j", (body) => {
    expect(mfaChallengeFromBody(body)).toBeNull();
  });
});

describe("withOtpCode", () => {
  const credentials = { email: "a@example.com", password: "secret-password" };

  it("adds the code without spaces or dashes", () => {
    expect(withOtpCode(credentials, " 123 456 ")).toEqual({
      ...credentials,
      otpCode: "123456",
    });
    expect(withOtpCode(credentials, "ABCDE-FGHJK").otpCode).toBe("ABCDEFGHJK");
  });

  it.each([undefined, null, "", "   "])(
    "leaves credentials alone for %j",
    (code) => {
      expect(withOtpCode(credentials, code)).toEqual(credentials);
    },
  );
});

describe("otpCodeAttribute", () => {
  it("maps the code to the API attribute", () => {
    expect(otpCodeAttribute({ otpCode: "123456" })).toEqual({
      otp_code: "123456",
    });
  });

  it("is empty without a code", () => {
    expect(otpCodeAttribute({ email: "a@example.com" })).toEqual({});
  });
});

describe("result helpers", () => {
  it("formats the secret in groups of four", () => {
    expect(formatSecret("ABCDEFGHIJKLMN")).toBe("ABCD EFGH IJKL MN");
  });

  it("reads action errors", () => {
    expect(actionError({ error: "Nope", status: 400 })).toBe("Nope");
    expect(actionError({ data: {} })).toBeNull();
    expect(actionError(null)).toBe("No response.");
  });

  it("reads recovery codes", () => {
    expect(
      recoveryCodesFromResult({
        data: { attributes: { codes: ["AAAAA-BBBBB", 3] } },
      }),
    ).toEqual(["AAAAA-BBBBB"]);
    expect(recoveryCodesFromResult({})).toEqual([]);
    expect(recoveryCodesText(["A", "B"])).toBe("A\nB\n");
  });
});
