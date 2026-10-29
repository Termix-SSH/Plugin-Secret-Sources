import { describe, expect, it } from "vitest";
import {
  credentialComplete,
  serializeCredential,
  specFor,
} from "../../src/frontend/source-kinds";

describe("source kinds", () => {
  it("stores one field as the token itself", () => {
    expect(
      serializeCredential(specFor("onepassword-connect"), { token: " t " }),
    ).toBe("t");
  });

  it("stores several fields as JSON, without empty ones", () => {
    expect(
      JSON.parse(
        serializeCredential(specFor("hashicorp-vault"), {
          roleId: "r",
          secretId: "s",
          token: "",
        }),
      ),
    ).toEqual({ roleId: "r", secretId: "s" });
    expect(serializeCredential(specFor("infisical"), {})).toBe("");
  });

  it("knows when a new source has enough to sign in", () => {
    expect(credentialComplete(specFor("hashicorp-vault"), { token: "x" })).toBe(
      true,
    );
    expect(
      credentialComplete(specFor("hashicorp-vault"), { roleId: "r" }),
    ).toBe(false);
    expect(credentialComplete(specFor("infisical"), { clientId: "a" })).toBe(
      false,
    );
    expect(credentialComplete(specFor("bitwarden-cli"), {})).toBe(true);
  });
});
