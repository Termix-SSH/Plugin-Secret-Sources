import {
  parseSecretReference,
  resolveConnectReference,
  testConnectSource,
  type SecretReference,
} from "../onepassword-connect.js";
import type { SecretProvider } from "./types.js";

/** 1Password Connect. op://<vault>/<item>/<field> */
export const onePasswordProvider: SecretProvider<SecretReference> = {
  kind: "onepassword-connect",
  scheme: "op",
  needsCredential: true,
  parseReference: parseSecretReference,
  resolve: (fetch, source, ref) =>
    resolveConnectReference(
      fetch,
      {
        baseUrl: source.baseUrl,
        token: source.credential,
        allowedPrivateHosts: source.allowedPrivateHosts,
      },
      ref,
    ),
  async test(fetch, source) {
    const vaults = await testConnectSource(fetch, {
      baseUrl: source.baseUrl,
      token: source.credential,
      allowedPrivateHosts: source.allowedPrivateHosts,
    });
    return `${vaults} vault${vaults === 1 ? "" : "s"} visible`;
  },
};
