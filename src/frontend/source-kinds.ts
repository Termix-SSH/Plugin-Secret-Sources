export type SecretSourceKind =
  | "onepassword-connect"
  | "infisical"
  | "bitwarden-sm"
  | "hashicorp-vault"
  | "bitwarden-cli";

export interface KindField {
  key: string;
  labelKey: string;
  secret: boolean;
  placeholder?: string;
  optional?: boolean;
}

export interface KindSpec {
  kind: SecretSourceKind;
  labelKey: string;
  urlLabelKey: string;
  defaultUrl: string;
  urlPlaceholder: string;
  /** The reference syntax shown under the form. */
  example: string;
  fields: KindField[];
}

export const KIND_SPECS: KindSpec[] = [
  {
    kind: "onepassword-connect",
    labelKey: "kinds.onepassword-connect",
    urlLabelKey: "urlLabel",
    defaultUrl: "",
    urlPlaceholder: "https://connect.internal:8080",
    example: "op://vault/item/field",
    fields: [
      {
        key: "token",
        labelKey: "tokenLabel",
        secret: true,
        placeholder: "eyJhbGciOi...",
      },
    ],
  },
  {
    kind: "infisical",
    labelKey: "kinds.infisical",
    urlLabelKey: "serverUrlLabel",
    defaultUrl: "https://app.infisical.com",
    urlPlaceholder: "https://app.infisical.com",
    example: "infisical://project-id/prod/folder/SECRET_NAME",
    fields: [
      { key: "clientId", labelKey: "fields.clientId", secret: false },
      { key: "clientSecret", labelKey: "fields.clientSecret", secret: true },
    ],
  },
  {
    kind: "bitwarden-sm",
    labelKey: "kinds.bitwarden-sm",
    urlLabelKey: "serverUrlLabel",
    defaultUrl: "https://vault.bitwarden.com",
    urlPlaceholder: "https://vault.bitwarden.com",
    example: "bws://secret-id",
    fields: [
      {
        key: "token",
        labelKey: "fields.accessToken",
        secret: true,
        placeholder: "0.xxxxxxxx-...",
      },
    ],
  },
  {
    kind: "hashicorp-vault",
    labelKey: "kinds.hashicorp-vault",
    urlLabelKey: "serverUrlLabel",
    defaultUrl: "",
    urlPlaceholder: "https://vault.internal:8200",
    example: "vault://secret/path/to/secret#key",
    fields: [
      {
        key: "token",
        labelKey: "fields.vaultToken",
        secret: true,
        optional: true,
      },
      {
        key: "roleId",
        labelKey: "fields.roleId",
        secret: false,
        optional: true,
      },
      {
        key: "secretId",
        labelKey: "fields.secretId",
        secret: true,
        optional: true,
      },
      {
        key: "namespace",
        labelKey: "fields.namespace",
        secret: false,
        optional: true,
      },
    ],
  },
  {
    kind: "bitwarden-cli",
    labelKey: "kinds.bitwarden-cli",
    urlLabelKey: "bwServeUrlLabel",
    defaultUrl: "http://localhost:8087",
    urlPlaceholder: "http://localhost:8087",
    example: "bw://item name/password",
    fields: [],
  },
];

export function specFor(kind: string): KindSpec {
  return KIND_SPECS.find((spec) => spec.kind === kind) ?? KIND_SPECS[0];
}

/**
 * The credential the server stores: the token itself for kinds with one
 * field, JSON for kinds with several, empty for none. Empty when nothing
 * was typed, which keeps the saved one on an edit.
 */
export function serializeCredential(
  spec: KindSpec,
  values: Record<string, string>,
): string {
  if (spec.fields.length === 0) return "";
  if (spec.fields.length === 1) return values[spec.fields[0].key]?.trim() ?? "";
  const filled = Object.fromEntries(
    spec.fields
      .map((field) => [field.key, values[field.key]?.trim() ?? ""])
      .filter(([, value]) => value),
  );
  return Object.keys(filled).length > 0 ? JSON.stringify(filled) : "";
}

/** Whether the typed values are enough to save a new source. */
export function credentialComplete(
  spec: KindSpec,
  values: Record<string, string>,
): boolean {
  if (spec.kind === "hashicorp-vault") {
    return !!(
      values.token?.trim() ||
      (values.roleId?.trim() && values.secretId?.trim())
    );
  }
  return spec.fields.every(
    (field) => field.optional || !!values[field.key]?.trim(),
  );
}
