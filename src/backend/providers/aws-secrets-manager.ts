import crypto from "node:crypto";
import {
  FETCH_TIMEOUT_MS,
  PICK_LIMIT,
  credentialFields,
  trimBase,
  type PickItem,
  type ProviderSource,
  type SecretProvider,
} from "./types.js";

/**
 * AWS Secrets Manager with an access key. The source URL is the regional
 * endpoint, like https://secretsmanager.eu-west-1.amazonaws.com.
 * aws-sm://<secret name or ARN>[#json-key]
 */
export interface AwsReference {
  secretId: string;
  /** A key in a JSON secret. Empty gives the whole string. */
  key: string;
}

export function parseAwsReference(raw: string): AwsReference | null {
  const value = raw.trim();
  if (!value.toLowerCase().startsWith("aws-sm://")) return null;
  const rest = value.slice("aws-sm://".length);
  const hash = rest.indexOf("#");
  const id = hash === -1 ? rest : rest.slice(0, hash);
  const key = hash === -1 ? "" : rest.slice(hash + 1);
  try {
    const secretId = decodeURIComponent(id);
    return secretId ? { secretId, key: decodeURIComponent(key) } : null;
  } catch {
    return null;
  }
}

const sha256 = (data: string) =>
  crypto.createHash("sha256").update(data, "utf8").digest("hex");
const hmac = (key: crypto.BinaryLike, data: string) =>
  crypto.createHmac("sha256", key).update(data, "utf8").digest();

export interface SignInput {
  method: string;
  url: string;
  region: string;
  service: string;
  headers: Record<string, string>;
  body: string;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  now?: Date;
}

/** Signature Version 4 headers for one request. */
export function signV4(input: SignInput): Record<string, string> {
  const url = new URL(input.url);
  const now = input.now ?? new Date();
  const amzDate = now
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d{3}/, "");
  const date = amzDate.slice(0, 8);
  const headers: Record<string, string> = {
    ...input.headers,
    host: url.host,
    "x-amz-date": amzDate,
    ...(input.sessionToken
      ? { "x-amz-security-token": input.sessionToken }
      : {}),
  };
  const names = Object.keys(headers)
    .map((name) => name.toLowerCase())
    .sort();
  const lower = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]),
  );
  const canonicalHeaders = names
    .map(
      (name) => `${name}:${String(lower[name]).trim().replace(/\s+/g, " ")}\n`,
    )
    .join("");
  const signedHeaders = names.join(";");
  const query = [...url.searchParams.entries()]
    .map(([k, v]) => [encodeURIComponent(k), encodeURIComponent(v)])
    .sort(([a, x], [b, y]) => (a === b ? (x < y ? -1 : 1) : a < b ? -1 : 1))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
  const canonicalRequest = [
    input.method,
    url.pathname || "/",
    query,
    canonicalHeaders,
    signedHeaders,
    sha256(input.body),
  ].join("\n");
  const scope = `${date}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    scope,
    sha256(canonicalRequest),
  ].join("\n");
  const kDate = hmac(`AWS4${input.secretAccessKey}`, date);
  const kRegion = hmac(kDate, input.region);
  const kService = hmac(kRegion, input.service);
  const kSigning = hmac(kService, "aws4_request");
  const signature = crypto
    .createHmac("sha256", kSigning)
    .update(stringToSign, "utf8")
    .digest("hex");
  return {
    ...headers,
    authorization: `AWS4-HMAC-SHA256 Credential=${input.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

/** The region in a Secrets Manager endpoint, or the one given. */
export function regionOf(baseUrl: string, given: string | undefined): string {
  if (given?.trim()) return given.trim();
  const match = /secretsmanager(?:-fips)?\.([a-z0-9-]+)\.amazonaws\.com/i.exec(
    baseUrl,
  );
  return match ? match[1] : "us-east-1";
}

async function call<T>(
  fetch: Parameters<SecretProvider["resolve"]>[0],
  source: ProviderSource,
  target: string,
  payload: Record<string, unknown>,
  label: string,
): Promise<T> {
  const fields = credentialFields(source.credential);
  if (!fields.accessKeyId || !fields.secretAccessKey) {
    throw new Error("AWS needs an access key id and secret access key");
  }
  const url = `${trimBase(source.baseUrl)}/`;
  const body = JSON.stringify(payload);
  const headers = signV4({
    method: "POST",
    url,
    region: regionOf(source.baseUrl, fields.region),
    service: "secretsmanager",
    headers: {
      "content-type": "application/x-amz-json-1.1",
      "x-amz-target": `secretsmanager.${target}`,
    },
    body,
    accessKeyId: fields.accessKeyId,
    secretAccessKey: fields.secretAccessKey,
    sessionToken: fields.sessionToken,
  });
  const response = await fetch(url, {
    method: "POST",
    headers,
    body,
    timeoutMs: FETCH_TIMEOUT_MS,
    allowPrivateHosts: source.allowedPrivateHosts,
  });
  if (!response.ok) {
    let reason = "";
    try {
      const err = (await response.json()) as {
        __type?: string;
        message?: string;
        Message?: string;
      };
      reason = (err.__type ?? "").split("#").pop() ?? "";
    } catch {
      // no JSON body
    }
    throw new Error(
      `${label} failed: HTTP ${response.status}${reason ? ` ${reason}` : ""}`,
    );
  }
  return (await response.json()) as T;
}

/** A key out of a JSON secret, or the whole string. */
export function pickKey(value: string, key: string, name: string): string {
  if (!key) return value;
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new Error(`Secret "${name}" is not JSON, so it has no key "${key}"`);
  }
  const found = (parsed as Record<string, unknown>)?.[key];
  if (found === undefined || found === null) {
    throw new Error(`Secret "${name}" has no key "${key}"`);
  }
  return typeof found === "string" ? found : JSON.stringify(found);
}

export const awsSecretsManagerProvider: SecretProvider<AwsReference> = {
  kind: "aws-secrets-manager",
  scheme: "aws-sm",
  needsCredential: true,
  parseReference: parseAwsReference,
  async resolve(fetch, source, ref) {
    const result = await call<{ SecretString?: string; SecretBinary?: string }>(
      fetch,
      source,
      "GetSecretValue",
      { SecretId: ref.secretId },
      `AWS secret "${ref.secretId}"`,
    );
    const value =
      result.SecretString ??
      (result.SecretBinary
        ? Buffer.from(result.SecretBinary, "base64").toString("utf8")
        : undefined);
    if (value === undefined) {
      throw new Error(`AWS secret "${ref.secretId}" has no value`);
    }
    return pickKey(value, ref.key, ref.secretId);
  },
  async test(fetch, source) {
    const result = await call<{ SecretList?: unknown[] }>(
      fetch,
      source,
      "ListSecrets",
      { MaxResults: 1 },
      "AWS sign in",
    );
    return `Signed in, ${result.SecretList?.length ? "secrets found" : "no secrets yet"}`;
  },
  async listItems(fetch, source, search) {
    const items: PickItem[] = [];
    let next: string | undefined;
    do {
      const page = await call<{
        SecretList?: Array<{ Name?: string; ARN?: string }>;
        NextToken?: string;
      }>(
        fetch,
        source,
        "ListSecrets",
        {
          MaxResults: 100,
          ...(next ? { NextToken: next } : {}),
          ...(search.trim()
            ? { Filters: [{ Key: "name", Values: [search.trim()] }] }
            : {}),
        },
        "AWS secret list",
      );
      for (const secret of page.SecretList ?? []) {
        if (!secret.Name) continue;
        const slash = secret.Name.lastIndexOf("/");
        items.push({
          id: secret.ARN ?? secret.Name,
          name: slash === -1 ? secret.Name : secret.Name.slice(slash + 1),
          folder: slash === -1 ? null : secret.Name.slice(0, slash),
          username: null,
          password: `aws-sm://${encodeURIComponent(secret.Name)}`,
        });
      }
      next = page.NextToken;
    } while (next && items.length < PICK_LIMIT);
    return items.slice(0, PICK_LIMIT);
  },
};
