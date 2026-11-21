import { createVerify, generateKeyPairSync } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import * as kdbxweb from "kdbxweb";
import {
  awsSecretsManagerProvider,
  parseAwsReference,
  regionOf,
  signV4,
} from "../../src/backend/providers/aws-secrets-manager.js";
import {
  azureKeyVaultProvider,
  parseAzureReference,
} from "../../src/backend/providers/azure-key-vault.js";
import {
  gcpSecretManagerProvider,
  parseGcpReference,
} from "../../src/backend/providers/gcp-secret-manager.js";
import {
  clearKeepassCache,
  keepassProvider,
  parseKeepassReference,
} from "../../src/backend/providers/keepass.js";
import {
  PROVIDERS,
  kindsForScheme,
} from "../../src/backend/providers/index.js";

function json(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  } as unknown as Response;
}

const source = (credential: unknown, baseUrl: string) => ({
  baseUrl,
  credential: JSON.stringify(credential),
  allowedPrivateHosts: [],
});

type Init = {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
};

describe("every provider", () => {
  it("has its own scheme, except the two Bitwarden vault kinds", () => {
    const schemes = PROVIDERS.filter((p) => p.kind !== "bitwarden-vault").map(
      (p) => p.scheme,
    );
    expect(new Set(schemes).size).toBe(schemes.length);
    expect(kindsForScheme("bw")).toEqual(["bitwarden-cli", "bitwarden-vault"]);
  });
});

describe("AWS Secrets Manager", () => {
  it("signs like botocore", () => {
    // Reference value from botocore SigV4Auth for the same request.
    const headers = signV4({
      method: "POST",
      url: "https://secretsmanager.eu-west-1.amazonaws.com/",
      region: "eu-west-1",
      service: "secretsmanager",
      headers: {
        "content-type": "application/x-amz-json-1.1",
        "x-amz-target": "secretsmanager.GetSecretValue",
      },
      body: '{"SecretId":"prod/db"}',
      accessKeyId: "AKIDEXAMPLE",
      secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
      sessionToken: "tok123",
      now: new Date("2026-11-20T20:25:00Z"),
    });
    expect(headers.authorization).toBe(
      "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261120/eu-west-1/secretsmanager/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=93030386b15bf38bbf86200d52c00a994d85a77d2c1e8c825b4a8b0d342481db",
    );
  });

  it("parses references and finds the region", () => {
    expect(parseAwsReference("aws-sm://prod%2Fdb#password")).toEqual({
      secretId: "prod/db",
      key: "password",
    });
    expect(parseAwsReference("aws-sm://")).toBeNull();
    expect(
      regionOf("https://secretsmanager.ap-south-1.amazonaws.com", ""),
    ).toBe("ap-south-1");
    expect(regionOf("http://localstack:4566", "eu-north-1")).toBe("eu-north-1");
  });

  it("reads a secret and one key of a JSON secret", async () => {
    const fetch = vi.fn(async (_url: string, init: Init) => {
      expect(init.headers?.["x-amz-target"]).toBe(
        "secretsmanager.GetSecretValue",
      );
      expect(init.headers?.authorization).toMatch(/^AWS4-HMAC-SHA256 /);
      return json({ SecretString: '{"user":"app","password":"s3cret"}' });
    });
    const src = source(
      { accessKeyId: "AK", secretAccessKey: "SK" },
      "https://secretsmanager.us-east-1.amazonaws.com",
    );
    expect(
      await awsSecretsManagerProvider.resolve(fetch as never, src, {
        secretId: "prod/db",
        key: "password",
      }),
    ).toBe("s3cret");
    await expect(
      awsSecretsManagerProvider.resolve(fetch as never, src, {
        secretId: "prod/db",
        key: "nope",
      }),
    ).rejects.toThrow('has no key "nope"');
  });

  it("says what AWS refused", async () => {
    const fetch = vi.fn(async () =>
      json({ __type: "com.amazonaws#ResourceNotFoundException" }, 400),
    );
    await expect(
      awsSecretsManagerProvider.resolve(
        fetch as never,
        source({ accessKeyId: "AK", secretAccessKey: "SK" }, "https://x.test"),
        { secretId: "gone", key: "" },
      ),
    ).rejects.toThrow("HTTP 400 ResourceNotFoundException");
  });

  it("lists secrets with their path as the folder", async () => {
    const fetch = vi.fn(async () =>
      json({ SecretList: [{ Name: "prod/db", ARN: "arn:1" }] }),
    );
    expect(
      await awsSecretsManagerProvider.listItems!(
        fetch as never,
        source({ accessKeyId: "AK", secretAccessKey: "SK" }, "https://x.test"),
        "",
      ),
    ).toEqual([
      {
        id: "arn:1",
        name: "db",
        folder: "prod",
        username: null,
        password: "aws-sm://prod%2Fdb",
      },
    ]);
  });
});

describe("Azure Key Vault", () => {
  const vault = "https://my-vault.vault.azure.net";
  const creds = { tenantId: "tenant-1", clientId: "app", clientSecret: "pw" };

  function fake(extra: (url: string) => Response | null = () => null) {
    return vi.fn(async (url: string, init: Init) => {
      if (url.startsWith("https://login.microsoftonline.com/tenant-1/")) {
        const body = new URLSearchParams(init.body);
        expect(body.get("scope")).toBe("https://vault.azure.net/.default");
        expect(body.get("client_secret")).toBe("pw");
        return json({ access_token: "tok" });
      }
      expect(init.headers?.Authorization).toBe("Bearer tok");
      return extra(url) ?? json({}, 404);
    });
  }

  it("reads a secret, with or without a version", async () => {
    const fetch = fake((url) =>
      url === `${vault}/secrets/db-password/v2?api-version=7.4`
        ? json({ value: "s3cret" })
        : null,
    );
    expect(parseAzureReference("azkv://db-password/v2")).toEqual({
      name: "db-password",
      version: "v2",
    });
    expect(parseAzureReference("azkv://bad name")).toBeNull();
    expect(
      await azureKeyVaultProvider.resolve(
        fetch as never,
        source(creds, vault),
        {
          name: "db-password",
          version: "v2",
        },
      ),
    ).toBe("s3cret");
  });

  it("never follows a nextLink off the vault", async () => {
    const fetch = fake((url) =>
      url.startsWith(`${vault}/secrets?`)
        ? json({
            value: [{ id: `${vault}/secrets/one` }],
            nextLink: "https://evil.example/steal",
          })
        : null,
    );
    const items = await azureKeyVaultProvider.listItems!(
      fetch as never,
      source(creds, vault),
      "",
    );
    expect(items.map((i) => i.password)).toEqual(["azkv://one"]);
    expect(fetch.mock.calls.some(([url]) => String(url).includes("evil"))).toBe(
      false,
    );
  });
});

describe("Google Cloud Secret Manager", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
  });
  const account = {
    client_email: "termix@proj.iam.gserviceaccount.com",
    private_key: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    project_id: "proj",
  };

  const fetch = vi.fn(async (url: string, init: Init) => {
    if (url === "https://oauth2.googleapis.com/token") {
      const jwt = new URLSearchParams(init.body).get("assertion")!;
      const [h, c, s] = jwt.split(".");
      const ok = createVerify("RSA-SHA256")
        .update(`${h}.${c}`)
        .verify(publicKey, Buffer.from(s, "base64url"));
      const claims = JSON.parse(Buffer.from(c, "base64url").toString());
      expect(ok).toBe(true);
      expect(claims.iss).toBe(account.client_email);
      return json({ access_token: "gtok" });
    }
    expect(init.headers?.Authorization).toBe("Bearer gtok");
    if (url.endsWith("/v1/projects/proj/secrets/db/versions/latest:access")) {
      return json({
        payload: { data: Buffer.from("s3cret").toString("base64") },
      });
    }
    if (url.includes("/v1/projects/proj/secrets?")) {
      return json({ secrets: [{ name: "projects/proj/secrets/db" }] });
    }
    return json({}, 404);
  });
  const src = source(
    { serviceAccountJson: JSON.stringify(account) },
    "https://secretmanager.googleapis.com",
  );

  it("signs in with a signed JWT and reads the latest version", async () => {
    expect(parseGcpReference("gcpsm://proj/db")).toEqual({
      project: "proj",
      secret: "db",
      version: "latest",
    });
    expect(parseGcpReference("gcpsm://proj")).toBeNull();
    expect(
      await gcpSecretManagerProvider.resolve(fetch as never, src, {
        project: "proj",
        secret: "db",
        version: "latest",
      }),
    ).toBe("s3cret");
    expect(
      await gcpSecretManagerProvider.listItems!(fetch as never, src, ""),
    ).toEqual([
      {
        id: "projects/proj/secrets/db",
        name: "db",
        folder: "proj",
        username: null,
        password: "gcpsm://proj/db",
      },
    ]);
  });

  it("refuses a key that is not Google's JSON or a plain http token_uri", async () => {
    await expect(
      gcpSecretManagerProvider.test(
        fetch as never,
        source({ serviceAccountJson: "nope" }, "https://x.test"),
      ),
    ).rejects.toThrow("JSON file from Google");
    await expect(
      gcpSecretManagerProvider.test(
        fetch as never,
        source(
          {
            serviceAccountJson: JSON.stringify({
              ...account,
              token_uri: "http://10.0.0.1/token",
            }),
          },
          "https://x.test",
        ),
      ),
    ).rejects.toThrow("must be https");
  });
});

describe("KeePass", () => {
  let file: ArrayBuffer;
  const url = "https://dav.example/Passwords.kdbx";

  beforeEach(async () => {
    clearKeepassCache();
    if (file) return;
    const db = kdbxweb.Kdbx.create(
      new kdbxweb.Credentials(kdbxweb.ProtectedValue.fromString("master!")),
      "Passwords",
    );
    const group = db.createGroup(db.getDefaultGroup(), "Servers");
    const entry = db.createEntry(group);
    entry.fields.set("Title", "web/1");
    entry.fields.set("UserName", "root");
    entry.fields.set("Password", kdbxweb.ProtectedValue.fromString("s3cret"));
    entry.fields.set("Api", "key-123");
    file = await db.save();
  });

  const fetch = vi.fn(async (_url: string, init: Init) => {
    expect(init.headers?.Authorization).toBe(
      `Basic ${Buffer.from("me:dav").toString("base64")}`,
    );
    return {
      ok: true,
      status: 200,
      arrayBuffer: async () => file,
    } as unknown as Response;
  });
  const src = (masterPassword: string) =>
    source({ masterPassword, httpUsername: "me", httpPassword: "dav" }, url);

  it("opens the file and reads fields by path", async () => {
    const ref = parseKeepassReference("kdbx://Servers/web%2F1")!;
    expect(ref).toEqual({
      groups: ["Servers"],
      title: "web/1",
      field: "Password",
    });
    expect(
      await keepassProvider.resolve(fetch as never, src("master!"), ref),
    ).toBe("s3cret");
    expect(
      await keepassProvider.resolve(
        fetch as never,
        src("master!"),
        parseKeepassReference("kdbx://Servers/web%2F1#username")!,
      ),
    ).toBe("root");
    expect(
      await keepassProvider.resolve(
        fetch as never,
        src("master!"),
        parseKeepassReference("kdbx://Servers/web%2F1#Api")!,
      ),
    ).toBe("key-123");
  });

  it("lists entries for the picker", async () => {
    expect(
      await keepassProvider.listItems!(fetch as never, src("master!"), "web"),
    ).toEqual([
      expect.objectContaining({
        name: "web/1",
        folder: "Servers",
        username: "kdbx://Servers/web%2F1#UserName",
        password: "kdbx://Servers/web%2F1",
      }),
    ]);
  });

  it("says when the master password is wrong", async () => {
    await expect(
      keepassProvider.test(fetch as never, src("wrong")),
    ).rejects.toThrow("master password or key file is wrong");
  });
});
