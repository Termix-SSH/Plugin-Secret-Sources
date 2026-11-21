import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import {
  renderWithApp,
  type RenderedPluginApp,
} from "@termix-ssh/plugin-sdk/testing";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";
import * as plugin from "../../src/frontend/index";
import { PluginComponent } from "@termix-ssh/plugin-sdk/ui";
import manifestJson from "../../manifest.json";
import locales from "../../locales/en.json";

const manifest = manifestJson as unknown as PluginManifest;
const source = {
  id: "src-1",
  name: "Vaultwarden",
  kind: "bitwarden-vault" as const,
  baseUrl: "https://vault.example.com",
  shared: true,
  owned: false,
  createdAt: "",
  updatedAt: "",
};
const locked = { unlocked: false, email: null, method: null, expiresAt: null };

let rendered: RenderedPluginApp | null = null;

afterEach(async () => {
  await rendered?.deactivate();
  rendered = null;
});

/** The plugin's API as the manager reaches it, routed by path. */
function fakeApi(
  options: {
    session?: unknown;
    post?: (url: string, body: unknown) => Promise<unknown>;
    del?: (url: string) => Promise<unknown>;
  } = {},
) {
  return {
    get: vi.fn(async (url: string) => ({
      data: url === "/" ? { sources: [source] } : (options.session ?? locked),
    })),
    post: vi.fn(async (url: string, body: unknown) => ({
      data: await (options.post?.(url, body) ?? {}),
    })),
    delete: vi.fn(async (url: string) => ({
      data: await (options.del?.(url) ?? { success: true }),
    })),
  };
}

function type(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

async function openUnlock(api: ReturnType<typeof fakeApi>) {
  rendered = await renderWithApp(plugin, {
    manifest,
    locales,
    api: api as never,
  });
  render(<PluginComponent id="credentials.secretManager" onClose={vi.fn()} />);
  fireEvent.click(await screen.findByLabelText(locales.unlock.toggle));
}

describe("vault unlock", () => {
  it("registers the unlock tab", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales });
    expect(rendered.registered.tabs()).toContain("vault-unlock");
  });

  it("asks for a two-step code, then unlocks with it", async () => {
    const bodies: unknown[] = [];
    const api = fakeApi({
      post: async (_url, body) => {
        bodies.push(body);
        if (bodies.length === 1) {
          throw {
            response: {
              data: { error: "Two-step login is required", twoFactor: [0] },
            },
          };
        }
        return {
          unlocked: true,
          email: "a@example.com",
          method: "password",
          expiresAt: Date.now() + 1000,
        };
      },
    });
    await openUnlock(api);
    fireEvent.click(await screen.findByText(locales.unlock.methods.password));
    type(locales.unlock.email, "a@example.com");
    type(locales.unlock.masterPassword, "master");
    fireEvent.click(screen.getByText(locales.unlock.submit));
    await screen.findByLabelText(locales.unlock.code);
    type(locales.unlock.code, "123456");
    fireEvent.click(screen.getByText(locales.unlock.submit));
    expect(await screen.findByText(locales.unlock.lock)).toBeTruthy();
    expect(bodies[1]).toEqual({
      method: "password",
      email: "a@example.com",
      password: "master",
      twoFactorProvider: 0,
      twoFactorCode: "123456",
    });
  });

  it("opens SSO and sends the pasted address back", async () => {
    const open = vi.spyOn(window, "open").mockReturnValue(null);
    const posts: Array<[string, unknown]> = [];
    const api = fakeApi({
      post: async (url, body) => {
        posts.push([url, body]);
        return url.endsWith("/sso")
          ? { url: "https://vault.example.com/identity/x" }
          : {
              unlocked: true,
              email: "a@example.com",
              method: "sso",
              expiresAt: 1,
            };
      },
    });
    await openUnlock(api);
    fireEvent.click(await screen.findByText(locales.unlock.ssoOpen));
    await waitFor(() =>
      expect(open).toHaveBeenCalledWith(
        "https://vault.example.com/identity/x",
        "_blank",
        "noopener,noreferrer",
      ),
    );
    type(locales.unlock.ssoAddress, "http://localhost:8065/?code=x&state=y");
    type(locales.unlock.masterPassword, "master");
    fireEvent.click(screen.getByText(locales.unlock.submit));
    await waitFor(() =>
      expect(posts[1]).toEqual([
        "/src-1/session",
        {
          method: "sso",
          redirect: "http://localhost:8065/?code=x&state=y",
          password: "master",
        },
      ]),
    );
    open.mockRestore();
  });

  it("locks an unlocked vault", async () => {
    const deleted: string[] = [];
    const api = fakeApi({
      session: {
        unlocked: true,
        email: "a@example.com",
        method: "sso",
        expiresAt: Date.now() + 1000,
      },
      del: async (url) => {
        deleted.push(url);
        return { success: true };
      },
    });
    await openUnlock(api);
    fireEvent.click(await screen.findByText(locales.unlock.lock));
    await waitFor(() => expect(deleted).toEqual(["/src-1/session"]));
    expect(await screen.findByText(locales.unlock.submit)).toBeTruthy();
  });
});
