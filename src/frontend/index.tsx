import type { TermixApp } from "@termix-ssh/plugin-sdk/frontend";
import { SecretSourceManager } from "./SecretSourceManager";
import { SecretReferenceHint } from "./SecretReferenceHint";
import { VaultUnlockTab } from "./VaultUnlockTab";

export function activate(app: TermixApp): void {
  app.registerComponent("credentials.secretHint", SecretReferenceHint);
  app.registerComponent("credentials.secretManager", SecretSourceManager);
  if (app.guest) return;
  app.registerTab("vault-unlock", VaultUnlockTab, {
    titleKey: "unlock.title",
    hostless: true,
    singleton: true,
  });
  app.registerPaletteEntry({
    id: "vault-unlock",
    titleKey: "unlock.title",
    keywords: ["bitwarden", "vaultwarden", "unlock", "vault"],
    scope: "global",
    run: (shell) => shell.openSingletonTab("vault-unlock"),
  });
}
