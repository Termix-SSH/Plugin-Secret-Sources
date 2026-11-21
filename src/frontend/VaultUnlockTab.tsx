import { useEffect, useMemo, useState } from "react";
import {
  LoadingState,
  NoticePanel,
  PANEL,
  PanelFrame,
  PanelShell,
} from "@termix-ssh/plugin-sdk/ui";
import { usePluginApi, useTranslation } from "@termix-ssh/plugin-sdk/frontend";
import {
  createSecretSourcesApi,
  type SecretSource,
} from "./secret-sources-api";
import { isPerUserKind } from "./source-kinds";
import { VaultUnlock } from "./VaultUnlock";

/**
 * Opened from a connect that needs the person's own vault unlocked first,
 * or from the palette.
 */
export function VaultUnlockTab() {
  const { t } = useTranslation();
  const pluginApi = usePluginApi();
  const api = useMemo(() => createSecretSourcesApi(pluginApi), [pluginApi]);
  const [sources, setSources] = useState<SecretSource[] | null>(null);
  const [unlocked, setUnlocked] = useState(false);

  useEffect(() => {
    let live = true;
    api
      .list()
      .then((all) => {
        if (live) setSources(all.filter((s) => isPerUserKind(s.kind)));
      })
      .catch(() => {
        if (live) setSources([]);
      });
    return () => {
      live = false;
    };
  }, [api]);

  return (
    <PanelFrame>
      <PanelShell>
        {sources === null ? (
          <LoadingState />
        ) : sources.length === 0 ? (
          <NoticePanel title={t("unlock.none")}>
            {t("unlock.noneHint")}
          </NoticePanel>
        ) : (
          <div className={`flex max-w-lg flex-col gap-4 ${PANEL.body}`}>
            {unlocked && (
              <p className="text-sm text-accent-brand" role="status">
                {t("unlock.retry")}
              </p>
            )}
            {sources.map((source) => (
              <div key={source.id} className="flex flex-col gap-2">
                <div className="text-sm font-medium">
                  {source.name}
                  <span className="ml-2 text-xs text-muted-foreground">
                    {source.baseUrl}
                  </span>
                </div>
                <VaultUnlock
                  api={api}
                  source={source}
                  onChange={(session) => {
                    if (session.unlocked) setUnlocked(true);
                  }}
                />
              </div>
            ))}
          </div>
        )}
      </PanelShell>
    </PanelFrame>
  );
}
