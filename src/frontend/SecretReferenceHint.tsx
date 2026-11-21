import { useEffect, useState } from "react";
import { KeyRound } from "lucide-react";
import { usePluginApi, useTranslation } from "@termix-ssh/plugin-sdk/frontend";
import {
  Button,
  Input,
  LoadingState,
  Select2,
} from "@termix-ssh/plugin-sdk/ui";
import {
  createSecretSourcesApi,
  type PickItem,
  type SecretSource,
} from "./secret-sources-api";

/** Kinds whose server can list items for the picker. */
const PICKABLE = new Set(["bitwarden-cli"]);

export interface PickedRefs {
  username?: string;
  password?: string;
}

/** Browse a source and fill the username and password with references. */
function Picker({
  onFill,
  onClose,
}: {
  onFill: (refs: PickedRefs) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation();
  const api = createSecretSourcesApi(usePluginApi());
  const [sources, setSources] = useState<SecretSource[] | null>(null);
  const [sourceId, setSourceId] = useState("");
  const [search, setSearch] = useState("");
  const [items, setItems] = useState<PickItem[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    void api
      .list()
      .then((list) => {
        const usable = list.filter((s) => PICKABLE.has(s.kind));
        setSources(usable);
        setSourceId((current) => current || usable[0]?.id || "");
      })
      .catch(() => setSources([]));
    // The API client is rebuilt each render; load once.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!sourceId) return;
    let live = true;
    setItems(null);
    setError("");
    const timer = window.setTimeout(() => {
      api
        .items(sourceId, search)
        .then((list) => {
          if (live) setItems(list);
        })
        .catch(() => {
          if (live) setError(t("picker.failed"));
        });
    }, 250);
    return () => {
      live = false;
      window.clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sourceId, search]);

  if (sources && sources.length === 0) {
    return (
      <div className="flex flex-col gap-1 border border-border p-2 text-xs text-muted-foreground">
        {t("picker.noSources")}
        <Button size="xs" variant="ghost" className="w-fit" onClick={onClose}>
          {t("picker.close")}
        </Button>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2 border border-border p-2">
      <div className="flex flex-wrap items-center gap-2">
        {sources && sources.length > 1 && (
          <Select2
            className="h-8 text-xs"
            value={sourceId}
            onChange={(e) => setSourceId(e.target.value)}
          >
            {sources.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </Select2>
        )}
        <Input
          className="h-8 min-w-40 flex-1 text-xs"
          value={search}
          placeholder={t("picker.search")}
          onChange={(e) => setSearch(e.target.value)}
        />
        <Button size="xs" variant="ghost" onClick={onClose}>
          {t("picker.close")}
        </Button>
      </div>
      {error ? (
        <p className="text-xs text-destructive">{error}</p>
      ) : !items ? (
        <LoadingState compact label={t("picker.loading")} />
      ) : items.length === 0 ? (
        <p className="text-xs text-muted-foreground">{t("picker.empty")}</p>
      ) : (
        <div className="flex max-h-56 flex-col overflow-auto">
          {items.map((item) => (
            <button
              key={item.id}
              type="button"
              className="flex items-center gap-2 border-b border-border px-2 py-1.5 text-left text-xs last:border-b-0 hover:bg-muted/50"
              onClick={() => {
                onFill({
                  ...(item.username ? { username: item.username } : {}),
                  ...(item.password ? { password: item.password } : {}),
                });
                onClose();
              }}
            >
              <KeyRound className="size-3 shrink-0 text-muted-foreground" />
              <span className="min-w-0 flex-1 truncate">{item.name}</span>
              {item.folder && (
                <span className="shrink-0 text-muted-foreground">
                  {item.folder}
                </span>
              )}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * One line under a secret field: references are allowed, here is where to
 * set them up. With onFill, a picker fills the username and password.
 */
export function SecretReferenceHint({
  onManage,
  onFill,
}: {
  onManage: () => void;
  onFill?: (refs: PickedRefs) => void;
}) {
  const { t } = useTranslation();
  const [picking, setPicking] = useState(false);
  return (
    <div className="flex flex-col gap-1">
      <p className="text-[10px] text-muted-foreground">
        {t("hint")}{" "}
        <button
          type="button"
          className="text-accent-brand hover:underline"
          onClick={onManage}
        >
          {t("manage")}
        </button>
        {onFill && (
          <>
            {" | "}
            <button
              type="button"
              className="text-accent-brand hover:underline"
              onClick={() => setPicking((v) => !v)}
            >
              {t("picker.open")}
            </button>
          </>
        )}
      </p>
      {picking && onFill && (
        <Picker onFill={onFill} onClose={() => setPicking(false)} />
      )}
    </div>
  );
}
