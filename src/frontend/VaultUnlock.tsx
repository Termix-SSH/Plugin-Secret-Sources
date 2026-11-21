import { useEffect, useState } from "react";
import { toast } from "sonner";
import {
  Button,
  Input,
  PasswordInput,
  Segmented,
} from "@termix-ssh/plugin-sdk/ui";
import { useTranslation } from "@termix-ssh/plugin-sdk/frontend";
import type {
  SecretSource,
  SecretSourcesApi,
  UnlockBody,
  VaultSession,
} from "./secret-sources-api";

type Method = "sso" | "password" | "apikey";

/** The server's error text and, for a two-step login, its providers. */
function failure(error: unknown): { message: string; twoFactor?: number[] } {
  const data = (error as { response?: { data?: unknown } })?.response?.data as
    { error?: unknown; twoFactor?: unknown } | undefined;
  const message =
    typeof data?.error === "string"
      ? data.error
      : String((error as { message?: unknown })?.message ?? error);
  return {
    message,
    ...(Array.isArray(data?.twoFactor)
      ? { twoFactor: data.twoFactor.map(Number) }
      : {}),
  };
}

const LABEL =
  "text-[9px] font-bold uppercase tracking-widest text-muted-foreground";

/**
 * Signs the person in to their own Bitwarden or Vaultwarden account for one
 * source and unlocks it with their master password.
 */
export function VaultUnlock({
  api,
  source,
  onChange,
}: {
  api: SecretSourcesApi;
  source: SecretSource;
  onChange?: (session: VaultSession) => void;
}) {
  const { t } = useTranslation();
  const [session, setSession] = useState<VaultSession | null>(null);
  const [method, setMethod] = useState<Method>("sso");
  const [values, setValues] = useState<Record<string, string>>({});
  const [twoFactor, setTwoFactor] = useState<number[] | null>(null);
  const [ssoOpened, setSsoOpened] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    api
      .session(source.id)
      .then((next) => {
        if (live) setSession(next);
      })
      .catch((error) => toast.error(failure(error).message));
    return () => {
      live = false;
    };
  }, [api, source.id]);

  const set = (key: string, value: string) =>
    setValues((prev) => ({ ...prev, [key]: value }));

  const done = (next: VaultSession) => {
    setSession(next);
    setValues({});
    setTwoFactor(null);
    setSsoOpened(false);
    onChange?.(next);
  };

  const openSso = async () => {
    setBusy(true);
    try {
      const url = await api.startSso(source.id);
      window.open(url, "_blank", "noopener,noreferrer");
      setSsoOpened(true);
    } catch (error) {
      toast.error(failure(error).message);
    } finally {
      setBusy(false);
    }
  };

  const unlock = async () => {
    const password = values.password ?? "";
    let body: UnlockBody;
    if (method === "sso") {
      body = { method, redirect: values.redirect ?? "", password };
    } else if (method === "apikey") {
      body = {
        method,
        clientId: values.clientId ?? "",
        clientSecret: values.clientSecret ?? "",
        password,
      };
    } else {
      body = {
        method,
        email: values.email ?? "",
        password,
        ...(twoFactor && values.code
          ? { twoFactorProvider: twoFactor[0], twoFactorCode: values.code }
          : {}),
      };
    }
    setBusy(true);
    try {
      done(await api.unlock(source.id, body));
      toast.success(t("unlock.done"));
    } catch (error) {
      const { message, twoFactor: providers } = failure(error);
      if (providers?.length) {
        setTwoFactor(providers);
        toast.message(t("unlock.codeNeeded"));
      } else {
        toast.error(message);
      }
    } finally {
      setBusy(false);
    }
  };

  const lock = async () => {
    setBusy(true);
    try {
      await api.lock(source.id);
      done({ unlocked: false, email: null, method: null, expiresAt: null });
    } catch (error) {
      toast.error(failure(error).message);
    } finally {
      setBusy(false);
    }
  };

  if (!session) return null;

  if (session.unlocked) {
    return (
      <div className="flex items-center gap-2 text-xs">
        <span className="flex-1 text-muted-foreground" role="status">
          {t("unlock.unlockedAs", {
            email: session.email ?? "",
            until: session.expiresAt
              ? new Date(session.expiresAt).toLocaleString()
              : "",
          })}
        </span>
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="h-7 text-[10px]"
          disabled={busy}
          onClick={() => void lock()}
        >
          {t("unlock.lock")}
        </Button>
      </div>
    );
  }

  const field = (key: string, label: string, secret = false) => {
    const Field = secret ? PasswordInput : Input;
    return (
      <div className="flex flex-col gap-1">
        <label htmlFor={`vault-${source.id}-${key}`} className={LABEL}>
          {label}
        </label>
        <Field
          id={`vault-${source.id}-${key}`}
          className={`h-8 text-xs${secret ? " pr-8" : ""}`}
          value={values[key] ?? ""}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
            set(key, e.target.value)
          }
        />
      </div>
    );
  };

  const ready =
    !!values.password &&
    (method === "sso"
      ? !!values.redirect?.trim()
      : method === "apikey"
        ? !!values.clientId?.trim() && !!values.clientSecret?.trim()
        : !!values.email?.trim() && (!twoFactor || !!values.code?.trim()));

  return (
    <div className="flex flex-col gap-2">
      <p className="text-[10px] text-muted-foreground">{t("unlock.intro")}</p>
      <Segmented
        value={method}
        onChange={(next) => {
          setMethod(next);
          setTwoFactor(null);
        }}
        options={[
          { value: "sso", label: t("unlock.methods.sso") },
          { value: "password", label: t("unlock.methods.password") },
          { value: "apikey", label: t("unlock.methods.apikey") },
        ]}
      />
      {method === "sso" && (
        <>
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="h-7 text-[10px]"
              disabled={busy}
              onClick={() => void openSso()}
            >
              {t("unlock.ssoOpen")}
            </Button>
            <span className="text-[10px] text-muted-foreground">
              {ssoOpened ? t("unlock.ssoPaste") : t("unlock.ssoHint")}
            </span>
          </div>
          {field("redirect", t("unlock.ssoAddress"))}
        </>
      )}
      {method === "password" && <>{field("email", t("unlock.email"))}</>}
      {method === "apikey" && (
        <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
          {field("clientId", t("unlock.clientId"))}
          {field("clientSecret", t("unlock.clientSecret"), true)}
        </div>
      )}
      {field("password", t("unlock.masterPassword"), true)}
      {method === "password" && twoFactor && field("code", t("unlock.code"))}
      <div className="flex justify-end">
        <Button
          type="button"
          variant="outline"
          size="sm"
          className="border-accent-brand/40 text-accent-brand"
          disabled={busy || !ready}
          onClick={() => void unlock()}
        >
          {t("unlock.submit")}
        </Button>
      </div>
    </div>
  );
}
