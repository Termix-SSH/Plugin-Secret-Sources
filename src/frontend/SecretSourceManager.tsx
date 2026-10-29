import { useCallback, useEffect, useMemo, useState } from "react";
import { KeyRound, Pencil, Plus, Trash2, X } from "lucide-react";
import { toast } from "sonner";
import {
  Button,
  Input,
  PasswordInput,
  Select2,
  useConfirm,
  Checkbox,
} from "@termix-ssh/plugin-sdk/ui";
import { usePluginApi, useTranslation } from "@termix-ssh/plugin-sdk/frontend";
import {
  createSecretSourcesApi,
  type SecretSource,
} from "./secret-sources-api";
import {
  credentialComplete,
  KIND_SPECS,
  serializeCredential,
  specFor,
  type SecretSourceKind,
} from "./source-kinds";

function errorMessage(error: unknown): string {
  if (error && typeof error === "object" && "message" in error) {
    return String((error as { message?: unknown }).message ?? "");
  }
  return String(error);
}

type FormState = {
  id?: string;
  name: string;
  kind: SecretSourceKind;
  baseUrl: string;
  credential: Record<string, string>;
  shared: boolean;
};

const emptyForm: FormState = {
  name: "",
  kind: "onepassword-connect",
  baseUrl: "",
  credential: {},
  shared: false,
};

export function SecretSourceManager({ onClose }: { onClose: () => void }) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const pluginApi = usePluginApi();
  const api = useMemo(() => createSecretSourcesApi(pluginApi), [pluginApi]);
  const [sources, setSources] = useState<SecretSource[]>([]);
  const [form, setForm] = useState<FormState | null>(null);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      setSources(await api.list());
    } catch (e) {
      toast.error(errorMessage(e));
    }
  }, [api]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const setField = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((prev) => (prev ? { ...prev, [key]: value } : prev));

  const handleSave = async () => {
    if (!form) return;
    const spec = specFor(form.kind);
    const token = serializeCredential(spec, form.credential);
    if (
      !form.name.trim() ||
      !form.baseUrl.trim() ||
      (!form.id && !credentialComplete(spec, form.credential))
    ) {
      toast.error(t("required"));
      return;
    }
    setSaving(true);
    try {
      if (form.id) {
        await api.update(form.id, {
          name: form.name,
          baseUrl: form.baseUrl,
          shared: form.shared,
          ...(token ? { token } : {}),
        });
      } else {
        await api.create({
          name: form.name,
          kind: form.kind,
          baseUrl: form.baseUrl,
          token,
          shared: form.shared,
        });
      }
      toast.success(t("saved"));
      setForm(null);
      await reload();
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (source: SecretSource) => {
    const ok = await confirm({
      title: t("deleteConfirm", { name: source.name }),
      confirmLabel: t("common.delete"),
    });
    if (!ok) return;
    try {
      await api.remove(source.id);
      toast.success(t("deleted"));
      await reload();
    } catch (e) {
      toast.error(errorMessage(e));
    }
  };

  const handleTest = async (source: SecretSource) => {
    setTesting(source.id);
    try {
      const result = await api.test(source.id);
      if (result.ok) {
        toast.success(result.detail ?? t("testPassed"));
      } else {
        toast.error(result.error ?? t("testFailed"));
      }
    } catch (e) {
      toast.error(errorMessage(e));
    } finally {
      setTesting(null);
    }
  };

  return (
    <div className="flex flex-col gap-3 col-span-2 border border-border bg-muted/20 p-3">
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
          {t("title")}
        </span>
        <button
          type="button"
          onClick={onClose}
          aria-label={t("common.close")}
          className="text-muted-foreground hover:text-foreground"
        >
          <X className="size-3.5" />
        </button>
      </div>
      <p className="text-[10px] text-muted-foreground">{t("description")}</p>

      {!form && (
        <>
          {sources.map((source) => (
            <div
              key={source.id}
              className="flex items-center gap-2 border border-border bg-background px-2 py-1.5 text-xs"
            >
              <KeyRound className="size-3.5 text-muted-foreground shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="truncate">
                  {source.name}
                  {source.shared && (
                    <span className="ml-1 text-[9px] uppercase text-muted-foreground">
                      {t("shared")}
                    </span>
                  )}
                </div>
                <div className="truncate text-[10px] text-muted-foreground">
                  {t(specFor(source.kind).labelKey)} | {source.baseUrl}
                </div>
              </div>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                className="h-6 text-[10px]"
                disabled={testing === source.id}
                onClick={() => void handleTest(source)}
              >
                {t("test")}
              </Button>
              {source.owned && (
                <>
                  <button
                    type="button"
                    aria-label={t("common.edit")}
                    className="text-muted-foreground hover:text-foreground"
                    onClick={() =>
                      setForm({
                        id: source.id,
                        name: source.name,
                        kind: specFor(source.kind).kind,
                        baseUrl: source.baseUrl,
                        credential: {},
                        shared: source.shared,
                      })
                    }
                  >
                    <Pencil className="size-3.5" />
                  </button>
                  <button
                    type="button"
                    aria-label={t("common.delete")}
                    className="text-muted-foreground hover:text-destructive"
                    onClick={() => void handleDelete(source)}
                  >
                    <Trash2 className="size-3.5" />
                  </button>
                </>
              )}
            </div>
          ))}
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="self-start border-accent-brand/40 text-accent-brand"
            onClick={() => setForm(emptyForm)}
          >
            <Plus className="size-3 mr-1" /> {t("new")}
          </Button>
        </>
      )}

      {form && (
        <div className="flex flex-col gap-2">
          <div className="flex flex-col gap-1">
            <label className="text-[9px] font-bold uppercase tracking-widest text-muted-foreground">
              {t("kindLabel")}
            </label>
            <Select2
              className="h-8 text-xs"
              value={form.kind}
              disabled={!!form.id}
              onChange={(e) => {
                const spec = specFor(e.target.value);
                setForm((prev) =>
                  prev
                    ? {
                        ...prev,
                        kind: spec.kind,
                        baseUrl: prev.baseUrl || spec.defaultUrl,
                        credential: {},
                      }
                    : prev,
                );
              }}
            >
              {KIND_SPECS.map((spec) => (
                <option key={spec.kind} value={spec.kind}>
                  {t(spec.labelKey)}
                </option>
              ))}
            </Select2>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            <div className="flex flex-col gap-1">
              <label className="text-[9px] font-bold uppercase tracking-widest text-muted-foreground">
                {t("nameLabel")}
              </label>
              <Input
                className="h-8 text-xs"
                placeholder={t("namePlaceholder")}
                value={form.name}
                onChange={(e) => setField("name", e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-[9px] font-bold uppercase tracking-widest text-muted-foreground">
                {t(specFor(form.kind).urlLabelKey)}
              </label>
              <Input
                className="h-8 text-xs"
                placeholder={specFor(form.kind).urlPlaceholder}
                value={form.baseUrl}
                onChange={(e) => setField("baseUrl", e.target.value)}
              />
            </div>
          </div>
          {specFor(form.kind).fields.map((field) => {
            const Field = field.secret ? PasswordInput : Input;
            return (
              <div key={field.key} className="flex flex-col gap-1">
                <label className="text-[9px] font-bold uppercase tracking-widest text-muted-foreground">
                  {t(field.labelKey)}
                </label>
                <Field
                  className={`h-8 text-xs${field.secret ? " pr-8" : ""}`}
                  placeholder={
                    form.id ? t("tokenKeep") : (field.placeholder ?? "")
                  }
                  value={form.credential[field.key] ?? ""}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                    setField("credential", {
                      ...form.credential,
                      [field.key]: e.target.value,
                    })
                  }
                />
              </div>
            );
          })}
          <p className="text-[10px] text-muted-foreground">
            {t(`kindHints.${form.kind}`)}{" "}
            <code className="font-mono">{specFor(form.kind).example}</code>
          </p>
          <label className="flex items-center gap-2 text-xs text-foreground">
            <Checkbox
              checked={form.shared}
              onCheckedChange={(checked) =>
                setField("shared", checked === true)
              }
            />
            {t("sharedLabel")}
          </label>
          <div className="flex justify-end gap-2">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => setForm(null)}
              disabled={saving}
            >
              {t("common.cancel")}
            </Button>
            <Button
              type="button"
              variant="outline"
              size="sm"
              className="border-accent-brand/40 text-accent-brand"
              onClick={() => void handleSave()}
              disabled={saving}
            >
              {form.id ? t("common.save") : t("common.create")}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
