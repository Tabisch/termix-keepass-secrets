import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
} from "react";
import { KeyRound, RefreshCw } from "lucide-react";
import { toast } from "sonner";
import { useTranslation, type TabProps } from "@termix-ssh/plugin-sdk/frontend";
import {
  Button,
  Checkbox,
  EmptyState,
  Field,
  ListBadge,
  ListRow,
  PanelList,
  PanelShell,
  SectionCard,
  SecretField,
  StatRow,
  SwitchRow,
  TextField,
  useConfirm,
} from "@termix-ssh/plugin-sdk/ui";
import {
  errorMessage,
  fileToBase64,
  type FolderListing,
  type KeePassApi,
  type Status,
} from "./api";

type Connected = Extract<Status, { connected: true }>;

/** Matches the server's limit, so a wrong file is refused before upload. */
const MAX_KEY_FILE_BYTES = 64 * 1024;

/** Paths found in the KeePass folder, to click instead of typing. */
function Suggestions({
  paths,
  onPick,
  disabled,
}: {
  paths: string[];
  onPick: (path: string) => void;
  disabled: boolean;
}) {
  if (!paths.length) return null;
  return (
    <div className="flex flex-wrap gap-1">
      {paths.map((path) => (
        <Button
          key={path}
          type="button"
          size="sm"
          variant="ghost"
          className="font-mono"
          disabled={disabled}
          onClick={() => onPick(path)}
        >
          {path}
        </Button>
      ))}
    </div>
  );
}

function ConnectForm({
  api,
  onConnected,
}: {
  api: KeePassApi;
  onConnected: (status: Status) => void;
}) {
  const { t } = useTranslation();
  const [listing, setListing] = useState<FolderListing | null>(null);
  const [listError, setListError] = useState<string | undefined>();
  const [databasePath, setDatabasePath] = useState("");
  const [password, setPassword] = useState("");
  const [keyFilePath, setKeyFilePath] = useState("");
  const [keyFile, setKeyFile] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();

  useEffect(() => {
    let live = true;
    api
      .files()
      .then((result) => {
        if (!live) return;
        setListing(result);
        if (result.databases.length === 1) {
          setDatabasePath(result.databases[0]!);
        }
      })
      .catch(
        (e) => live && setListError(errorMessage(e, t("connect.listFailed"))),
      );
    return () => {
      live = false;
    };
  }, [api, t]);

  const pickKeyFile = async (file: File | undefined) => {
    setError(undefined);
    if (!file) return setKeyFile(undefined);
    if (file.size > MAX_KEY_FILE_BYTES) {
      setKeyFile(undefined);
      return setError(t("connect.keyFileTooBig"));
    }
    setKeyFile(await fileToBase64(file));
  };

  const ready =
    databasePath.trim() && (password || keyFilePath.trim() || keyFile);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(undefined);
    try {
      onConnected(
        await api.connect({
          databasePath: databasePath.trim(),
          password,
          ...(keyFilePath.trim()
            ? { keyFilePath: keyFilePath.trim() }
            : keyFile
              ? { keyFile }
              : {}),
        }),
      );
      setPassword("");
    } catch (e) {
      setError(errorMessage(e, t("error.generic")));
    } finally {
      setBusy(false);
    }
  };

  return (
    <SectionCard
      title={t("connect.title")}
      icon={<KeyRound className="size-4" />}
    >
      <form onSubmit={submit} className="flex flex-col gap-3 text-xs">
        <p className="text-muted-foreground">{t("connect.intro")}</p>
        {listError && <p className="text-destructive">{listError}</p>}
        {listing && !listing.databases.length && (
          <p className="text-muted-foreground">{t("connect.noDatabases")}</p>
        )}
        <TextField
          label={t("connect.database")}
          value={databasePath}
          onChange={setDatabasePath}
          placeholder={t("connect.databasePlaceholder")}
          disabled={busy}
          mono
        />
        <Suggestions
          paths={listing?.databases ?? []}
          onPick={setDatabasePath}
          disabled={busy}
        />
        <SecretField
          label={t("connect.passwordLabel")}
          value={password}
          onChange={setPassword}
          hint={t("connect.passwordHint")}
          disabled={busy}
        />
        <TextField
          label={t("connect.keyFile")}
          value={keyFilePath}
          onChange={setKeyFilePath}
          placeholder={t("connect.keyFileNone")}
          disabled={busy}
          mono
        />
        <Suggestions
          paths={listing?.keyFiles ?? []}
          onPick={setKeyFilePath}
          disabled={busy}
        />
        {!keyFilePath.trim() && (
          <Field
            label={t("connect.keyFileUploadLabel")}
            hint={t("connect.keyFileUploadHint")}
            htmlFor="keepass-key-file"
          >
            <input
              id="keepass-key-file"
              type="file"
              disabled={busy}
              className="text-xs"
              onChange={(event) => void pickKeyFile(event.target.files?.[0])}
            />
          </Field>
        )}
        {error && <p className="text-destructive">{error}</p>}
        <div>
          <Button type="submit" size="sm" disabled={busy || !ready}>
            {busy ? t("connect.connecting") : t("connect.submit")}
          </Button>
        </div>
      </form>
    </SectionCard>
  );
}

function ConnectedView({
  api,
  status,
  onStatus,
}: {
  api: KeePassApi;
  status: Connected;
  onStatus: (status: Status) => void;
}) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [chosen, setChosen] = useState<string[]>(status.groups);
  const [removeMissing, setRemoveMissing] = useState(status.removeMissing);
  const [passwordReferences, setPasswordReferences] = useState(
    status.passwordReferences,
  );
  const [busy, setBusy] = useState<
    null | "save" | "sync" | "refresh" | "disconnect"
  >(null);

  useEffect(() => {
    setChosen(status.groups);
    setRemoveMissing(status.removeMissing);
    setPasswordReferences(status.passwordReferences);
  }, [status.groups, status.removeMissing, status.passwordReferences]);

  const dirty =
    removeMissing !== status.removeMissing ||
    passwordReferences !== status.passwordReferences ||
    chosen.length !== status.groups.length ||
    chosen.some((name, index) => name !== status.groups[index]);

  // Chosen groups that are gone from the database still show, so they can be unticked.
  const rows = useMemo(() => {
    const available = status.availableGroups.map((g) => ({
      ...g,
      missing: false,
    }));
    const known = new Set(available.map((g) => g.path.toLowerCase()));
    for (const path of status.groups) {
      if (!known.has(path.toLowerCase())) {
        available.push({ path, entries: 0, missing: true });
      }
    }
    return available;
  }, [status.availableGroups, status.groups]);

  const run = async (
    kind: NonNullable<typeof busy>,
    action: () => Promise<Status>,
    success?: string,
  ) => {
    setBusy(kind);
    try {
      onStatus(await action());
      if (success) toast.success(success);
    } catch (e) {
      toast.error(errorMessage(e, t("error.generic")));
      // A failed sync still recorded why, so show it.
      if (kind === "sync") onStatus(await api.status().catch(() => status));
    } finally {
      setBusy(null);
    }
  };

  const toggle = (path: string, on: boolean) =>
    setChosen((previous) =>
      on ? [...previous, path] : previous.filter((entry) => entry !== path),
    );

  const disconnect = async (removeCredentials: boolean) => {
    const ok = await confirm({
      title: t("account.disconnectTitle"),
      description: t("account.disconnectBody"),
      confirmLabel: removeCredentials
        ? t("account.disconnectRemove")
        : t("account.disconnectKeep"),
    });
    if (!ok) return;
    await run(
      "disconnect",
      () => api.disconnect(removeCredentials),
      t("account.disconnected"),
    );
  };

  const summary = status.lastSummary;

  return (
    <div className="flex flex-col gap-2">
      <SectionCard
        title={t("account.title")}
        icon={<KeyRound className="size-4" />}
        action={
          <div className="flex gap-1">
            <Button
              size="sm"
              variant="ghost"
              onClick={() => disconnect(false)}
              disabled={busy !== null}
            >
              {t("account.disconnect")}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="text-destructive"
              onClick={() => disconnect(true)}
              disabled={busy !== null}
            >
              {t("account.disconnectRemove")}
            </Button>
          </div>
        }
      >
        <StatRow
          label={t("account.database")}
          value={status.databasePath}
          mono
        />
        <StatRow
          label={t("account.keyFile")}
          value={
            status.keyFilePath ??
            (status.keyFileUploaded
              ? t("account.keyFileUploaded")
              : t("account.keyFileNone"))
          }
          mono={Boolean(status.keyFilePath)}
        />
      </SectionCard>

      <SectionCard
        title={t("groups.title")}
        icon={<KeyRound className="size-4" />}
        action={
          <Button
            size="sm"
            variant="ghost"
            disabled={busy !== null}
            onClick={() => run("refresh", api.refreshGroups)}
          >
            <RefreshCw className="size-3.5" />
            {t("groups.refresh")}
          </Button>
        }
      >
        <div className="flex flex-col gap-2 text-xs">
          <p className="text-muted-foreground">{t("groups.hint")}</p>
          {rows.length === 0 ? (
            <EmptyState title={t("groups.empty")} />
          ) : (
            <div className="flex flex-col">
              {rows.map((row) => {
                const id = `keepass-group-${row.path}`;
                return (
                  <label
                    key={row.path}
                    htmlFor={id}
                    className="flex items-center gap-2 border-b border-border py-1.5 last:border-b-0"
                  >
                    <Checkbox
                      id={id}
                      checked={chosen.includes(row.path)}
                      onCheckedChange={(value) =>
                        toggle(row.path, value === true)
                      }
                    />
                    <span className="flex-1">{row.path}</span>
                    {row.missing ? (
                      <ListBadge tone="warning">
                        {t("groups.missing")}
                      </ListBadge>
                    ) : (
                      <span className="text-muted-foreground">
                        {t("groups.items", { count: row.entries })}
                      </span>
                    )}
                  </label>
                );
              })}
            </div>
          )}
          <SwitchRow
            label={t("groups.removeMissing")}
            description={t("groups.removeMissingHint")}
            checked={removeMissing}
            onChange={setRemoveMissing}
          />
          <SwitchRow
            label={t("groups.passwordReferences")}
            description={t("groups.passwordReferencesHint")}
            checked={passwordReferences}
            onChange={setPasswordReferences}
          />
          <div>
            <Button
              size="sm"
              disabled={!dirty || busy !== null}
              onClick={() =>
                run(
                  "save",
                  () =>
                    api.saveConfig(chosen, removeMissing, passwordReferences),
                  t("groups.saved"),
                )
              }
            >
              {t("groups.save")}
            </Button>
          </div>
        </div>
      </SectionCard>

      <SectionCard
        title={t("sync.title")}
        icon={<RefreshCw className="size-4" />}
        action={
          <Button
            size="sm"
            disabled={busy !== null || dirty || status.groups.length === 0}
            onClick={() => run("sync", api.sync, t("sync.ok"))}
          >
            {busy === "sync" ? t("sync.running") : t("sync.now")}
          </Button>
        }
      >
        <div className="flex flex-col gap-1 text-xs">
          <StatRow
            label={t("sync.last")}
            value={
              status.lastSyncAt
                ? new Date(status.lastSyncAt).toLocaleString()
                : t("sync.never")
            }
          />
          {status.lastStatus === "error" && (
            <p className="text-destructive">
              {t("sync.failed")}: {status.lastError}
            </p>
          )}
          {status.lastStatus === "ok" && summary && (
            <p className="text-muted-foreground">
              {t("sync.summary", { ...summary })}
              {summary.skipped > 0 && ` ${t("sync.skippedHint")}`}
            </p>
          )}
          <p className="text-muted-foreground">
            {status.syncIntervalMinutes > 0
              ? t("sync.interval", { count: status.syncIntervalMinutes })
              : t("sync.manualOnly")}
          </p>
        </div>
      </SectionCard>

      <SectionCard
        title={t("imported.title")}
        icon={<KeyRound className="size-4" />}
      >
        <PanelList empty={<EmptyState title={t("imported.empty")} />}>
          {status.items.map((item) => (
            <ListRow
              key={item.credentialId}
              title={item.title ?? String(item.credentialId)}
              meta={item.group}
            >
              <code className="text-xs text-muted-foreground select-all">
                {item.tag}
              </code>
            </ListRow>
          ))}
        </PanelList>
      </SectionCard>
    </div>
  );
}

export function KeePassTab({ isVisible, api }: TabProps & { api: KeePassApi }) {
  const { t } = useTranslation();
  const [status, setStatus] = useState<Status | null>(null);
  const [failed, setFailed] = useState(false);

  const load = useCallback(async () => {
    try {
      setStatus(await api.status());
      setFailed(false);
    } catch {
      setFailed(true);
    }
  }, [api]);

  useEffect(() => {
    if (isVisible) void load();
  }, [isVisible, load]);

  return (
    <PanelShell
      icon={<KeyRound className="size-4" />}
      title={t("tab.title")}
      scroll
    >
      <div className="p-2.5">
        {failed && <EmptyState title={t("error.load")} />}
        {!failed && status && !status.connected && (
          <ConnectForm api={api} onConnected={setStatus} />
        )}
        {!failed && status?.connected && (
          <ConnectedView api={api} status={status} onStatus={setStatus} />
        )}
      </div>
    </PanelShell>
  );
}
