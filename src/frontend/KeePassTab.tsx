import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  type FormEvent,
} from "react";
import { Plus, KeyRound, RefreshCw } from "lucide-react";
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
  type DatabaseStatus,
  type FolderListing,
  type KeePassApi,
  type Status,
} from "./api";

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
  allowRemember,
  onConnected,
  onCancel,
}: {
  api: KeePassApi;
  /** False when an admin forbids storing master passwords. */
  allowRemember: boolean;
  onConnected: (status: Status) => void;
  /** Shown once a database is connected, to close the form again. */
  onCancel?: () => void;
}) {
  const { t } = useTranslation();
  const [remember, setRemember] = useState(allowRemember);
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
          rememberPassword: allowRemember && remember,
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
        {allowRemember ? (
          <SwitchRow
            label={t("connect.remember")}
            description={t("connect.rememberHint")}
            checked={remember}
            onChange={setRemember}
          />
        ) : (
          <p className="text-muted-foreground">{t("connect.rememberOff")}</p>
        )}
        {error && <p className="text-destructive">{error}</p>}
        <div className="flex gap-1">
          <Button type="submit" size="sm" disabled={busy || !ready}>
            {busy ? t("connect.connecting") : t("connect.submit")}
          </Button>
          {onCancel && (
            <Button
              type="button"
              size="sm"
              variant="ghost"
              disabled={busy}
              onClick={onCancel}
            >
              {t("connect.cancel")}
            </Button>
          )}
        </div>
      </form>
    </SectionCard>
  );
}

/** Asks for the master password of a database that doesn't remember it. */
function UnlockForm({
  api,
  status,
  onStatus,
}: {
  api: KeePassApi;
  status: DatabaseStatus;
  onStatus: (status: Status) => void;
}) {
  const { t } = useTranslation();
  const [password, setPassword] = useState("");
  const [keyFile, setKeyFile] = useState<string | undefined>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();

  const pickKeyFile = async (file: File | undefined) => {
    setError(undefined);
    if (!file) return setKeyFile(undefined);
    if (file.size > MAX_KEY_FILE_BYTES) {
      setKeyFile(undefined);
      return setError(t("connect.keyFileTooBig"));
    }
    setKeyFile(await fileToBase64(file));
  };

  const ready = status.keyFileUploaded
    ? Boolean(keyFile)
    : Boolean(password || status.keyFilePath);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(undefined);
    try {
      onStatus(
        await api.unlock(status.id, {
          password,
          ...(keyFile ? { keyFile } : {}),
        }),
      );
      setPassword("");
      toast.success(t("unlock.done"));
    } catch (e) {
      setError(errorMessage(e, t("error.generic")));
    } finally {
      setBusy(false);
    }
  };

  const fileId = `keepass-unlock-key-${status.id}`;
  return (
    <form
      onSubmit={submit}
      className="flex flex-col gap-2 border border-border p-2 text-xs"
    >
      <ListBadge tone="warning">{t("unlock.locked")}</ListBadge>
      <p className="text-muted-foreground">{t("unlock.hint")}</p>
      <SecretField
        label={t("connect.passwordLabel")}
        value={password}
        onChange={setPassword}
        disabled={busy}
      />
      {status.keyFileUploaded && (
        <Field label={t("unlock.keyFile")} htmlFor={fileId}>
          <input
            id={fileId}
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
          {busy ? t("unlock.unlocking") : t("unlock.submit")}
        </Button>
      </div>
    </form>
  );
}

function DatabaseView({
  api,
  status,
  syncIntervalMinutes,
  allowRemember,
  onStatus,
}: {
  api: KeePassApi;
  status: DatabaseStatus;
  syncIntervalMinutes: number;
  allowRemember: boolean;
  onStatus: (status: Status) => void;
}) {
  const { t } = useTranslation();
  const confirm = useConfirm();
  const [chosen, setChosen] = useState<string[]>(status.groups);
  const [removeMissing, setRemoveMissing] = useState(status.removeMissing);
  const [passwordReferences, setPasswordReferences] = useState(
    status.passwordReferences,
  );
  const [rememberPassword, setRememberPassword] = useState(
    status.rememberPassword,
  );
  const [busy, setBusy] = useState<
    null | "save" | "sync" | "refresh" | "disconnect" | "lock"
  >(null);

  useEffect(() => {
    setChosen(status.groups);
    setRemoveMissing(status.removeMissing);
    setPasswordReferences(status.passwordReferences);
    setRememberPassword(status.rememberPassword);
  }, [
    status.groups,
    status.removeMissing,
    status.passwordReferences,
    status.rememberPassword,
  ]);

  const dirty =
    removeMissing !== status.removeMissing ||
    passwordReferences !== status.passwordReferences ||
    rememberPassword !== status.rememberPassword ||
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
      if (kind === "sync") {
        const fresh = await api.status().catch(() => null);
        if (fresh) onStatus(fresh);
      }
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
      () => api.disconnect(status.id, removeCredentials),
      t("account.disconnected"),
    );
  };

  const summary = status.lastSummary;

  return (
    <div className="flex flex-col gap-2">
      <SectionCard
        title={status.databasePath}
        icon={<KeyRound className="size-4" />}
        action={
          <div className="flex gap-1">
            {!status.rememberPassword && !status.locked && (
              <Button
                size="sm"
                variant="ghost"
                onClick={() =>
                  run("lock", () => api.lock(status.id), t("unlock.lockedNow"))
                }
                disabled={busy !== null}
              >
                {t("unlock.lock")}
              </Button>
            )}
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
          label={t("account.keyFile")}
          value={
            status.keyFilePath ??
            (status.keyFileUploaded
              ? t("account.keyFileUploaded")
              : t("account.keyFileNone"))
          }
          mono={Boolean(status.keyFilePath)}
        />
        <StatRow
          label={t("account.password")}
          value={
            status.rememberPassword
              ? t("account.passwordRemembered")
              : t("account.passwordMemory")
          }
        />
        {status.locked && (
          <UnlockForm api={api} status={status} onStatus={onStatus} />
        )}
      </SectionCard>

      <SectionCard
        title={t("groups.title")}
        icon={<KeyRound className="size-4" />}
        action={
          <Button
            size="sm"
            variant="ghost"
            disabled={busy !== null}
            onClick={() => run("refresh", () => api.refreshGroups(status.id))}
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
                const id = `keepass-group-${status.id}-${row.path}`;
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
          {allowRemember && (
            <SwitchRow
              label={t("connect.remember")}
              description={t("groups.rememberHint")}
              checked={rememberPassword}
              onChange={setRememberPassword}
            />
          )}
          <div>
            <Button
              size="sm"
              disabled={!dirty || busy !== null}
              onClick={() =>
                run(
                  "save",
                  () =>
                    api.saveConfig(
                      status.id,
                      chosen,
                      removeMissing,
                      passwordReferences,
                      rememberPassword,
                    ),
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
            disabled={
              busy !== null ||
              dirty ||
              status.locked ||
              status.groups.length === 0
            }
            onClick={() => run("sync", () => api.sync(status.id), t("sync.ok"))}
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
            {syncIntervalMinutes > 0
              ? t("sync.interval", { count: syncIntervalMinutes })
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
  const [adding, setAdding] = useState(false);
  const [syncing, setSyncing] = useState(false);

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

  const syncAll = async () => {
    setSyncing(true);
    try {
      const result = await api.syncAll();
      setStatus(result);
      if (result.failed) {
        toast.error(t("databases.syncAllFailed", { count: result.failed }));
      } else if (result.locked) {
        toast.warning(t("databases.syncAllLocked", { count: result.locked }));
      } else {
        toast.success(t("sync.ok"));
      }
    } catch (e) {
      toast.error(errorMessage(e, t("error.generic")));
    } finally {
      setSyncing(false);
    }
  };

  const databases = status?.databases ?? [];
  const syncable = databases.some((d) => d.groups.length > 0);

  return (
    <PanelShell
      icon={<KeyRound className="size-4" />}
      title={t("tab.title")}
      scroll
    >
      <div className="flex flex-col gap-2 p-2.5">
        {failed && <EmptyState title={t("error.load")} />}
        {!failed && status && (
          <>
            {databases.length > 0 && (
              <div className="flex items-center gap-1">
                <span className="flex-1 text-xs text-muted-foreground">
                  {t("databases.count", { count: databases.length })}
                </span>
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={adding}
                  onClick={() => setAdding(true)}
                >
                  <Plus className="size-3.5" />
                  {t("databases.add")}
                </Button>
                <Button
                  size="sm"
                  disabled={syncing || !syncable}
                  onClick={syncAll}
                >
                  {syncing ? t("sync.running") : t("databases.syncAll")}
                </Button>
              </div>
            )}
            {(databases.length === 0 || adding) && (
              <ConnectForm
                api={api}
                allowRemember={status.allowRememberPassword}
                onConnected={(next) => {
                  setStatus(next);
                  setAdding(false);
                }}
                onCancel={databases.length ? () => setAdding(false) : undefined}
              />
            )}
            {databases.map((database) => (
              <DatabaseView
                key={database.id}
                api={api}
                status={database}
                syncIntervalMinutes={status.syncIntervalMinutes}
                allowRemember={status.allowRememberPassword}
                onStatus={setStatus}
              />
            ))}
          </>
        )}
      </div>
    </PanelShell>
  );
}
