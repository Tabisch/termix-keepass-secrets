import crypto from "node:crypto";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import {
  inGroup,
  openDatabase,
  type Vault,
  type VaultEntry,
} from "./keepass/database.js";
import { readFileInRoot } from "./keepass/files.js";
import {
  coreCredentialsFor,
  type CoreCredentials,
  type CredentialInput,
} from "./core-credentials.js";
import type {
  Database,
  GroupInfo,
  Repository,
  SyncSummary,
} from "./repository.js";
import type { StoredUnlock, Unlocks } from "./unlocks.js";

/** Where the KeePass folder is when an admin did not set one. */
export const DEFAULT_DATABASE_ROOT = "/keepass";

/** Tag on every credential this plugin makes, so people can filter by it. */
export const CREDENTIAL_TAG = "keepass";

/**
 * The tag that names one KeePass entry: "keepass:" and its UUID. The UUID
 * never changes, so the tag stays the same across syncs, edits, moves and a
 * credential being made again, and other plugins (NetBox Sync) can find the
 * credential by it.
 */
export function credentialIdTag(entryId: string): string {
  return `${CREDENTIAL_TAG}:${entryId}`;
}

/** The scheme this plugin resolves in a credential's password at connect. */
export const SECRET_SCHEME = "keepass";

/**
 * What a credential holds instead of the password with password references
 * on: Termix hands it to this plugin's resolver when a host connects.
 */
export function passwordReference(entryId: string): string {
  return `${SECRET_SCHEME}://${entryId}/password`;
}

export class SyncError extends Error {
  constructor(
    message: string,
    readonly code: "not_connected" | "busy" | "locked",
  ) {
    super(message);
    this.name = "SyncError";
  }
}

export interface DatabaseSource {
  databasePath: string;
  keyFilePath: string | null;
}

export async function databaseRoot(ctx: PluginContext): Promise<string> {
  const value = await ctx.settings.get<string>("databaseRoot");
  return typeof value === "string" && value.trim()
    ? value.trim()
    : DEFAULT_DATABASE_ROOT;
}

export async function loadVault(
  ctx: PluginContext,
  source: DatabaseSource,
  unlock: StoredUnlock,
): Promise<Vault> {
  const root = await databaseRoot(ctx);
  const file = await readFileInRoot(root, source.databasePath);
  const keyFile = source.keyFilePath
    ? await readFileInRoot(root, source.keyFilePath)
    : unlock.keyFile
      ? Buffer.from(unlock.keyFile, "base64")
      : null;
  return openDatabase(file, { password: unlock.password, keyFile });
}

export function groupInfos(vault: Vault): GroupInfo[] {
  return vault.groups.map(({ path, entries }) => ({ path, entries }));
}

function hostnameOf(url: string): string {
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname;
  } catch {
    return "";
  }
}

/** The entry's group without the root group, which every entry shares. */
function folderOf(entry: VaultEntry): string {
  const slash = entry.groupPath.indexOf("/");
  return slash < 0 ? entry.groupPath : entry.groupPath.slice(slash + 1);
}

export function toCredentialInput(
  entry: VaultEntry,
  useReference = false,
): CredentialInput {
  return {
    name:
      entry.title || hostnameOf(entry.url) || entry.username || "KeePass entry",
    description: entry.url,
    folder: folderOf(entry),
    tags: [CREDENTIAL_TAG, credentialIdTag(entry.id)],
    username: entry.username,
    password: useReference ? passwordReference(entry.id) : entry.password,
  };
}

function hashInput(input: CredentialInput): string {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(input))
    .digest("hex");
}

/**
 * Picks the entries in the chosen groups and the groups under them. An entry
 * under several of them is counted for the first one in the user's order.
 */
export function selectEntries(
  vault: Vault,
  chosen: string[],
): Map<string, { entry: VaultEntry; group: string }> {
  const selected = new Map<string, { entry: VaultEntry; group: string }>();
  for (const name of chosen) {
    const group =
      vault.groups.find((g) => g.path.toLowerCase() === name.toLowerCase())
        ?.path ?? name;
    for (const entry of vault.entries) {
      if (!selected.has(entry.id) && inGroup(entry.groupPath, name)) {
        selected.set(entry.id, { entry, group });
      }
    }
  }
  return selected;
}

const emptySummary = (): SyncSummary => ({
  created: 0,
  updated: 0,
  unchanged: 0,
  removed: 0,
  skipped: 0,
});

export function lockedError(database: Database): SyncError {
  return new SyncError(
    `${database.databasePath} is locked. Unlock it with its master password in the KeePass tab`,
    "locked",
  );
}

export function createSyncer(deps: {
  ctx: PluginContext;
  repo: Repository;
  unlocks: Unlocks;
}) {
  const { ctx, repo, unlocks } = deps;
  const coreFor = (userId: string): Promise<CoreCredentials> =>
    coreCredentialsFor(ctx, userId);
  const running = new Set<number>();

  /** The database's master password, remembered or typed since the last restart. */
  async function unlock(database: Database): Promise<StoredUnlock> {
    const stored = await unlocks.get(database);
    if (!stored) throw lockedError(database);
    return stored;
  }

  async function syncOnce(database: Database): Promise<SyncSummary> {
    const { userId } = database;
    const vault = await loadVault(ctx, database, await unlock(database));
    const selected = selectEntries(vault, database.groups);
    const summary = emptySummary();

    const imported = new Map(
      (await repo.listItems(userId, database.id)).map((item) => [
        item.entryId,
        item,
      ]),
    );
    // Only ask for a Termix session when something has to change.
    const needsCore =
      [...imported.keys()].some((id) => !selected.has(id)) ||
      [...selected.entries()].some(
        ([id, { entry }]) =>
          entry.password &&
          imported.get(id)?.contentHash !==
            hashInput(toCredentialInput(entry, database.passwordReferences)),
      );
    const core = needsCore ? await coreFor(userId) : null;

    try {
      for (const [id, { entry, group }] of selected) {
        if (!entry.password) {
          // Termix needs a password for a password credential.
          summary.skipped += 1;
          continue;
        }
        const input = toCredentialInput(entry, database.passwordReferences);
        const contentHash = hashInput(input);
        const previous = imported.get(id);
        if (previous && previous.contentHash === contentHash) {
          summary.unchanged += 1;
          continue;
        }
        let credentialId = previous?.credentialId;
        if (
          credentialId !== undefined &&
          (await core!.update(credentialId, input))
        ) {
          summary.updated += 1;
        } else {
          // New, or deleted in Termix since: make it again.
          credentialId = await core!.create(input);
          summary.created += 1;
        }
        await repo.saveItem(userId, {
          databaseId: database.id,
          entryId: id,
          credentialId,
          groupPath: group,
          title: input.name,
          contentHash,
        });
      }

      // Nothing from a chosen group the database no longer has is removed:
      // that is as likely to be a renamed group as a deleted one, and
      // unticking it in the tab removes its credentials on purpose.
      const present = vault.groups.map((g) => g.path);
      const chosenAndGone = (path: string) =>
        database.groups.some(
          (name) =>
            inGroup(path, name) && !present.some((p) => inGroup(p, name)),
        );
      for (const [id, item] of imported) {
        if (selected.has(id)) continue;
        if (chosenAndGone(item.groupPath)) continue;
        if (database.removeMissing) {
          await core!.remove(item.credentialId);
          summary.removed += 1;
        }
        await repo.deleteItem(userId, database.id, id);
      }
    } finally {
      await repo.persist();
    }

    await repo.updateDatabase(userId, database.id, {
      availableGroups: groupInfos(vault),
      lastSyncAt: new Date().toISOString(),
      lastStatus: "ok",
      lastError: null,
      lastSummary: summary,
    });
    return summary;
  }

  /**
   * Syncs one database. Must run as its user (a route, or inside
   * ctx.asUser). A failure is recorded on the database and thrown.
   */
  async function run(userId: string, databaseId: number): Promise<SyncSummary> {
    const database = await repo.getDatabase(userId, databaseId);
    if (!database) {
      throw new SyncError(
        "This KeePass database is not connected",
        "not_connected",
      );
    }
    if (running.has(databaseId)) {
      throw new SyncError("A sync is already running", "busy");
    }
    running.add(databaseId);
    try {
      return await syncOnce(database);
    } catch (error) {
      // Locked is a state the tab shows, not a failed sync.
      if (error instanceof SyncError && error.code === "locked") throw error;
      await repo
        .updateDatabase(userId, databaseId, {
          lastSyncAt: new Date().toISOString(),
          lastStatus: "error",
          lastError: error instanceof Error ? error.message : String(error),
        })
        .catch(() => undefined);
      throw error;
    } finally {
      running.delete(databaseId);
    }
  }

  return {
    unlock,
    coreFor,
    run,

    /** Whether the database can be opened without asking its user. */
    async isUnlocked(database: Database): Promise<boolean> {
      return (await unlocks.get(database)) !== null;
    },

    /**
     * Syncs every database of the user, one after another. One failing
     * database doesn't stop the others; each records its own result.
     * Locked databases are skipped and counted.
     */
    async runAll(userId: string): Promise<{
      ok: number;
      locked: number;
      failed: { id: number; error: unknown }[];
    }> {
      let ok = 0;
      let locked = 0;
      const failed: { id: number; error: unknown }[] = [];
      for (const database of await repo.listDatabases(userId)) {
        if (!database.groups.length) continue;
        if (!(await unlocks.get(database))) {
          locked += 1;
          continue;
        }
        try {
          await run(userId, database.id);
          ok += 1;
        } catch (error) {
          failed.push({ id: database.id, error });
        }
      }
      return { ok, locked, failed };
    },

    /** Lists the database's groups, without saving anything. */
    async groups(
      source: DatabaseSource,
      stored: StoredUnlock,
    ): Promise<GroupInfo[]> {
      return groupInfos(await loadVault(ctx, source, stored));
    },
  };
}

export type Syncer = ReturnType<typeof createSyncer>;
