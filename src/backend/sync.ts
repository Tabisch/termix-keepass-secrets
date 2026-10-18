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
import type { GroupInfo, Repository, SyncSummary } from "./repository.js";

/** The ctx.secrets key holding the acting user's master password. */
export const UNLOCK_SECRET = "unlock";

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
    readonly code: "not_connected" | "busy",
  ) {
    super(message);
    this.name = "SyncError";
  }
}

/** What ctx.secrets holds per user, as JSON. */
export interface StoredUnlock {
  password: string;
  /** An uploaded key file, base64. */
  keyFile?: string;
}

export function parseUnlock(raw: string | null): StoredUnlock | null {
  if (!raw) return null;
  try {
    const value = JSON.parse(raw) as StoredUnlock;
    return typeof value?.password === "string" ? value : null;
  } catch {
    return null;
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

export function createSyncer(deps: { ctx: PluginContext; repo: Repository }) {
  const { ctx, repo } = deps;
  const coreFor = (userId: string): Promise<CoreCredentials> =>
    coreCredentialsFor(ctx, userId);
  const running = new Set<string>();

  /** Reads the acting user's master password. Must run as that user. */
  async function unlock(): Promise<StoredUnlock> {
    const stored = parseUnlock(await ctx.secrets.get(UNLOCK_SECRET));
    if (!stored) {
      throw new SyncError("KeePass is not connected", "not_connected");
    }
    return stored;
  }

  async function syncOnce(userId: string): Promise<SyncSummary> {
    const connection = await repo.getConnection(userId);
    if (!connection) {
      throw new SyncError("KeePass is not connected", "not_connected");
    }
    const vault = await loadVault(ctx, connection, await unlock());
    const selected = selectEntries(vault, connection.groups);
    const summary: SyncSummary = {
      created: 0,
      updated: 0,
      unchanged: 0,
      removed: 0,
      skipped: 0,
    };

    const imported = new Map(
      (await repo.listItems(userId)).map((item) => [item.entryId, item]),
    );
    // Only ask for a Termix session when something has to change.
    const needsCore =
      [...imported.keys()].some((id) => !selected.has(id)) ||
      [...selected.entries()].some(
        ([id, { entry }]) =>
          entry.password &&
          imported.get(id)?.contentHash !==
            hashInput(toCredentialInput(entry, connection.passwordReferences)),
      );
    const core = needsCore ? await coreFor(userId) : null;

    try {
      for (const [id, { entry, group }] of selected) {
        if (!entry.password) {
          // Termix needs a password for a password credential.
          summary.skipped += 1;
          continue;
        }
        const input = toCredentialInput(entry, connection.passwordReferences);
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
        connection.groups.some(
          (name) =>
            inGroup(path, name) && !present.some((p) => inGroup(p, name)),
        );
      for (const [id, item] of imported) {
        if (selected.has(id)) continue;
        if (chosenAndGone(item.groupPath)) continue;
        if (connection.removeMissing) {
          await core!.remove(item.credentialId);
          summary.removed += 1;
        }
        await repo.deleteItem(userId, id);
      }
    } finally {
      await repo.persist();
    }

    await repo.saveConnection(userId, {
      availableGroups: groupInfos(vault),
      lastSyncAt: new Date().toISOString(),
      lastStatus: "ok",
      lastError: null,
      lastSummary: summary,
    });
    return summary;
  }

  return {
    unlock,
    coreFor,

    /** Syncs one user. Must run as that user (a route, or inside ctx.asUser). */
    async run(userId: string): Promise<SyncSummary> {
      if (running.has(userId)) {
        throw new SyncError("A sync is already running", "busy");
      }
      running.add(userId);
      try {
        return await syncOnce(userId);
      } catch (error) {
        if (!(error instanceof SyncError && error.code === "not_connected")) {
          await repo
            .saveConnection(userId, {
              lastSyncAt: new Date().toISOString(),
              lastStatus: "error",
              lastError: error instanceof Error ? error.message : String(error),
            })
            .catch(() => undefined);
        }
        throw error;
      } finally {
        running.delete(userId);
      }
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
