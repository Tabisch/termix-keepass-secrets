import { normalizeId, type Vault } from "./keepass/database.js";
import type { Database, Repository } from "./repository.js";
import { SECRET_SCHEME, selectEntries, type DatabaseSource } from "./sync.js";
import type { StoredUnlock, Unlocks } from "./unlocks.js";

/**
 * Resolves "keepass://<uuid>/password" references, the way the Secret Sources
 * plugin resolves "op://...": Termix calls this when a host whose credential
 * holds one connects, for the user who owns the credential. The password is
 * read from that user's databases right then and never written anywhere.
 *
 * The reference names no database, so it keeps working when a database is
 * connected again. The database the entry was imported from is asked first,
 * then the user's other databases in the order they were connected.
 */

const REFERENCE = new RegExp(
  `^${SECRET_SCHEME}://\\{?([0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\}?/password/?$`,
  "i",
);

/**
 * How long one opened database answers. Connecting to several hosts at once
 * then costs one file read and one key derivation per database, and the
 * passwords live in memory only that long.
 */
const VAULT_TTL_MS = 30_000;

export class SecretReferenceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SecretReferenceError";
  }
}

export interface ResolverDeps {
  repo: Repository;
  unlocks: Pick<Unlocks, "get">;
  fetchVault: (source: DatabaseSource, unlock: StoredUnlock) => Promise<Vault>;
  now?: () => number;
}

export function createSecretResolver({
  repo,
  unlocks,
  fetchVault,
  now = Date.now,
}: ResolverDeps) {
  /** By database id. */
  const cache = new Map<
    number,
    {
      userId: string;
      expiresAt: number;
      passwords: Promise<Map<string, string>>;
    }
  >();

  /** The passwords of the entries in the database's chosen groups, by id. */
  async function loadPasswords(
    database: Database,
  ): Promise<Map<string, string>> {
    const stored = await unlocks.get(database);
    if (!stored) {
      throw new SecretReferenceError(
        `KeePass database ${database.databasePath} is locked since Termix restarted. Unlock it with its master password in the KeePass tab`,
      );
    }
    const vault = await fetchVault(database, stored);
    const passwords = new Map<string, string>();
    for (const [id, { entry }] of selectEntries(vault, database.groups)) {
      if (entry.password) passwords.set(id, entry.password);
    }
    return passwords;
  }

  function passwordsFor(database: Database): Promise<Map<string, string>> {
    const hit = cache.get(database.id);
    if (hit && hit.expiresAt > now()) return hit.passwords;
    const passwords = loadPasswords(database);
    cache.set(database.id, {
      userId: database.userId,
      expiresAt: now() + VAULT_TTL_MS,
      passwords,
    });
    // A failure is not remembered, so the next connect tries again.
    passwords.catch(() => {
      if (cache.get(database.id)?.passwords === passwords) {
        cache.delete(database.id);
      }
    });
    return passwords;
  }

  return {
    async resolve(userId: string, reference: string): Promise<string> {
      const match = REFERENCE.exec(reference.trim());
      if (!match) {
        throw new SecretReferenceError(
          `Not a KeePass reference. Use ${SECRET_SCHEME}://<entry UUID>/password`,
        );
      }
      const id = normalizeId(match[1]!);
      const all = await repo.listDatabases(userId);
      if (!all.length) {
        throw new SecretReferenceError(
          "KeePass is not connected for this user",
        );
      }
      const importedFrom = new Set(
        (await repo.listItems(userId))
          .filter((item) => item.entryId === id)
          .map((item) => item.databaseId),
      );
      const ordered = [
        ...all.filter((d) => importedFrom.has(d.id)),
        ...all.filter((d) => !importedFrom.has(d.id)),
      ];

      let lastError: unknown = null;
      for (const database of ordered) {
        try {
          const password = (await passwordsFor(database)).get(id);
          if (password) return password;
        } catch (error) {
          // Another database may still have it. If none does, the one that
          // couldn't be read (locked, file gone) may, so say why.
          lastError = error;
        }
      }
      if (lastError) {
        throw lastError instanceof Error
          ? lastError
          : new SecretReferenceError(String(lastError));
      }
      throw new SecretReferenceError(
        `KeePass entry ${id} is not in a group you import, or has no password`,
      );
    },

    /** Drops what is held for a user, or for one of their databases. */
    forget(userId: string, databaseId?: number): void {
      for (const [key, value] of cache) {
        if (
          value.userId === userId &&
          (databaseId === undefined || key === databaseId)
        ) {
          cache.delete(key);
        }
      }
    },
  };
}

export type SecretResolver = ReturnType<typeof createSecretResolver>;
