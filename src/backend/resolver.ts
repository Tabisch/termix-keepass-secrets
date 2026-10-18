import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import { normalizeId, type Vault } from "./keepass/database.js";
import type { Repository } from "./repository.js";
import {
  parseUnlock,
  SECRET_SCHEME,
  selectEntries,
  UNLOCK_SECRET,
  type DatabaseSource,
  type StoredUnlock,
} from "./sync.js";

/**
 * Resolves "keepass://<uuid>/password" references, the way the Secret Sources
 * plugin resolves "op://...": Termix calls this when a host whose credential
 * holds one connects, for the user who owns the credential. The password is
 * read from that user's database right then and never written anywhere.
 */

const REFERENCE = new RegExp(
  `^${SECRET_SCHEME}://\\{?([0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\\}?/password/?$`,
  "i",
);

/**
 * How long one opened database answers. Connecting to several hosts at once
 * then costs one file read and one key derivation, and the passwords live in
 * memory only that long.
 */
const VAULT_TTL_MS = 30_000;

export class SecretReferenceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SecretReferenceError";
  }
}

export interface ResolverDeps {
  ctx: PluginContext;
  repo: Repository;
  fetchVault: (source: DatabaseSource, unlock: StoredUnlock) => Promise<Vault>;
  now?: () => number;
}

export function createSecretResolver({
  ctx,
  repo,
  fetchVault,
  now = Date.now,
}: ResolverDeps) {
  const cache = new Map<
    string,
    { expiresAt: number; passwords: Promise<Map<string, string>> }
  >();

  /** The passwords of the entries in the user's chosen groups, by id. */
  async function loadPasswords(userId: string): Promise<Map<string, string>> {
    const connection = await repo.getConnection(userId);
    if (!connection) {
      throw new SecretReferenceError("KeePass is not connected for this user");
    }
    const stored = parseUnlock(
      await ctx.asUser(userId, () => ctx.secrets.get(UNLOCK_SECRET)),
    );
    if (!stored) {
      throw new SecretReferenceError("KeePass is not connected for this user");
    }
    const vault = await fetchVault(connection, stored);
    const passwords = new Map<string, string>();
    for (const [id, { entry }] of selectEntries(vault, connection.groups)) {
      if (entry.password) passwords.set(id, entry.password);
    }
    return passwords;
  }

  function passwordsFor(userId: string): Promise<Map<string, string>> {
    const hit = cache.get(userId);
    if (hit && hit.expiresAt > now()) return hit.passwords;
    const passwords = loadPasswords(userId);
    cache.set(userId, { expiresAt: now() + VAULT_TTL_MS, passwords });
    // A failure is not remembered, so the next connect tries again.
    passwords.catch(() => {
      if (cache.get(userId)?.passwords === passwords) cache.delete(userId);
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
      const password = (await passwordsFor(userId)).get(id);
      if (!password) {
        throw new SecretReferenceError(
          `KeePass entry ${id} is not in a group you import, or has no password`,
        );
      }
      return password;
    },

    /** Drops what is held for a user, like when they disconnect. */
    forget(userId: string): void {
      cache.delete(userId);
    },
  };
}

export type SecretResolver = ReturnType<typeof createSecretResolver>;
