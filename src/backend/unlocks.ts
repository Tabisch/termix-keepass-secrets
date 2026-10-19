import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";

/**
 * Where a database's master password (and an uploaded key file) is kept.
 *
 * Remembered: in ctx.secrets under unlockSecret(id), encrypted with the
 * installation key, so scheduled syncs work while nobody is signed in.
 *
 * Not remembered: only in this plugin's memory. Nothing is written to disk,
 * so a restart of Termix, or a disable and enable of the plugin, locks the
 * database until its user types the password again.
 */

/** What is kept per database: JSON in ctx.secrets, or the object in memory. */
export interface StoredUnlock {
  password: string;
  /** An uploaded key file, base64. */
  keyFile?: string;
}

/** The ctx.secrets key holding a remembered master password. */
export function unlockSecret(databaseId: number): string {
  return `unlock-${databaseId}`;
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

/** Whether an admin lets people store master passwords on the server. */
export async function rememberingAllowed(ctx: PluginContext): Promise<boolean> {
  return (await ctx.settings.get<boolean>("allowRememberPassword")) !== false;
}

export interface UnlockTarget {
  id: number;
  userId: string;
  rememberPassword: boolean;
}

export function createUnlocks(ctx: PluginContext) {
  // Made inside activate, so a disable and enable starts empty too.
  const memory = new Map<number, StoredUnlock>();
  /** Stored passwords deleted since an admin forbade them, once each. */
  const purged = new Set<number>();

  /** Runs fn as the database's user, without an audit line when already them. */
  const asOwner = <T>(userId: string, fn: () => Promise<T>): Promise<T> =>
    ctx.currentActor() === userId ? fn() : ctx.asUser(userId, fn);

  /** Remembered and still allowed by the admin. */
  const remembered = async (database: UnlockTarget) =>
    database.rememberPassword && (await rememberingAllowed(ctx));

  return {
    /** The password to open the database with, or null while it is locked. */
    async get(database: UnlockTarget): Promise<StoredUnlock | null> {
      if (database.rememberPassword) {
        if (await rememberingAllowed(ctx)) {
          const stored = parseUnlock(
            await asOwner(database.userId, () =>
              ctx.secrets.get(unlockSecret(database.id)),
            ),
          );
          if (stored) return stored;
        } else if (!purged.has(database.id)) {
          // An admin turned remembering off since: don't keep it on disk.
          await asOwner(database.userId, () =>
            ctx.secrets.delete(unlockSecret(database.id)),
          );
          purged.add(database.id);
        }
      }
      return memory.get(database.id) ?? null;
    },

    /** Keeps the password where the database says. Must run as its user. */
    async save(database: UnlockTarget, stored: StoredUnlock): Promise<void> {
      if (await remembered(database)) {
        await ctx.secrets.set(
          unlockSecret(database.id),
          JSON.stringify(stored),
        );
        memory.delete(database.id);
      } else {
        // Switching remembering off, or an admin forbidding it, leaves
        // nothing behind on disk.
        await ctx.secrets.delete(unlockSecret(database.id));
        memory.set(database.id, stored);
      }
    },

    /** Locks a database that isn't remembered. */
    lock(databaseId: number): void {
      memory.delete(databaseId);
    },

    /** Forgets the password wherever it is. Must run as the database's user. */
    async remove(databaseId: number): Promise<void> {
      memory.delete(databaseId);
      await ctx.secrets.delete(unlockSecret(databaseId));
    },
  };
}

export type Unlocks = ReturnType<typeof createUnlocks>;
