import { and, eq } from "drizzle-orm";
import type { BetterSQLite3Database } from "drizzle-orm/better-sqlite3";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";

// The table objects ctx.db.define hands back. Drizzle's own types are per
// dialect, so the queries treat them loosely.
type Table = any;

export interface SyncSummary {
  created: number;
  updated: number;
  unchanged: number;
  removed: number;
  skipped: number;
}

export interface GroupInfo {
  path: string;
  entries: number;
}

export interface Database {
  id: number;
  userId: string;
  databasePath: string;
  keyFilePath: string | null;
  keyFileUploaded: boolean;
  groups: string[];
  availableGroups: GroupInfo[];
  removeMissing: boolean;
  /** Credentials hold keepass:// references, not passwords. */
  passwordReferences: boolean;
  lastSyncAt: string | null;
  lastStatus: "ok" | "error" | null;
  lastError: string | null;
  lastSummary: SyncSummary | null;
}

export type DatabaseValues = Partial<Omit<Database, "id" | "userId">>;

export interface ImportedItem {
  databaseId: number;
  entryId: string;
  credentialId: number;
  groupPath: string;
  title: string | null;
  contentHash: string;
  updatedAt: string;
}

/** json() columns hold text. Writes stringify; reads accept either, to be safe. */
function fromJson<T>(value: unknown, fallback: T): T {
  if (value == null) return fallback;
  if (typeof value === "string") {
    try {
      return JSON.parse(value) as T;
    } catch {
      return fallback;
    }
  }
  return value as T;
}

function toDatabase(row: Record<string, unknown>): Database {
  return {
    id: Number(row.id),
    userId: String(row.userId),
    databasePath: String(row.databasePath),
    keyFilePath: (row.keyFilePath as string | null) ?? null,
    keyFileUploaded: Boolean(Number(row.keyFileUploaded)),
    groups: fromJson<string[]>(row.chosenGroups, []),
    availableGroups: fromJson<GroupInfo[]>(row.availableGroups, []),
    removeMissing: Boolean(Number(row.removeMissing)),
    passwordReferences: Boolean(Number(row.passwordReferences)),
    lastSyncAt: (row.lastSyncAt as string | null) ?? null,
    lastStatus: (row.lastStatus as Database["lastStatus"]) ?? null,
    lastError: (row.lastError as string | null) ?? null,
    lastSummary: fromJson<SyncSummary | null>(row.lastSummary, null),
  };
}

function toRow(values: DatabaseValues): Record<string, unknown> {
  const row: Record<string, unknown> = {};
  if (values.databasePath !== undefined) {
    row.databasePath = values.databasePath;
  }
  if (values.keyFilePath !== undefined) row.keyFilePath = values.keyFilePath;
  if (values.keyFileUploaded !== undefined) {
    row.keyFileUploaded = values.keyFileUploaded ? 1 : 0;
  }
  if (values.groups !== undefined) {
    row.chosenGroups = JSON.stringify(values.groups);
  }
  if (values.availableGroups !== undefined) {
    row.availableGroups = JSON.stringify(values.availableGroups);
  }
  if (values.removeMissing !== undefined) {
    row.removeMissing = values.removeMissing ? 1 : 0;
  }
  if (values.passwordReferences !== undefined) {
    row.passwordReferences = values.passwordReferences ? 1 : 0;
  }
  if (values.lastSyncAt !== undefined) row.lastSyncAt = values.lastSyncAt;
  if (values.lastStatus !== undefined) row.lastStatus = values.lastStatus;
  if (values.lastError !== undefined) row.lastError = values.lastError;
  if (values.lastSummary !== undefined) {
    row.lastSummary = values.lastSummary && JSON.stringify(values.lastSummary);
  }
  return row;
}

export function createRepository(
  ctx: PluginContext,
  databases: Table,
  items: Table,
) {
  const client = () => ctx.db.client<BetterSQLite3Database>();
  const byId = (userId: string, id: number) =>
    and(eq(databases.userId, userId), eq(databases.id, id));

  async function listDatabases(userId: string): Promise<Database[]> {
    const db = await client();
    const rows = await db
      .select()
      .from(databases)
      .where(eq(databases.userId, userId));
    return rows.map(toDatabase).sort((a, b) => a.id - b.id);
  }

  return {
    listDatabases,

    async getDatabase(userId: string, id: number): Promise<Database | null> {
      const db = await client();
      const rows = await db.select().from(databases).where(byId(userId, id));
      return rows[0] ? toDatabase(rows[0]) : null;
    },

    async findDatabaseByPath(
      userId: string,
      databasePath: string,
    ): Promise<Database | null> {
      return (
        (await listDatabases(userId)).find(
          (d) => d.databasePath === databasePath,
        ) ?? null
      );
    },

    /** Every user's databases, for the scheduler. */
    async listAllDatabases(): Promise<Database[]> {
      const db = await client();
      const rows = await db.select().from(databases);
      return rows.map(toDatabase);
    },

    /** Adds a database and returns its id. The path must be new for the user. */
    async createDatabase(
      userId: string,
      values: DatabaseValues & { databasePath: string },
    ): Promise<number> {
      const db = await client();
      await db.insert(databases).values({
        userId,
        keyFileUploaded: 0,
        chosenGroups: "[]",
        removeMissing: 1,
        passwordReferences: 1,
        ...toRow(values),
      });
      await ctx.db.persist();
      // No .returning() on MySQL, so read it back by the path, which is
      // unique per user.
      const rows = await db
        .select({ id: databases.id, databasePath: databases.databasePath })
        .from(databases)
        .where(eq(databases.userId, userId));
      const row = rows.find(
        (r: { databasePath: string }) => r.databasePath === values.databasePath,
      );
      return Number(row.id);
    },

    async updateDatabase(
      userId: string,
      id: number,
      values: DatabaseValues,
    ): Promise<void> {
      const row = toRow(values);
      if (!Object.keys(row).length) return;
      const db = await client();
      await db.update(databases).set(row).where(byId(userId, id));
      await ctx.db.persist();
    },

    async deleteDatabase(userId: string, id: number): Promise<void> {
      const db = await client();
      await db
        .delete(items)
        .where(and(eq(items.userId, userId), eq(items.databaseId, id)));
      await db.delete(databases).where(byId(userId, id));
      await ctx.db.persist();
    },

    /** The user's imported items, of one database or of all of them. */
    async listItems(
      userId: string,
      databaseId?: number,
    ): Promise<ImportedItem[]> {
      const db = await client();
      const rows = await db
        .select()
        .from(items)
        .where(
          databaseId === undefined
            ? eq(items.userId, userId)
            : and(eq(items.userId, userId), eq(items.databaseId, databaseId)),
        );
      return rows.map((row: Record<string, unknown>) => ({
        databaseId: Number(row.databaseId),
        entryId: String(row.entryId),
        credentialId: Number(row.credentialId),
        groupPath: String(row.groupPath),
        title: (row.title as string | null) ?? null,
        contentHash: String(row.contentHash),
        updatedAt: String(row.updatedAt),
      }));
    },

    async saveItem(
      userId: string,
      item: Omit<ImportedItem, "updatedAt">,
    ): Promise<void> {
      const db = await client();
      const now = new Date().toISOString();
      const where = and(
        eq(items.userId, userId),
        eq(items.databaseId, item.databaseId),
        eq(items.entryId, item.entryId),
      );
      const existing = await db
        .select({ id: items.id })
        .from(items)
        .where(where);
      if (existing.length) {
        await db
          .update(items)
          .set({
            credentialId: item.credentialId,
            groupPath: item.groupPath,
            title: item.title,
            contentHash: item.contentHash,
            updatedAt: now,
          })
          .where(where);
      } else {
        await db.insert(items).values({ userId, ...item, updatedAt: now });
      }
    },

    async deleteItem(userId: string, databaseId: number, entryId: string) {
      const db = await client();
      await db
        .delete(items)
        .where(
          and(
            eq(items.userId, userId),
            eq(items.databaseId, databaseId),
            eq(items.entryId, entryId),
          ),
        );
    },

    persist: () => ctx.db.persist(),
  };
}

export type Repository = ReturnType<typeof createRepository>;
