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

export interface Connection {
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

export interface ImportedItem {
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

function toConnection(row: Record<string, unknown>): Connection {
  return {
    userId: String(row.userId),
    databasePath: String(row.databasePath),
    keyFilePath: (row.keyFilePath as string | null) ?? null,
    keyFileUploaded: Boolean(Number(row.keyFileUploaded)),
    groups: fromJson<string[]>(row.chosenGroups, []),
    availableGroups: fromJson<GroupInfo[]>(row.availableGroups, []),
    removeMissing: Boolean(Number(row.removeMissing)),
    passwordReferences: Boolean(Number(row.passwordReferences)),
    lastSyncAt: (row.lastSyncAt as string | null) ?? null,
    lastStatus: (row.lastStatus as Connection["lastStatus"]) ?? null,
    lastError: (row.lastError as string | null) ?? null,
    lastSummary: fromJson<SyncSummary | null>(row.lastSummary, null),
  };
}

export function createRepository(
  ctx: PluginContext,
  connections: Table,
  items: Table,
) {
  const client = () => ctx.db.client<BetterSQLite3Database>();

  return {
    async getConnection(userId: string): Promise<Connection | null> {
      const db = await client();
      const rows = await db
        .select()
        .from(connections)
        .where(eq(connections.userId, userId));
      return rows[0] ? toConnection(rows[0]) : null;
    },

    async listConnections(): Promise<Connection[]> {
      const db = await client();
      const rows = await db.select().from(connections);
      return rows.map(toConnection);
    },

    async saveConnection(
      userId: string,
      values: Partial<Omit<Connection, "userId">>,
    ): Promise<void> {
      const db = await client();
      const row: Record<string, unknown> = {};
      if (values.databasePath !== undefined) {
        row.databasePath = values.databasePath;
      }
      if (values.keyFilePath !== undefined) {
        row.keyFilePath = values.keyFilePath;
      }
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
        row.lastSummary =
          values.lastSummary && JSON.stringify(values.lastSummary);
      }

      const existing = await db
        .select({ id: connections.id })
        .from(connections)
        .where(eq(connections.userId, userId));
      if (existing.length) {
        await db
          .update(connections)
          .set(row)
          .where(eq(connections.userId, userId));
      } else {
        await db.insert(connections).values({
          userId,
          databasePath: "",
          keyFileUploaded: 0,
          chosenGroups: "[]",
          removeMissing: 1,
          passwordReferences: 1,
          ...row,
        });
      }
      await ctx.db.persist();
    },

    async deleteConnection(userId: string): Promise<void> {
      const db = await client();
      await db.delete(items).where(eq(items.userId, userId));
      await db.delete(connections).where(eq(connections.userId, userId));
      await ctx.db.persist();
    },

    async listItems(userId: string): Promise<ImportedItem[]> {
      const db = await client();
      const rows = await db
        .select()
        .from(items)
        .where(eq(items.userId, userId));
      return rows.map((row: Record<string, unknown>) => ({
        entryId: String(row.entryId),
        credentialId: Number(row.credentialId),
        groupPath: String(row.groupPath),
        title: (row.title as string | null) ?? null,
        contentHash: String(row.contentHash),
        updatedAt: String(row.updatedAt),
      }));
    },

    async saveItem(userId: string, item: Omit<ImportedItem, "updatedAt">) {
      const db = await client();
      const now = new Date().toISOString();
      const where = and(
        eq(items.userId, userId),
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

    async deleteItem(userId: string, entryId: string) {
      const db = await client();
      await db
        .delete(items)
        .where(and(eq(items.userId, userId), eq(items.entryId, entryId)));
    },

    persist: () => ctx.db.persist(),
  };
}

export type Repository = ReturnType<typeof createRepository>;
