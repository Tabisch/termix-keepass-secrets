import {
  defineTable,
  id,
  integer,
  json,
  refUser,
  text,
  timestamp,
  varchar,
} from "@termix-ssh/plugin-sdk/db";

/**
 * One row per user who connected a KeePass database. The master password
 * (and an uploaded key file) is not here: it lives in ctx.secrets, encrypted
 * with the installation key, so a scheduled sync can read it while the user
 * is signed out.
 */
export const connections = defineTable("connections", {
  id: id(),
  userId: refUser().notNull().unique(),
  /** The .kdbx file, relative to the admin's KeePass folder. */
  databasePath: text().notNull(),
  /** A key file in the KeePass folder, relative to it. */
  keyFilePath: text(),
  /** Whether a key file was uploaded instead; its bytes are in ctx.secrets. */
  keyFileUploaded: integer().notNull().default(0),
  /** Group paths to import, as the user picked them. */
  chosenGroups: json().notNull(),
  /** Every group seen in the database on the last read, for the picker. */
  availableGroups: json(),
  /** Delete credentials this plugin made when their entry leaves the groups. */
  removeMissing: integer().notNull().default(1),
  /**
   * Write "keepass://<uuid>/password" references into credentials instead of
   * the passwords, resolved from the database when a host connects.
   */
  passwordReferences: integer().notNull().default(1),
  lastSyncAt: timestamp(),
  /** "ok" or "error". */
  lastStatus: varchar(16),
  lastError: text(),
  /** Counts from the last run: created, updated, removed, skipped. */
  lastSummary: json(),
  createdAt: timestamp().notNull().defaultNow(),
});

/**
 * Which Termix credential a KeePass entry was imported as. contentHash is a
 * hash of what was last written, so an unchanged entry is not written again.
 */
export const items = defineTable(
  "items",
  {
    id: id(),
    userId: refUser().notNull(),
    entryId: varchar(64).notNull(),
    credentialId: integer().notNull(),
    /** The chosen group the entry was imported through. */
    groupPath: text().notNull(),
    title: text(),
    contentHash: varchar(64).notNull(),
    updatedAt: timestamp().notNull().defaultNow(),
  },
  {
    indexes: [
      { name: "idx_p_keepass_secrets_items_user_id", columns: ["userId"] },
    ],
    uniques: [
      {
        name: "uq_p_keepass_secrets_items_user_entry",
        columns: ["userId", "entryId"],
      },
    ],
  },
);

// termix-plugin migrations reads this list.
export const tables = [connections, items];
