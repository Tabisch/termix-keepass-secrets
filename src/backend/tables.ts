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
 * One row per KeePass database a user connected; a user can connect many.
 * The master password (and an uploaded key file) is not here: when
 * remembered it lives in ctx.secrets under unlockSecret(id), encrypted with
 * the installation key, so a scheduled sync can read it while the user is
 * signed out. Otherwise it is only ever in memory (see unlocks.ts).
 */
export const databases = defineTable(
  "databases",
  {
    id: id(),
    userId: refUser().notNull(),
    /**
     * The .kdbx file, relative to the admin's KeePass folder. One row per
     * path and user, which the repository keeps: a unique index on a path
     * this long is too wide for MySQL.
     */
    databasePath: text().notNull(),
    /** A key file in the KeePass folder, relative to it. */
    keyFilePath: text(),
    /** Whether a key file was uploaded instead; kept like the password. */
    keyFileUploaded: integer().notNull().default(0),
    /**
     * Store the master password encrypted on the server. Off, it is kept in
     * memory only and has to be typed again after every restart.
     */
    rememberPassword: integer().notNull().default(1),
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
  },
  {
    indexes: [
      { name: "idx_p_keepass_secrets_databases_user_id", columns: ["userId"] },
    ],
  },
);

/**
 * Which Termix credential a KeePass entry was imported as. contentHash is a
 * hash of what was last written, so an unchanged entry is not written again.
 */
export const items = defineTable(
  "items",
  {
    id: id(),
    userId: refUser().notNull(),
    databaseId: integer().notNull(),
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
        // A copy of a database keeps its entries' UUIDs, so the same entry
        // can be imported once from each.
        name: "uq_p_keepass_secrets_items_database_entry",
        columns: ["userId", "databaseId", "entryId"],
      },
    ],
  },
);

// termix-plugin migrations reads this list.
export const tables = [databases, items];
