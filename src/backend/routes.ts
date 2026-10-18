import type { Request, Response, Router } from "express";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import { DatabaseOpenError } from "./keepass/database.js";
import {
  DatabaseFileError,
  listFolder,
  normalizeRelativePath,
} from "./keepass/files.js";
import type { Database, Repository } from "./repository.js";
import type { SecretResolver } from "./resolver.js";
import {
  credentialIdTag,
  databaseRoot,
  SyncError,
  unlockSecret,
  type StoredUnlock,
  type Syncer,
} from "./sync.js";

const MAX_DATABASES = 50;
const MAX_GROUPS = 200;
const MAX_NAME_LENGTH = 1024;
const MAX_PASSWORD_LENGTH = 10_000;
/** Key files are small; KeePass' own are under 1 KB. */
const MAX_KEY_FILE_BYTES = 64 * 1024;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Answers a failed file, database or sync call without spending the error budget. */
function sendFailure(res: Response, error: unknown) {
  if (error instanceof SyncError) {
    const status = error.code === "not_connected" ? 404 : 409;
    return res.status(status).json({ error: error.message, code: error.code });
  }
  if (error instanceof DatabaseFileError) {
    const status =
      error.code === "no_root" ? 503 : error.code === "not_found" ? 404 : 400;
    return res.status(status).json({ error: error.message, code: error.code });
  }
  if (error instanceof DatabaseOpenError) {
    return res.status(422).json({ error: error.message, code: error.code });
  }
  return res.status(502).json({ error: errorMessage(error) });
}

function optionalPath(value: unknown): string | null | undefined {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value !== "string" || value.length > MAX_NAME_LENGTH) {
    return undefined;
  }
  return value;
}

/** The :id route parameter, or null when it isn't one. */
function databaseIdOf(req: Request): number | null {
  const id = Number((req.params as Record<string, string>).id);
  return Number.isSafeInteger(id) && id > 0 ? id : null;
}

const notConnected = (res: Response) =>
  res.status(404).json({
    error: "This KeePass database is not connected",
    code: "not_connected",
  });

export function registerRoutes(
  router: Router,
  ctx: PluginContext,
  repo: Repository,
  syncer: Syncer,
  resolver: Pick<SecretResolver, "forget">,
): void {
  router.use(ctx.rbac.require("use") as never);

  const actor = () => ctx.currentActor() as string;

  async function status(userId: string) {
    const interval =
      (await ctx.settings.get<number>("syncIntervalMinutes")) ?? 60;
    const items = await repo.listItems(userId);
    const databases = (await repo.listDatabases(userId)).map(
      (database: Database) => ({
        id: database.id,
        databasePath: database.databasePath,
        keyFilePath: database.keyFilePath,
        keyFileUploaded: database.keyFileUploaded,
        groups: database.groups,
        availableGroups: database.availableGroups,
        removeMissing: database.removeMissing,
        passwordReferences: database.passwordReferences,
        lastSyncAt: database.lastSyncAt,
        lastStatus: database.lastStatus,
        lastError: database.lastError,
        lastSummary: database.lastSummary,
        items: items
          .filter((item) => item.databaseId === database.id)
          .map(({ title, groupPath, credentialId, entryId, updatedAt }) => ({
            title,
            group: groupPath,
            credentialId,
            tag: credentialIdTag(entryId),
            updatedAt,
          }))
          .sort((a, b) => (a.title ?? "").localeCompare(b.title ?? "")),
      }),
    );
    return { syncIntervalMinutes: interval, databases };
  }

  /**
   * @openapi
   * /plugin-api/keepass-secrets/status:
   *   get:
   *     summary: The signed-in user's KeePass databases, their chosen groups and imported credentials
   *     tags:
   *       - KeePass
   *     responses:
   *       200:
   *         description: Every database the user connected, what is synced from it and how its last sync went. Each imported credential lists its stable keepass:<uuid> tag
   */
  router.get("/status", async (_req: Request, res: Response) => {
    res.json(await status(actor()));
  });

  /**
   * @openapi
   * /plugin-api/keepass-secrets/files:
   *   get:
   *     summary: The KeePass databases and key files in the folder an admin set
   *     tags:
   *       - KeePass
   *     responses:
   *       200:
   *         description: Paths relative to the KeePass folder. truncated is true when the folder had more than was listed
   *       503:
   *         description: The KeePass folder is not set or does not exist on the server
   */
  router.get("/files", async (_req: Request, res: Response) => {
    try {
      res.json(await listFolder(await databaseRoot(ctx)));
    } catch (error) {
      return sendFailure(res, error);
    }
  });

  /**
   * @openapi
   * /plugin-api/keepass-secrets/databases:
   *   post:
   *     summary: Connect a KeePass database, or connect one again with a new password
   *     description: Opens the database to check the password, then stores the password (and an uploaded key file) encrypted for the signed-in user. Neither is ever sent back. A path the user already connected keeps its chosen groups and gets the new password.
   *     tags:
   *       - KeePass
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               databasePath:
   *                 type: string
   *                 description: The .kdbx file, relative to the KeePass folder
   *               password:
   *                 type: string
   *                 description: The master password. May be empty when a key file opens the database alone
   *               keyFilePath:
   *                 type: string
   *                 description: A key file in the KeePass folder, relative to it
   *               keyFile:
   *                 type: string
   *                 description: An uploaded key file, base64. Ignored when keyFilePath is set
   *     responses:
   *       200:
   *         description: Connected. The body is the new status, with the database's groups
   *       400:
   *         description: Missing or invalid fields, a path outside the KeePass folder, or too many databases
   *       404:
   *         description: The file is not in the KeePass folder
   *       422:
   *         description: The password or key file is wrong, or the file is not a KeePass database
   *       503:
   *         description: The KeePass folder is not set or does not exist on the server
   */
  router.post("/databases", async (req: Request, res: Response) => {
    const body = req.body ?? {};
    const password = typeof body.password === "string" ? body.password : "";
    const keyFilePath = optionalPath(body.keyFilePath);
    const keyFile =
      typeof body.keyFile === "string" && body.keyFile ? body.keyFile : null;
    if (
      typeof body.databasePath !== "string" ||
      !body.databasePath.trim() ||
      body.databasePath.length > MAX_NAME_LENGTH
    ) {
      return res
        .status(400)
        .json({ error: "databasePath is required", code: "invalid_path" });
    }
    if (keyFilePath === undefined) {
      return res
        .status(400)
        .json({ error: "keyFilePath must be a path", code: "invalid_path" });
    }
    if (password.length > MAX_PASSWORD_LENGTH) {
      return res.status(400).json({ error: "password is too long" });
    }
    if (
      keyFile &&
      (keyFile.length > (MAX_KEY_FILE_BYTES * 4) / 3 + 4 ||
        !/^[A-Za-z0-9+/]+={0,2}$/.test(keyFile))
    ) {
      return res
        .status(400)
        .json({ error: "keyFile must be a base64 file of at most 64 KB" });
    }
    if (!password && !keyFilePath && !keyFile) {
      return res.status(400).json({
        error: "Give the master password, a key file or both",
        code: "invalid_key",
      });
    }

    try {
      const source = {
        databasePath: normalizeRelativePath(body.databasePath),
        keyFilePath: keyFilePath ? normalizeRelativePath(keyFilePath) : null,
      };
      const stored: StoredUnlock = {
        password,
        ...(keyFile && !source.keyFilePath ? { keyFile } : {}),
      };
      const userId = actor();
      const previous = await repo.findDatabaseByPath(
        userId,
        source.databasePath,
      );
      if (
        !previous &&
        (await repo.listDatabases(userId)).length >= MAX_DATABASES
      ) {
        return res.status(400).json({
          error: `You can connect at most ${MAX_DATABASES} databases`,
          code: "too_many",
        });
      }
      const availableGroups = await syncer.groups(source, stored);
      const values = {
        ...source,
        keyFileUploaded: Boolean(stored.keyFile),
        availableGroups,
      };
      let id: number;
      if (previous) {
        id = previous.id;
        await repo.updateDatabase(userId, id, values);
      } else {
        id = await repo.createDatabase(userId, values);
      }
      await ctx.secrets.set(unlockSecret(id), JSON.stringify(stored));
      resolver.forget(userId, id);
      ctx.log.info(`keepass database ${id} connected for user ${userId}`);
      res.json(await status(userId));
    } catch (error) {
      return sendFailure(res, error);
    }
  });

  /**
   * @openapi
   * /plugin-api/keepass-secrets/databases/{id}/config:
   *   put:
   *     summary: Choose which groups of a KeePass database to import
   *     tags:
   *       - KeePass
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: integer
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               groups:
   *                 type: array
   *                 description: Group paths like "Passwords/Servers". A group brings the groups under it
   *                 items:
   *                   type: string
   *               removeMissing:
   *                 type: boolean
   *                 description: Delete credentials this plugin made when their entry leaves the chosen groups
   *               passwordReferences:
   *                 type: boolean
   *                 description: Write keepass://<uuid>/password references into credentials instead of passwords, resolved from the database when a host connects. The next sync rewrites the credentials
   *     responses:
   *       200:
   *         description: Saved. The body is the new status
   *       400:
   *         description: Invalid groups
   *       404:
   *         description: The user has no database with this id
   */
  router.put("/databases/:id/config", async (req: Request, res: Response) => {
    const id = databaseIdOf(req);
    const { groups, removeMissing, passwordReferences } = req.body ?? {};
    if (
      !Array.isArray(groups) ||
      groups.length > MAX_GROUPS ||
      groups.some(
        (name) =>
          typeof name !== "string" ||
          !name.trim() ||
          name.length > MAX_NAME_LENGTH,
      )
    ) {
      return res.status(400).json({ error: "groups must be a list of paths" });
    }
    if (removeMissing !== undefined && typeof removeMissing !== "boolean") {
      return res
        .status(400)
        .json({ error: "removeMissing must be true or false" });
    }
    if (
      passwordReferences !== undefined &&
      typeof passwordReferences !== "boolean"
    ) {
      return res
        .status(400)
        .json({ error: "passwordReferences must be true or false" });
    }
    const userId = actor();
    if (id === null || !(await repo.getDatabase(userId, id))) {
      return notConnected(res);
    }
    const unique = [
      ...new Set((groups as string[]).map((name) => name.trim())),
    ];
    await repo.updateDatabase(userId, id, {
      groups: unique,
      ...(removeMissing !== undefined ? { removeMissing } : {}),
      ...(passwordReferences !== undefined ? { passwordReferences } : {}),
    });
    // References resolve against the chosen groups, so drop what the
    // resolver holds for the old ones.
    resolver.forget(userId, id);
    res.json(await status(userId));
  });

  /**
   * @openapi
   * /plugin-api/keepass-secrets/databases/{id}/groups/refresh:
   *   post:
   *     summary: Read a database's groups again
   *     tags:
   *       - KeePass
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: integer
   *     responses:
   *       200:
   *         description: The new status, with the database's current groups
   *       404:
   *         description: The user has no database with this id, or the file is gone
   *       422:
   *         description: The stored password no longer opens the database
   */
  router.post(
    "/databases/:id/groups/refresh",
    async (req: Request, res: Response) => {
      const id = databaseIdOf(req);
      const userId = actor();
      const database = id === null ? null : await repo.getDatabase(userId, id);
      if (!database) return notConnected(res);
      try {
        const availableGroups = await syncer.groups(
          database,
          await syncer.unlock(database.id),
        );
        await repo.updateDatabase(userId, database.id, { availableGroups });
        res.json(await status(userId));
      } catch (error) {
        return sendFailure(res, error);
      }
    },
  );

  /**
   * @openapi
   * /plugin-api/keepass-secrets/databases/{id}/sync:
   *   post:
   *     summary: Sync one database's chosen groups into Termix credentials now
   *     tags:
   *       - KeePass
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: integer
   *     responses:
   *       200:
   *         description: Synced. The body is the new status, with what changed in the database's lastSummary
   *       404:
   *         description: The user has no database with this id, or the file is gone
   *       409:
   *         description: A sync of this database is already running
   *       422:
   *         description: The stored password no longer opens the database
   *       502:
   *         description: Termix refused part of the sync. lastError has the reason
   */
  router.post("/databases/:id/sync", async (req: Request, res: Response) => {
    const id = databaseIdOf(req);
    if (id === null) return notConnected(res);
    const userId = actor();
    try {
      await syncer.run(userId, id);
      res.json(await status(userId));
    } catch (error) {
      return sendFailure(res, error);
    }
  });

  /**
   * @openapi
   * /plugin-api/keepass-secrets/sync:
   *   post:
   *     summary: Sync every database of the signed-in user now
   *     description: Databases with no groups chosen are skipped. One database failing doesn't stop the others; each records its own result in lastStatus and lastError.
   *     tags:
   *       - KeePass
   *     responses:
   *       200:
   *         description: The new status. failed counts the databases whose sync failed
   */
  router.post("/sync", async (_req: Request, res: Response) => {
    const userId = actor();
    const { failed } = await syncer.runAll(userId);
    res.json({ ...(await status(userId)), failed: failed.length });
  });

  /**
   * @openapi
   * /plugin-api/keepass-secrets/databases/{id}:
   *   delete:
   *     summary: Disconnect a KeePass database and forget its password
   *     tags:
   *       - KeePass
   *     parameters:
   *       - in: path
   *         name: id
   *         required: true
   *         schema:
   *           type: integer
   *       - in: query
   *         name: removeCredentials
   *         schema:
   *           type: boolean
   *         description: Also delete the credentials this plugin imported from it
   *     responses:
   *       200:
   *         description: Disconnected. The body is the new status
   *       404:
   *         description: The user has no database with this id
   *       502:
   *         description: An imported credential could not be deleted. Nothing was disconnected
   */
  router.delete("/databases/:id", async (req: Request, res: Response) => {
    const id = databaseIdOf(req);
    const userId = actor();
    if (id === null || !(await repo.getDatabase(userId, id))) {
      return notConnected(res);
    }
    if (req.query.removeCredentials === "true") {
      const items = await repo.listItems(userId, id);
      if (items.length) {
        try {
          const core = await syncer.coreFor(userId);
          for (const item of items) await core.remove(item.credentialId);
        } catch (error) {
          return sendFailure(res, error);
        }
      }
    }
    await ctx.secrets.delete(unlockSecret(id));
    await repo.deleteDatabase(userId, id);
    resolver.forget(userId, id);
    ctx.log.info(`keepass database ${id} disconnected for user ${userId}`);
    res.json(await status(userId));
  });
}
