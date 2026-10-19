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
  type Syncer,
} from "./sync.js";
import {
  rememberingAllowed,
  type StoredUnlock,
  type Unlocks,
} from "./unlocks.js";

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
    const status =
      error.code === "not_connected"
        ? 404
        : error.code === "locked"
          ? 423
          : 409;
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

/**
 * The password and uploaded key file in a connect or unlock body, or the
 * answer to send when they are not valid.
 */
function readSecrets(
  body: Record<string, unknown>,
): { password: string; keyFile: string | null } | { error: string } {
  const password = typeof body.password === "string" ? body.password : "";
  const keyFile =
    typeof body.keyFile === "string" && body.keyFile ? body.keyFile : null;
  if (password.length > MAX_PASSWORD_LENGTH) {
    return { error: "password is too long" };
  }
  if (
    keyFile &&
    (keyFile.length > (MAX_KEY_FILE_BYTES * 4) / 3 + 4 ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(keyFile))
  ) {
    return { error: "keyFile must be a base64 file of at most 64 KB" };
  }
  return { password, keyFile };
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
  unlocks: Unlocks,
  resolver: Pick<SecretResolver, "forget">,
): void {
  router.use(ctx.rbac.require("use") as never);

  const actor = () => ctx.currentActor() as string;

  async function status(userId: string) {
    const interval =
      (await ctx.settings.get<number>("syncIntervalMinutes")) ?? 60;
    const allowRememberPassword = await rememberingAllowed(ctx);
    const items = await repo.listItems(userId);
    const rows = await repo.listDatabases(userId);
    const unlocked = await Promise.all(rows.map((d) => syncer.isUnlocked(d)));
    const databases = rows.map((database: Database, index: number) => ({
      id: database.id,
      databasePath: database.databasePath,
      keyFilePath: database.keyFilePath,
      keyFileUploaded: database.keyFileUploaded,
      rememberPassword: database.rememberPassword && allowRememberPassword,
      locked: !unlocked[index],
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
    }));
    return {
      syncIntervalMinutes: interval,
      allowRememberPassword,
      databases,
    };
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
   *     description: Opens the database to check the password, then keeps the password (and an uploaded key file) for the signed-in user, encrypted on the server or, with rememberPassword false, only in memory. Neither is ever sent back. A path the user already connected keeps its chosen groups and gets the new password.
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
   *               rememberPassword:
   *                 type: boolean
   *                 description: Store the master password (and an uploaded key file) encrypted on the server, so scheduled syncs work after a restart. Defaults to true. False, or an admin forbidding it, keeps them in memory only, so the database locks on every restart
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
    const keyFilePath = optionalPath(body.keyFilePath);
    const secrets = readSecrets(body);
    if ("error" in secrets) return res.status(400).json(secrets);
    const { password, keyFile } = secrets;
    if (
      body.rememberPassword !== undefined &&
      typeof body.rememberPassword !== "boolean"
    ) {
      return res
        .status(400)
        .json({ error: "rememberPassword must be true or false" });
    }
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
        // An admin can forbid storing passwords for everyone.
        rememberPassword:
          body.rememberPassword !== false && (await rememberingAllowed(ctx)),
        availableGroups,
      };
      let id: number;
      if (previous) {
        id = previous.id;
        await repo.updateDatabase(userId, id, values);
      } else {
        id = await repo.createDatabase(userId, values);
      }
      await unlocks.save({ id, userId, ...values }, stored);
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
   *               rememberPassword:
   *                 type: boolean
   *                 description: Store the master password encrypted on the server. Off, it is kept in memory only, deleted from the server, and asked for again after every restart
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
    const { groups, removeMissing, passwordReferences, rememberPassword } =
      req.body ?? {};
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
    if (
      rememberPassword !== undefined &&
      typeof rememberPassword !== "boolean"
    ) {
      return res
        .status(400)
        .json({ error: "rememberPassword must be true or false" });
    }
    const userId = actor();
    const database = id === null ? null : await repo.getDatabase(userId, id);
    if (!database) return notConnected(res);
    if (
      rememberPassword !== undefined &&
      rememberPassword !== database.rememberPassword
    ) {
      // Move the password it is unlocked with to its new place. A locked
      // database just changes the setting and keeps waiting for it.
      const current = await unlocks.get(database);
      const next = {
        ...database,
        rememberPassword: rememberPassword && (await rememberingAllowed(ctx)),
      };
      await repo.updateDatabase(userId, database.id, {
        rememberPassword: next.rememberPassword,
      });
      if (current) await unlocks.save(next, current);
      else await unlocks.remove(database.id);
    }
    const unique = [
      ...new Set((groups as string[]).map((name) => name.trim())),
    ];
    await repo.updateDatabase(userId, database.id, {
      groups: unique,
      ...(removeMissing !== undefined ? { removeMissing } : {}),
      ...(passwordReferences !== undefined ? { passwordReferences } : {}),
    });
    // References resolve against the chosen groups, so drop what the
    // resolver holds for the old ones.
    resolver.forget(userId, database.id);
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
          await syncer.unlock(database),
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
   * /plugin-api/keepass-secrets/databases/{id}/unlock:
   *   post:
   *     summary: Unlock a database whose master password is not remembered
   *     description: Opens the database to check the password, then keeps it in memory until Termix restarts (or on the server, for a database set to remember it). Needed after every restart for databases that don't remember their password.
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
   *               password:
   *                 type: string
   *               keyFile:
   *                 type: string
   *                 description: The uploaded key file again, base64, for a database connected with one
   *     responses:
   *       200:
   *         description: Unlocked. The body is the new status
   *       400:
   *         description: Missing password or key file
   *       404:
   *         description: The user has no database with this id, or the file is gone
   *       422:
   *         description: The password or key file is wrong
   */
  router.post("/databases/:id/unlock", async (req: Request, res: Response) => {
    const id = databaseIdOf(req);
    const userId = actor();
    const database = id === null ? null : await repo.getDatabase(userId, id);
    if (!database) return notConnected(res);
    const secrets = readSecrets(req.body ?? {});
    if ("error" in secrets) return res.status(400).json(secrets);
    if (database.keyFileUploaded && !secrets.keyFile) {
      return res.status(400).json({
        error:
          "This database was connected with an uploaded key file. Upload it again",
        code: "invalid_key",
      });
    }
    if (!secrets.password && !database.keyFilePath && !secrets.keyFile) {
      return res
        .status(400)
        .json({ error: "Give the master password", code: "invalid_key" });
    }
    const stored: StoredUnlock = {
      password: secrets.password,
      ...(database.keyFileUploaded && secrets.keyFile
        ? { keyFile: secrets.keyFile }
        : {}),
    };
    try {
      const availableGroups = await syncer.groups(database, stored);
      await unlocks.save(database, stored);
      await repo.updateDatabase(userId, database.id, { availableGroups });
      resolver.forget(userId, database.id);
      ctx.log.info(
        `keepass database ${database.id} unlocked for user ${userId}`,
      );
      res.json(await status(userId));
    } catch (error) {
      return sendFailure(res, error);
    }
  });

  /**
   * @openapi
   * /plugin-api/keepass-secrets/databases/{id}/lock:
   *   post:
   *     summary: Forget the master password of a database that doesn't remember it, now
   *     description: The database stays connected and locked until it is unlocked again. A database that remembers its password is not changed.
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
   *         description: Locked. The body is the new status
   *       404:
   *         description: The user has no database with this id
   */
  router.post("/databases/:id/lock", async (req: Request, res: Response) => {
    const id = databaseIdOf(req);
    const userId = actor();
    const database = id === null ? null : await repo.getDatabase(userId, id);
    if (!database) return notConnected(res);
    unlocks.lock(database.id);
    resolver.forget(userId, database.id);
    res.json(await status(userId));
  });

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
   *     description: Databases with no groups chosen, and locked ones, are skipped. One database failing doesn't stop the others; each records its own result in lastStatus and lastError.
   *     tags:
   *       - KeePass
   *     responses:
   *       200:
   *         description: The new status. failed counts the databases whose sync failed, locked the ones skipped because they wait for their master password
   */
  router.post("/sync", async (_req: Request, res: Response) => {
    const userId = actor();
    const { failed, locked } = await syncer.runAll(userId);
    res.json({ ...(await status(userId)), failed: failed.length, locked });
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
    await unlocks.remove(id);
    await repo.deleteDatabase(userId, id);
    resolver.forget(userId, id);
    ctx.log.info(`keepass database ${id} disconnected for user ${userId}`);
    res.json(await status(userId));
  });
}
