import type { Request, Response, Router } from "express";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import { DatabaseOpenError } from "./keepass/database.js";
import {
  DatabaseFileError,
  listFolder,
  normalizeRelativePath,
} from "./keepass/files.js";
import type { Repository } from "./repository.js";
import type { SecretResolver } from "./resolver.js";
import {
  credentialIdTag,
  databaseRoot,
  SyncError,
  UNLOCK_SECRET,
  type StoredUnlock,
  type Syncer,
} from "./sync.js";

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
    const connection = await repo.getConnection(userId);
    const interval =
      (await ctx.settings.get<number>("syncIntervalMinutes")) ?? 60;
    if (!connection) {
      return { connected: false, syncIntervalMinutes: interval };
    }
    const items = await repo.listItems(userId);
    return {
      connected: true,
      syncIntervalMinutes: interval,
      databasePath: connection.databasePath,
      keyFilePath: connection.keyFilePath,
      keyFileUploaded: connection.keyFileUploaded,
      groups: connection.groups,
      availableGroups: connection.availableGroups,
      removeMissing: connection.removeMissing,
      passwordReferences: connection.passwordReferences,
      lastSyncAt: connection.lastSyncAt,
      lastStatus: connection.lastStatus,
      lastError: connection.lastError,
      lastSummary: connection.lastSummary,
      items: items
        .map(({ title, groupPath, credentialId, entryId, updatedAt }) => ({
          title,
          group: groupPath,
          credentialId,
          tag: credentialIdTag(entryId),
          updatedAt,
        }))
        .sort((a, b) => (a.title ?? "").localeCompare(b.title ?? "")),
    };
  }

  /**
   * @openapi
   * /plugin-api/keepass-secrets/status:
   *   get:
   *     summary: The signed-in user's KeePass database, chosen groups and imported credentials
   *     tags:
   *       - KeePass
   *     responses:
   *       200:
   *         description: Whether a database is connected, and if so what is synced and how the last sync went. Each imported credential lists its stable keepass:<uuid> tag
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
   * /plugin-api/keepass-secrets/connect:
   *   post:
   *     summary: Connect a KeePass database
   *     description: Opens the database to check the password, then stores the password (and an uploaded key file) encrypted for the signed-in user. Neither is ever sent back.
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
   *         description: Missing or invalid fields, or a path outside the KeePass folder
   *       404:
   *         description: The file is not in the KeePass folder
   *       422:
   *         description: The password or key file is wrong, or the file is not a KeePass database
   *       503:
   *         description: The KeePass folder is not set or does not exist on the server
   */
  router.post("/connect", async (req: Request, res: Response) => {
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
      const availableGroups = await syncer.groups(source, stored);
      const userId = actor();
      const previous = await repo.getConnection(userId);
      await ctx.secrets.set(UNLOCK_SECRET, JSON.stringify(stored));
      resolver.forget(userId);
      await repo.saveConnection(userId, {
        ...source,
        keyFileUploaded: Boolean(stored.keyFile),
        availableGroups,
        // Another database's groups mean nothing here.
        ...(previous && previous.databasePath !== source.databasePath
          ? { groups: [] }
          : {}),
      });
      ctx.log.info(`keepass connected for user ${userId}`);
      res.json(await status(userId));
    } catch (error) {
      return sendFailure(res, error);
    }
  });

  /**
   * @openapi
   * /plugin-api/keepass-secrets/config:
   *   put:
   *     summary: Choose which KeePass groups to import
   *     tags:
   *       - KeePass
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
   *         description: KeePass is not connected
   */
  router.put("/config", async (req: Request, res: Response) => {
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
    if (!(await repo.getConnection(userId))) {
      return res
        .status(404)
        .json({ error: "KeePass is not connected", code: "not_connected" });
    }
    const unique = [
      ...new Set((groups as string[]).map((name) => name.trim())),
    ];
    await repo.saveConnection(userId, {
      groups: unique,
      ...(removeMissing !== undefined ? { removeMissing } : {}),
      ...(passwordReferences !== undefined ? { passwordReferences } : {}),
    });
    // References resolve against the chosen groups, so drop what the
    // resolver holds for the old ones.
    resolver.forget(userId);
    res.json(await status(userId));
  });

  /**
   * @openapi
   * /plugin-api/keepass-secrets/groups/refresh:
   *   post:
   *     summary: Read the database's groups again
   *     tags:
   *       - KeePass
   *     responses:
   *       200:
   *         description: The new status, with the database's current groups
   *       404:
   *         description: KeePass is not connected, or the file is gone
   *       422:
   *         description: The stored password no longer opens the database
   */
  router.post("/groups/refresh", async (_req: Request, res: Response) => {
    const userId = actor();
    try {
      const connection = await repo.getConnection(userId);
      if (!connection) {
        throw new SyncError("KeePass is not connected", "not_connected");
      }
      const availableGroups = await syncer.groups(
        connection,
        await syncer.unlock(),
      );
      await repo.saveConnection(userId, { availableGroups });
      res.json(await status(userId));
    } catch (error) {
      return sendFailure(res, error);
    }
  });

  /**
   * @openapi
   * /plugin-api/keepass-secrets/sync:
   *   post:
   *     summary: Sync the chosen groups into Termix credentials now
   *     tags:
   *       - KeePass
   *     responses:
   *       200:
   *         description: Synced. The body is the new status, with what changed in lastSummary
   *       404:
   *         description: KeePass is not connected, or the file is gone
   *       409:
   *         description: A sync is already running
   *       422:
   *         description: The stored password no longer opens the database
   *       502:
   *         description: Termix refused part of the sync. lastError has the reason
   */
  router.post("/sync", async (_req: Request, res: Response) => {
    const userId = actor();
    try {
      await syncer.run(userId);
      res.json(await status(userId));
    } catch (error) {
      return sendFailure(res, error);
    }
  });

  /**
   * @openapi
   * /plugin-api/keepass-secrets/connect:
   *   delete:
   *     summary: Disconnect the KeePass database and forget its password
   *     tags:
   *       - KeePass
   *     parameters:
   *       - in: query
   *         name: removeCredentials
   *         schema:
   *           type: boolean
   *         description: Also delete the credentials this plugin imported
   *     responses:
   *       200:
   *         description: Disconnected
   *       502:
   *         description: An imported credential could not be deleted. Nothing was disconnected
   */
  router.delete("/connect", async (req: Request, res: Response) => {
    const userId = actor();
    if (req.query.removeCredentials === "true") {
      const items = await repo.listItems(userId);
      if (items.length) {
        try {
          const core = await syncer.coreFor(userId);
          for (const item of items) await core.remove(item.credentialId);
        } catch (error) {
          return sendFailure(res, error);
        }
      }
    }
    await ctx.secrets.delete(UNLOCK_SECRET);
    await repo.deleteConnection(userId);
    resolver.forget(userId);
    ctx.log.info(`keepass disconnected for user ${userId}`);
    res.json({ connected: false });
  });
}
