import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import kdbxweb from "kdbxweb";
import type { KdbxGroup } from "kdbxweb";
import type { PluginFetchInit } from "@termix-ssh/plugin-sdk/backend";
import { openDatabase } from "../../src/backend/keepass/database.js";

/**
 * Builds real .kdbx files with kdbxweb, so the plugin's own decryption and
 * parsing run in tests.
 */

export const MASTER_PASSWORD = "correct horse battery staple";
export const ROOT_GROUP = "Passwords";

export interface FakeEntry {
  /** 32 hex digits. */
  id: string;
  /** Under the root group, like "Servers/Linux". Empty for the root itself. */
  group: string;
  title?: string;
  username?: string;
  password?: string;
  url?: string;
}

export interface DatabaseSpec {
  entries: FakeEntry[];
  /** Extra empty groups. */
  groups?: string[];
  password?: string;
  keyFile?: Uint8Array | null;
  /** Entries to put in the recycle bin. */
  recycled?: FakeEntry[];
  version?: 3 | 4;
}

let argonSet = false;

export async function buildDatabase(spec: DatabaseSpec): Promise<Buffer> {
  if (!argonSet) {
    // Opening once installs the plugin's Argon2, which saving needs too.
    await openDatabase(Buffer.alloc(0), { password: "x" }).catch(() => {});
    argonSet = true;
  }
  const credentials = new kdbxweb.Credentials(
    spec.password === ""
      ? null
      : kdbxweb.ProtectedValue.fromString(spec.password ?? MASTER_PASSWORD),
    spec.keyFile ?? null,
  );
  await credentials.ready;
  const db = kdbxweb.Kdbx.create(credentials, ROOT_GROUP);
  if (spec.version === 3) {
    db.setVersion(3);
  } else {
    // Light Argon2 settings, so tests are quick.
    db.header.kdfParameters!.set(
      "M",
      kdbxweb.VarDictionary.ValueType.UInt64,
      kdbxweb.Int64.from(1024 * 64),
    );
    db.header.kdfParameters!.set(
      "I",
      kdbxweb.VarDictionary.ValueType.UInt64,
      kdbxweb.Int64.from(1),
    );
  }
  const root = db.getDefaultGroup();
  const groups = new Map<string, KdbxGroup>([["", root]]);
  const groupAt = (groupPath: string): KdbxGroup => {
    const existing = groups.get(groupPath);
    if (existing) return existing;
    const slash = groupPath.lastIndexOf("/");
    const parent = groupAt(slash < 0 ? "" : groupPath.slice(0, slash));
    const group = db.createGroup(parent, groupPath.slice(slash + 1));
    groups.set(groupPath, group);
    return group;
  };
  for (const name of spec.groups ?? []) groupAt(name);

  const add = (entry: FakeEntry, parent: KdbxGroup) => {
    const created = db.createEntry(parent);
    created.uuid = new kdbxweb.KdbxUuid(
      new Uint8Array(Buffer.from(entry.id, "hex")).buffer,
    );
    created.fields.set("Title", entry.title ?? "");
    created.fields.set("UserName", entry.username ?? "");
    created.fields.set(
      "Password",
      kdbxweb.ProtectedValue.fromString(entry.password ?? ""),
    );
    created.fields.set("URL", entry.url ?? "");
  };
  for (const entry of spec.entries) add(entry, groupAt(entry.group));
  if (spec.recycled?.length) {
    db.createRecycleBin();
    const bin = db.getGroup(db.meta.recycleBinUuid!)!;
    for (const entry of spec.recycled) add(entry, bin);
  }
  return Buffer.from(await db.save());
}

/** A fresh folder that plays the mounted share. */
export function makeRoot(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), "keepass-root-"));
}

export function writeFile(root: string, relative: string, data: Uint8Array) {
  const full = path.join(root, relative);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, data);
}

interface StoredCredential {
  id: number;
  userId: string;
  name: string;
  description: string;
  folder: string;
  tags: string[];
  username: string;
  password: string;
  authType: string;
}

/** Fakes Termix core's /credentials routes, which the plugin calls through ctx.fetch. */
export function createFakeCore() {
  const credentials = new Map<number, StoredCredential>();
  const requests: Array<{ url: string; init?: PluginFetchInit }> = [];
  let nextId = 1;
  let coreFailure: { method: string; status: number } | null = null;
  let tokenOwner: (token: string) => string | undefined = () => undefined;

  const json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });

  function core(url: URL, init?: PluginFetchInit): Response {
    const method = init?.method ?? "GET";
    const bearer = (init?.headers?.authorization ?? "").replace(/^Bearer /, "");
    const userId = tokenOwner(bearer);
    if (!userId) return json(401, { error: "Missing authentication token" });
    if (coreFailure && coreFailure.method === method) {
      return json(coreFailure.status, { error: "refused" });
    }
    const body = init?.body ? JSON.parse(init.body) : {};
    const match = url.pathname.match(/^\/credentials(?:\/(\d+))?$/);
    if (!match) return json(404, { error: "not found" });
    const id = match[1] ? Number(match[1]) : null;
    if (method === "POST" && id === null) {
      if (!body.name || (body.authType === "password" && !body.password)) {
        return json(400, { error: "Password is required" });
      }
      const created = { id: nextId++, userId, ...body };
      credentials.set(created.id, created);
      return json(201, { id: created.id, name: created.name });
    }
    const existing = id !== null ? credentials.get(id) : undefined;
    if (!existing || existing.userId !== userId) {
      return json(404, { error: "Credential not found" });
    }
    if (method === "PUT") {
      Object.assign(existing, body);
      return json(200, { id: existing.id });
    }
    if (method === "DELETE") {
      credentials.delete(existing.id);
      return json(200, { message: "Credential deleted successfully" });
    }
    return json(405, { error: "method" });
  }

  const fetch = async (
    url: string,
    init?: PluginFetchInit,
  ): Promise<Response> => {
    requests.push({ url, init });
    const parsed = new URL(url);
    if (parsed.hostname === "127.0.0.1" && parsed.port === "30001") {
      if (!init?.allowPrivateHosts?.includes("127.0.0.1")) {
        throw new Error("blocked private address");
      }
      return core(parsed, init);
    }
    throw new Error(`unexpected fetch ${url}`);
  };

  return {
    fetch,
    credentials,
    requests,
    /** Says which user a token minted by ctx.auth.issueUserToken acts as. */
    resolveTokens(resolve: (token: string) => string | undefined) {
      tokenOwner = resolve;
    },
    failCore(failure: typeof coreFailure) {
      coreFailure = failure;
    },
    credentialsOf(userId: string) {
      return [...credentials.values()].filter((c) => c.userId === userId);
    },
  };
}

export type FakeCore = ReturnType<typeof createFakeCore>;
