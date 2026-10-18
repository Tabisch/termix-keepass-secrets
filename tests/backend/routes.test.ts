import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import express, { type Router } from "express";
import kdbxweb from "kdbxweb";
import {
  createMockCtx,
  createTestDb,
  type MockPluginContext,
  type TestDb,
} from "@termix-ssh/plugin-sdk/testing";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";
import manifestJson from "../../manifest.json";
import { activate } from "../../src/backend/index.js";
import {
  MASTER_PASSWORD,
  buildDatabase,
  createFakeCore,
  makeRoot,
  writeFile,
  type DatabaseSpec,
  type FakeCore,
  type FakeEntry,
} from "./fixtures.js";

const pluginDir = fileURLToPath(new URL("../..", import.meta.url));
const manifest = manifestJson as unknown as PluginManifest;

const WEB = "11111111AAAA4AAA8AAA111111111111";
const DB = "22222222BBBB4BBB8BBB222222222222";
const MAIL = "33333333CCCC4CCC8CCC333333333333";
const NOPASS = "44444444DDDD4DDD8DDD444444444444";
const TRASH = "55555555EEEE4EEE8EEE555555555555";

const DB_FILE = "team/servers.kdbx";

let db: TestDb;
let mock: MockPluginContext;
let core: FakeCore;
let server: http.Server;
let port: number;
let root: string;
let actor = "user-1";
let entries: FakeEntry[];
/** The id of the database connectAndChoose connected. */
let dbId: number;

function seedEntries() {
  entries = [
    {
      id: WEB,
      group: "Servers/Linux",
      title: "web-1",
      username: "deploy",
      password: "pw-web",
      url: "https://web-1.example.com",
    },
    {
      id: DB,
      group: "Servers",
      title: "db-1",
      username: "dba",
      password: "pw-db",
    },
    {
      id: MAIL,
      group: "Personal",
      title: "mail",
      username: "me",
      password: "pw-mail",
    },
    { id: NOPASS, group: "Servers", title: "sso-only", username: "me" },
  ];
}

async function writeDatabase(spec: Partial<DatabaseSpec> = {}) {
  writeFile(
    root,
    DB_FILE,
    await buildDatabase({
      entries,
      groups: ["Empty"],
      recycled: [{ id: TRASH, group: "", title: "old", password: "pw-old" }],
      ...spec,
    }),
  );
}

async function start(permissions: string[] = ["keepass-secrets.use"]) {
  db = await createTestDb(pluginDir);
  for (const id of ["user-1", "user-2"]) {
    db.sqlite
      .prepare("INSERT INTO users (id, username) VALUES (?, ?)")
      .run(id, id);
  }
  root = makeRoot();
  seedEntries();
  await writeDatabase();
  core = createFakeCore();

  let router: Router | null = null;
  mock = createMockCtx({
    pluginId: manifest.id,
    manifest,
    capabilities: manifest.capabilities,
    db: db.database,
    router: () => (router = express.Router()),
    permissions,
    fetch: core.fetch,
  });
  core.resolveTokens((token) => {
    const index = Number(token.replace("fake-token-", "")) - 1;
    return mock.auth.userTokens[index]?.userId;
  });
  await mock.ctx.settings.set("databaseRoot", root);
  await activate(mock.ctx);

  const app = express();
  app.use(express.json());
  app.use((_req, _res, next) => {
    mock.setActor(actor);
    next();
  });
  app.use((req, res, next) => router!(req, res, next));
  server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, resolve));
  port = (server.address() as AddressInfo).port;
}

beforeEach(() => {
  actor = "user-1";
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  db.close();
  fs.rmSync(root, { recursive: true, force: true });
});

async function request(method: string, path: string, body?: unknown) {
  const response = await fetch(`http://127.0.0.1:${port}${path}`, {
    method,
    headers: body ? { "content-type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  return { status: response.status, body: await response.json() };
}

/** Connects a database, and remembers its id for db1() when it worked. */
async function connect(extra: Record<string, unknown> = {}) {
  const body = { databasePath: DB_FILE, password: MASTER_PASSWORD, ...extra };
  const res = await request("POST", "/databases", body);
  if (res.status === 200) {
    const path = String(body.databasePath).replace(/\\/g, "/");
    dbId = byPath(res.body, path).id;
  }
  return res;
}

// Most tests check the stored passwords, so they turn references off.
async function connectAndChoose(
  groups: string[],
  removeMissing = true,
  passwordReferences = false,
) {
  const connected = await connect();
  expect(connected.status).toBe(200);
  const config = await request("PUT", `/databases/${dbId}/config`, {
    groups,
    removeMissing,
    passwordReferences,
  });
  expect(config.status).toBe(200);
  return byPath(config.body, DB_FILE);
}

/** One database from a status body. */
function byPath(body: { databases: { databasePath: string }[] }, path: string) {
  return body.databases.find((d) => d.databasePath === path) as any;
}

/** The connected database's part of the status. */
async function current() {
  return byPath((await request("GET", "/status")).body, DB_FILE);
}

/** The connected database's own routes. */
const db1 = (suffix = "") => `/databases/${dbId}${suffix}`;

/** Syncs the connected database and returns its part of the status. */
async function sync() {
  const res = await request("POST", db1("/sync"));
  return {
    status: res.status,
    body: res.status === 200 ? byPath(res.body, DB_FILE) : res.body,
  };
}

// By name, so the order the database lists entries in doesn't matter.
const stored = () =>
  core
    .credentialsOf("user-1")
    .map(({ id: _id, userId: _u, ...rest }) => rest)
    .sort((a, b) => a.name.localeCompare(b.name));

describe("the KeePass folder", () => {
  beforeEach(() => start());

  it("lists databases and key files under it", async () => {
    writeFile(root, "keys/team.keyx", Buffer.from("key"));
    writeFile(root, "notes.txt", Buffer.from("no"));
    writeFile(root, ".hidden/secret.kdbx", Buffer.from("no"));
    const res = await request("GET", "/files");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      databases: [DB_FILE],
      keyFiles: ["keys/team.keyx"],
      truncated: false,
    });
  });

  it("says when an admin has not set a folder that exists", async () => {
    await mock.ctx.settings.set("databaseRoot", path.join(root, "nope"));
    const res = await request("GET", "/files");
    expect(res.status).toBe(503);
    expect(res.body.code).toBe("no_root");
    await mock.ctx.settings.set("databaseRoot", "relative/path");
    expect((await connect()).body.code).toBe("no_root");
  });

  it("never opens a file outside it", async () => {
    const outside = makeRoot();
    try {
      writeFile(outside, "x.kdbx", await buildDatabase({ entries }));
      expect((await connect({ databasePath: "../x.kdbx" })).body.code).toBe(
        "invalid_path",
      );
      fs.symlinkSync(
        path.join(outside, "x.kdbx"),
        path.join(root, "link.kdbx"),
      );
      const res = await connect({ databasePath: "link.kdbx" });
      expect(res.status).toBe(400);
      expect(res.body.code).toBe("outside_root");
      expect((await connect({ databasePath: "missing.kdbx" })).status).toBe(
        404,
      );
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
});

describe("connecting", () => {
  beforeEach(() => start());

  it("starts with no databases", async () => {
    expect((await request("GET", "/status")).body).toEqual({
      syncIntervalMinutes: 60,
      databases: [],
    });
  });

  it("opens the database, stores the password and lists the groups", async () => {
    const res = await connect();
    expect(res.status).toBe(200);
    expect(byPath(res.body, DB_FILE)).toMatchObject({
      databasePath: DB_FILE,
      keyFilePath: null,
      keyFileUploaded: false,
      groups: [],
      availableGroups: [
        { path: "Passwords", entries: 4 },
        { path: "Passwords/Empty", entries: 0 },
        { path: "Passwords/Personal", entries: 1 },
        { path: "Passwords/Servers", entries: 3 },
        { path: "Passwords/Servers/Linux", entries: 1 },
      ],
    });
    expect(JSON.stringify(res.body)).not.toContain(MASTER_PASSWORD);
    expect(JSON.parse((await mock.ctx.secrets.get(`unlock-${dbId}`))!)).toEqual(
      { password: MASTER_PASSWORD },
    );
  });

  it("accepts backslashes in the path", async () => {
    expect((await connect({ databasePath: "team\\servers.kdbx" })).status).toBe(
      200,
    );
  });

  it("reads KDBX 3.1 too", async () => {
    await writeDatabase({ version: 3 });
    expect((await connect()).status).toBe(200);
  });

  it("says when the password is wrong", async () => {
    const res = await connect({ password: "wrong" });
    expect(res.status).toBe(422);
    expect(res.body.code).toBe("wrong_key");
    expect((await request("GET", "/status")).body.databases).toEqual([]);
  });

  it("says when the file is not a KeePass database", async () => {
    writeFile(root, "fake.kdbx", Buffer.from("not a database"));
    const res = await connect({ databasePath: "fake.kdbx" });
    expect(res.status).toBe(422);
    expect(res.body.code).toBe("not_kdbx");
  });

  it("opens a database with a key file from the folder", async () => {
    const keyFile = await kdbxweb.Credentials.createRandomKeyFile(2);
    writeFile(root, "keys/team.keyx", keyFile);
    await writeDatabase({ keyFile });
    expect((await connect()).body.code).toBe("wrong_key");
    const res = await connect({ keyFilePath: "keys/team.keyx" });
    expect(res.status).toBe(200);
    expect(byPath(res.body, DB_FILE).keyFilePath).toBe("keys/team.keyx");
  });

  it("opens a database with an uploaded key file and no password", async () => {
    const keyFile = await kdbxweb.Credentials.createRandomKeyFile(2);
    await writeDatabase({ keyFile, password: "" });
    const res = await connect({
      password: "",
      keyFile: Buffer.from(keyFile).toString("base64"),
    });
    expect(res.status).toBe(200);
    expect(byPath(res.body, DB_FILE).keyFileUploaded).toBe(true);
    await request("PUT", db1("/config"), {
      groups: ["Passwords/Servers"],
      passwordReferences: false,
    });
    expect((await sync()).body.lastSummary.created).toBe(2);
  });

  it("validates what it is given", async () => {
    expect((await request("POST", "/databases", {})).status).toBe(400);
    expect((await connect({ password: "", keyFilePath: "" })).body.code).toBe(
      "invalid_key",
    );
    expect((await connect({ keyFile: "not base64!" })).status).toBe(400);
    expect((await connect({ keyFilePath: 7 })).status).toBe(400);
  });

  it("validates the group list", async () => {
    await connect();
    expect(
      (await request("PUT", db1("/config"), { groups: "Servers" })).status,
    ).toBe(400);
    expect(
      (await request("PUT", db1("/config"), { groups: [""] })).status,
    ).toBe(400);
    expect(
      (
        await request("PUT", db1("/config"), {
          groups: ["a"],
          removeMissing: "yes",
        })
      ).status,
    ).toBe(400);
  });

  it("answers 404 for a database that isn't connected", async () => {
    for (const path of ["/databases/999/config", "/databases/abc/config"]) {
      const res = await request("PUT", path, { groups: ["Passwords"] });
      expect(res.status).toBe(404);
    }
    expect((await request("POST", "/databases/999/sync")).status).toBe(404);
    expect(
      (await request("POST", "/databases/999/groups/refresh")).status,
    ).toBe(404);
    expect((await request("DELETE", "/databases/999")).status).toBe(404);
  });

  it("keeps the groups and takes the new password when a database is connected again", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    const first = dbId;
    await writeDatabase({ password: "a new one" });
    const res = await connect({ password: "a new one" });
    expect(res.body.databases).toHaveLength(1);
    expect(dbId).toBe(first);
    expect(byPath(res.body, DB_FILE).groups).toEqual(["Passwords/Servers"]);
    expect((await sync()).status).toBe(200);
  });

  it("keeps each user's databases to themselves", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    actor = "user-2";
    expect((await request("GET", "/status")).body.databases).toEqual([]);
    expect((await sync()).status).toBe(404);
    expect((await request("PUT", db1("/config"), { groups: [] })).status).toBe(
      404,
    );
    expect((await request("DELETE", db1())).status).toBe(404);
  });
});

describe("several databases", () => {
  beforeEach(() => start());

  const OPS = "ops/ops.kdbx";
  const OPS_ENTRY = "66666666FFFF4FFF8FFF666666666666";

  async function connectOps(password = "ops password") {
    writeFile(
      root,
      OPS,
      await buildDatabase({
        password,
        entries: [
          {
            id: OPS_ENTRY,
            group: "Network",
            title: "switch-1",
            username: "admin",
            password: "pw-switch",
          },
        ],
      }),
    );
    const res = await request("POST", "/databases", {
      databasePath: OPS,
      password,
    });
    expect(res.status).toBe(200);
    const ops = byPath(res.body, OPS);
    await request("PUT", `/databases/${ops.id}/config`, {
      groups: ["Passwords/Network"],
      passwordReferences: false,
    });
    return ops.id as number;
  }

  it("connects each with its own password and syncs each on its own", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    const opsId = await connectOps();
    expect(opsId).not.toBe(dbId);

    const status = (await request("GET", "/status")).body;
    expect(
      status.databases.map((d: { databasePath: string }) => d.databasePath),
    ).toEqual([DB_FILE, OPS]);
    expect(
      JSON.parse((await mock.ctx.secrets.get(`unlock-${opsId}`))!).password,
    ).toBe("ops password");

    await sync();
    expect(stored().map((c) => c.name)).toEqual(["db-1", "web-1"]);
    const res = await request("POST", `/databases/${opsId}/sync`);
    expect(byPath(res.body, OPS).lastSummary.created).toBe(1);
    expect(byPath(res.body, OPS).items).toEqual([
      expect.objectContaining({
        title: "switch-1",
        group: "Passwords/Network",
        tag: `keepass:${OPS_ENTRY}`,
      }),
    ]);
    expect(byPath(res.body, DB_FILE).items).toHaveLength(2);
    expect(stored().map((c) => c.name)).toEqual(["db-1", "switch-1", "web-1"]);
  });

  it("syncs them all at once, and one failing doesn't stop the others", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    const opsId = await connectOps();
    fs.rmSync(path.join(root, DB_FILE));
    const res = await request("POST", "/sync");
    expect(res.status).toBe(200);
    expect(res.body.failed).toBe(1);
    expect(byPath(res.body, DB_FILE).lastStatus).toBe("error");
    expect(byPath(res.body, OPS).lastStatus).toBe("ok");
    expect(stored().map((c) => c.name)).toEqual(["switch-1"]);
    expect(opsId).toBeGreaterThan(0);
  });

  it("removes only what one database left behind", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    await connectOps();
    await request("POST", "/sync");
    entries.splice(0, 1);
    await writeDatabase();
    expect((await sync()).body.lastSummary.removed).toBe(1);
    expect(stored().map((c) => c.name)).toEqual(["db-1", "switch-1"]);
  });

  it("imports an entry from two copies of a database once from each", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    fs.copyFileSync(path.join(root, DB_FILE), path.join(root, "copy.kdbx"));
    const res = await request("POST", "/databases", {
      databasePath: "copy.kdbx",
      password: MASTER_PASSWORD,
    });
    const copy = byPath(res.body, "copy.kdbx");
    await request("PUT", `/databases/${copy.id}/config`, {
      groups: ["Passwords/Servers"],
      passwordReferences: false,
    });
    await request("POST", "/sync");
    expect(stored().map((c) => c.name)).toEqual([
      "db-1",
      "db-1",
      "web-1",
      "web-1",
    ]);
  });

  it("disconnects one and leaves the others", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    const opsId = await connectOps();
    await request("POST", "/sync");
    const res = await request(
      "DELETE",
      `/databases/${opsId}?removeCredentials=true`,
    );
    expect(res.body.databases.map((d: { id: number }) => d.id)).toEqual([dbId]);
    expect(await mock.ctx.secrets.get(`unlock-${opsId}`)).toBeNull();
    expect(await mock.ctx.secrets.get(`unlock-${dbId}`)).not.toBeNull();
    expect(stored().map((c) => c.name)).toEqual(["db-1", "web-1"]);
  });

  it("resolves a reference from whichever database has the entry", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    await connectOps();
    const resolve = mock.auth.secretResolvers.get("keepass")!;
    expect(await resolve("user-1", `keepass://${OPS_ENTRY}/password`)).toBe(
      "pw-switch",
    );
    expect(await resolve("user-1", `keepass://${WEB}/password`)).toBe("pw-web");
  });

  it("still resolves from one database when another is broken", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    await connectOps();
    fs.rmSync(path.join(root, DB_FILE));
    const resolve = mock.auth.secretResolvers.get("keepass")!;
    expect(await resolve("user-1", `keepass://${OPS_ENTRY}/password`)).toBe(
      "pw-switch",
    );
  });
});

describe("syncing", () => {
  beforeEach(() => start());

  it("imports the entries of the chosen groups and the groups under them", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    const res = await sync();
    expect(res.status).toBe(200);
    expect(res.body.lastStatus).toBe("ok");
    expect(res.body.lastSummary).toEqual({
      created: 2,
      updated: 0,
      unchanged: 0,
      removed: 0,
      skipped: 1,
    });
    expect(stored()).toEqual([
      {
        name: "db-1",
        description: "",
        folder: "Servers",
        tags: ["keepass", `keepass:${DB}`],
        username: "dba",
        password: "pw-db",
        authType: "password",
      },
      {
        name: "web-1",
        description: "https://web-1.example.com",
        folder: "Servers/Linux",
        tags: ["keepass", `keepass:${WEB}`],
        username: "deploy",
        password: "pw-web",
        authType: "password",
      },
    ]);
    expect(
      res.body.items.map((i: { title: string; tag: string; group: string }) => [
        i.title,
        i.tag,
        i.group,
      ]),
    ).toEqual([
      ["db-1", `keepass:${DB}`, "Passwords/Servers"],
      ["web-1", `keepass:${WEB}`, "Passwords/Servers"],
    ]);
    expect(mock.auth.userTokens).toEqual([
      expect.objectContaining({ userId: "user-1", purpose: "KeePass sync" }),
    ]);
  });

  it("never imports the recycle bin, even with the root group chosen", async () => {
    await connectAndChoose(["Passwords"]);
    const res = await sync();
    expect(res.body.lastSummary.created).toBe(3);
    expect(stored().map((c) => c.name)).not.toContain("old");
  });

  it("matches group paths without caring about case", async () => {
    await connectAndChoose(["passwords/servers"]);
    expect((await sync()).body.lastSummary.created).toBe(2);
  });

  it("leaves unchanged entries alone and asks Termix for nothing", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    await sync();
    const before = core.requests.length;
    const res = await sync();
    expect(res.body.lastSummary).toMatchObject({
      created: 0,
      updated: 0,
      unchanged: 2,
    });
    expect(core.requests.length).toBe(before);
    expect(mock.auth.userTokens).toHaveLength(1);
  });

  it("updates a credential when its entry changes in KeePass", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    await sync();
    entries[0].password = "rotated";
    entries[0].group = "Servers";
    await writeDatabase();
    const res = await sync();
    expect(res.body.lastSummary).toMatchObject({ updated: 1, unchanged: 1 });
    expect(stored().find((c) => c.name === "web-1")).toMatchObject({
      password: "rotated",
      folder: "Servers",
      tags: ["keepass", `keepass:${WEB}`],
    });
  });

  it("makes a credential again when it was deleted in Termix", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    await sync();
    const web = core.credentialsOf("user-1").find((c) => c.name === "web-1")!;
    core.credentials.delete(web.id);
    entries[0].password = "rotated";
    await writeDatabase();
    const res = await sync();
    expect(res.body.lastSummary).toMatchObject({ created: 1, updated: 0 });
    const again = core.credentialsOf("user-1").find((c) => c.name === "web-1")!;
    // A new Termix id, but the same tag, so whatever found it by tag still does.
    expect(again.id).not.toBe(web.id);
    expect(again.tags).toEqual(web.tags);
  });

  it("deletes credentials whose entry left the chosen groups", async () => {
    await connectAndChoose(["Passwords/Servers", "Passwords/Personal"]);
    await sync();
    expect(stored()).toHaveLength(3);

    await request("PUT", db1("/config"), {
      groups: ["Passwords/Servers"],
      removeMissing: true,
    });
    const res = await sync();
    expect(res.body.lastSummary).toMatchObject({ removed: 1, unchanged: 2 });
    expect(
      stored()
        .map((c) => c.name)
        .sort(),
    ).toEqual(["db-1", "web-1"]);
  });

  it("deletes credentials whose entry was deleted in KeePass", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    await sync();
    entries.splice(0, 1);
    await writeDatabase();
    const res = await sync();
    expect(res.body.lastSummary).toMatchObject({ removed: 1 });
    expect(stored().map((c) => c.name)).toEqual(["db-1"]);
  });

  it("keeps them, untracked, when removal is off", async () => {
    await connectAndChoose(["Passwords/Servers", "Passwords/Personal"], false);
    await sync();
    await request("PUT", db1("/config"), { groups: ["Passwords/Servers"] });
    const res = await sync();
    expect(res.body.lastSummary.removed).toBe(0);
    expect(stored()).toHaveLength(3);
    expect(res.body.items).toHaveLength(2);
  });

  it("counts an entry under several chosen groups for the first one", async () => {
    await connectAndChoose(["Passwords/Servers/Linux", "Passwords/Servers"]);
    const res = await sync();
    expect(
      res.body.items.find((i: { title: string }) => i.title === "web-1").group,
    ).toBe("Passwords/Servers/Linux");
  });

  it("keeps credentials of a chosen group that vanished from the database", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    await sync();
    entries = entries.filter((e) => !e.group.startsWith("Servers"));
    await writeDatabase();
    const res = await sync();
    expect(res.body.lastSummary.removed).toBe(0);
    expect(stored()).toHaveLength(2);

    await request("PUT", db1("/config"), { groups: [] });
    expect((await sync()).body.lastSummary.removed).toBe(2);
  });

  it("records a failed sync and shows why", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    core.failCore({ method: "POST", status: 403 });
    const res = await sync();
    expect(res.status).toBe(502);
    expect(res.body.error).toMatch(
      /Termix refused to create a credential \(403/,
    );
    const status = await current();
    expect(status.lastStatus).toBe("error");
    expect(status.lastError).toMatch(/403/);
  });

  it("records it when the master password changed", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    await writeDatabase({ password: "a new one" });
    const res = await sync();
    expect(res.status).toBe(422);
    expect(res.body.code).toBe("wrong_key");
    expect((await current()).lastError).toMatch(/master password/);
  });

  it("refreshes the group list from the database", async () => {
    await connectAndChoose([]);
    await writeDatabase({ groups: ["Lab"] });
    const res = await request("POST", db1("/groups/refresh"));
    expect(
      byPath(res.body, DB_FILE).availableGroups.map(
        (g: { path: string }) => g.path,
      ),
    ).toContain("Passwords/Lab");
  });
});

describe("disconnecting", () => {
  beforeEach(() => start());

  it("forgets the password and keeps imported credentials by default", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    await sync();
    expect((await request("DELETE", db1())).body.databases).toEqual([]);
    expect(await mock.ctx.secrets.get(`unlock-${dbId}`)).toBeNull();
    expect(stored()).toHaveLength(2);
    expect((await request("GET", "/status")).body.databases).toEqual([]);
  });

  it("can delete the imported credentials too", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    await sync();
    await request("DELETE", db1("?removeCredentials=true"));
    expect(stored()).toEqual([]);
  });
});

describe("password references", () => {
  beforeEach(() => start());

  const resolve = (userId: string, reference: string) =>
    mock.auth.secretResolvers.get("keepass")!(userId, reference);

  async function connectWithReferences() {
    const saved = await connectAndChoose(["Passwords/Servers"], true, true);
    expect(saved.passwordReferences).toBe(true);
  }

  it("declares the scheme it registers, which Termix requires", () => {
    expect(manifest.contributes?.auth?.secretSchemes).toEqual(["keepass"]);
    expect([...mock.auth.secretResolvers.keys()]).toEqual(
      manifest.contributes?.auth?.secretSchemes,
    );
  });

  it("is on for a new connection", async () => {
    const connected = await connect();
    expect(byPath(connected.body, DB_FILE).passwordReferences).toBe(true);
    await request("PUT", db1("/config"), { groups: ["Passwords/Servers"] });
    await sync();
    expect(stored().map((c) => c.password)).toEqual([
      `keepass://${DB}/password`,
      `keepass://${WEB}/password`,
    ]);
    expect(JSON.stringify(stored())).not.toContain("pw-");
  });

  it("resolves a reference from the database when a host connects", async () => {
    await connectWithReferences();
    await sync();
    expect(await resolve("user-1", `keepass://${WEB}/password`)).toBe("pw-web");
    // Lower case and the dashed form work too, and the file is read once for both.
    entries[1].password = "changed";
    await writeDatabase();
    expect(
      await resolve(
        "user-1",
        "keepass://{22222222-bbbb-4bbb-8bbb-222222222222}/password",
      ),
    ).toBe("pw-db");
  });

  it("reads the database again after the groups are saved", async () => {
    await connectWithReferences();
    await request("PUT", db1("/config"), {
      groups: ["Passwords/Servers"],
      passwordReferences: true,
    });
    entries[0].password = "rotated";
    await writeDatabase();
    expect(await resolve("user-1", `keepass://${WEB}/password`)).toBe(
      "rotated",
    );
  });

  it("only resolves entries in the chosen groups, for a connected user", async () => {
    await connectWithReferences();
    await expect(
      resolve("user-1", `keepass://${MAIL}/password`),
    ).rejects.toThrow(/not in a group you import/);
    await expect(
      resolve("user-1", `keepass://${TRASH}/password`),
    ).rejects.toThrow(/not in a group you import/);
    await expect(resolve("user-1", `keepass://${WEB}/notes`)).rejects.toThrow(
      /Not a KeePass reference/,
    );
    await expect(
      resolve("user-2", `keepass://${WEB}/password`),
    ).rejects.toThrow(/not connected/);

    await request("DELETE", db1());
    await expect(
      resolve("user-1", `keepass://${WEB}/password`),
    ).rejects.toThrow(/not connected/);
  });

  it("writes the passwords back when turned off", async () => {
    await connectWithReferences();
    await sync();
    await request("PUT", db1("/config"), {
      groups: ["Passwords/Servers"],
      passwordReferences: false,
    });
    const res = await sync();
    expect(res.body.lastSummary).toMatchObject({ updated: 2, created: 0 });
    expect(stored().map((c) => c.password)).toEqual(["pw-db", "pw-web"]);
  });

  it("refuses a value that is not true or false", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    const res = await request("PUT", db1("/config"), {
      groups: ["Passwords/Servers"],
      passwordReferences: "yes",
    });
    expect(res.status).toBe(400);
  });
});

describe("scheduled sync", () => {
  beforeEach(() => start());

  it("syncs connections that are due, as their own user", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    actor = "user-2";
    mock.setActor(undefined);
    expect(mock.scheduled).toEqual([
      expect.objectContaining({ kind: "every", ms: 60_000 }),
    ]);
    await mock.runScheduled();
    expect(stored()).toHaveLength(2);
    expect(mock.auth.userTokens.map((t) => t.userId)).toEqual(["user-1"]);
  });

  it("waits for the interval before syncing again", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    await sync();
    entries[0].password = "rotated";
    await writeDatabase();
    await mock.runScheduled();
    expect(stored().find((c) => c.name === "web-1")?.password).toBe("pw-web");
  });

  it("does nothing when the admin turned automatic sync off", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    await mock.ctx.settings.set("syncIntervalMinutes", 0);
    await mock.runScheduled();
    expect(stored()).toEqual([]);
  });

  it("skips connections with no groups chosen", async () => {
    await connectAndChoose([]);
    await mock.runScheduled();
    expect(mock.auth.userTokens).toEqual([]);
  });

  it("records a failure instead of throwing", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    fs.rmSync(path.join(root, DB_FILE));
    await expect(mock.runScheduled()).resolves.toBeUndefined();
    const status = await current();
    expect(status.lastStatus).toBe("error");
    expect(status.lastError).toMatch(/was not found in the KeePass folder/);
  });
});

describe("lifecycle", () => {
  beforeEach(() => start());

  it("works after a disable and enable", async () => {
    await connectAndChoose(["Passwords/Servers"]);
    for (const dispose of mock.disposals) await dispose();
    await activate(mock.ctx);
    expect((await current()).databasePath).toBe(DB_FILE);
  });
});

describe("permissions", () => {
  beforeEach(() => start([]));

  it("refuses users without keepass-secrets.use", async () => {
    expect((await request("GET", "/status")).status).toBe(403);
    expect((await request("GET", "/files")).status).toBe(403);
    expect((await connect()).status).toBe(403);
  });
});
