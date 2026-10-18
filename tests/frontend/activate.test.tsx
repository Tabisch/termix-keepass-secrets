import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import {
  renderWithApp,
  type RenderedPluginApp,
} from "@termix-ssh/plugin-sdk/testing";
import type { PluginManifest } from "@termix-ssh/plugin-sdk/manifest";
import * as plugin from "../../src/frontend/index";
import manifestJson from "../../manifest.json";
import locales from "../../locales/en.json";

const manifest = manifestJson as unknown as PluginManifest;

let rendered: RenderedPluginApp | null = null;

afterEach(async () => {
  await rendered?.deactivate();
  rendered = null;
});

const servers = {
  id: 1,
  databasePath: "team/servers.kdbx",
  keyFilePath: null,
  keyFileUploaded: false,
  groups: ["Passwords/Servers"],
  availableGroups: [
    { path: "Passwords/Personal", entries: 1 },
    { path: "Passwords/Servers", entries: 2 },
  ],
  removeMissing: true,
  passwordReferences: true,
  lastSyncAt: "2026-10-18T10:00:00.000Z",
  lastStatus: "ok",
  lastError: null,
  lastSummary: { created: 2, updated: 0, unchanged: 0, removed: 0, skipped: 1 },
  items: [
    {
      title: "web-1",
      group: "Passwords/Servers",
      credentialId: 7,
      tag: "keepass:11111111AAAA4AAA8AAA111111111111",
      updatedAt: "",
    },
  ],
};

const ops = {
  ...servers,
  id: 2,
  databasePath: "ops/ops.kdbx",
  groups: [],
  availableGroups: [{ path: "Ops/Network", entries: 3 }],
  lastSyncAt: null,
  lastStatus: null,
  lastSummary: null,
  items: [],
};

const connected = { syncIntervalMinutes: 60, databases: [servers] };
const both = { syncIntervalMinutes: 60, databases: [servers, ops] };
const empty = { syncIntervalMinutes: 60, databases: [] };

/** connected, with the first database changed. */
const withServers = (changes: Partial<typeof servers>) => ({
  ...connected,
  databases: [{ ...servers, ...changes }],
});

const listing = {
  databases: ["team/servers.kdbx", "team/other.kdbx"],
  keyFiles: ["keys/team.keyx"],
  truncated: false,
};

function disconnectedApi(post = vi.fn(async () => ({ data: connected }))) {
  return {
    get: vi.fn(async (path: string) => ({
      data: path === "/files" ? listing : empty,
    })),
    post,
  };
}

describe(`${manifest.id} activate`, () => {
  it("registers the rail item and tab", async () => {
    rendered = await renderWithApp(plugin, { manifest, locales });
    expect(rendered.registered.tabs()).toEqual(["keepass"]);
    expect(rendered.registered.railItems()).toEqual([
      expect.objectContaining({
        id: "keepass",
        permission: "keepass-secrets.use",
      }),
    ]);
  });

  it("offers the databases in the folder and sends the chosen one", async () => {
    const post = vi.fn(async () => ({ data: connected }));
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: disconnectedApi(post) as never,
    });
    rendered.renderTab("keepass", { isVisible: true });
    await screen.findByText(locales.connect.title);
    fireEvent.click(await screen.findByText("team/servers.kdbx"));
    fireEvent.click(screen.getByText("keys/team.keyx"));
    fireEvent.click(screen.getByText(locales.connect.submit));
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/databases", {
        databasePath: "team/servers.kdbx",
        password: "",
        keyFilePath: "keys/team.keyx",
      }),
    );
    expect(await screen.findByText("team/servers.kdbx")).toBeTruthy();
  });

  it("shows the server's reason when connecting fails", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: disconnectedApi(
        vi.fn(async () => {
          throw {
            response: {
              data: {
                error:
                  "The master password or key file does not open this database",
              },
            },
          };
        }),
      ) as never,
    });
    rendered.renderTab("keepass", { isVisible: true });
    fireEvent.click(await screen.findByText("team/other.kdbx"));
    fireEvent.click(screen.getByText("keys/team.keyx"));
    fireEvent.click(screen.getByText(locales.connect.submit));
    expect(
      await screen.findByText(
        "The master password or key file does not open this database",
      ),
    ).toBeTruthy();
  });

  it("shows groups, the last sync and what was imported", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: { get: vi.fn(async () => ({ data: connected })) } as never,
    });
    rendered.renderTab("keepass", { isVisible: true });
    expect(await screen.findByText("Passwords/Personal")).toBeTruthy();
    expect(screen.getByText("2 entries")).toBeTruthy();
    expect(screen.getByText("web-1")).toBeTruthy();
    expect(
      screen.getByText("keepass:11111111AAAA4AAA8AAA111111111111"),
    ).toBeTruthy();
    expect(
      screen.getByText(/2 added, 0 updated, 0 unchanged, 0 removed, 1 skipped/),
    ).toBeTruthy();
    expect(screen.getByText("Syncs every 60 minutes.")).toBeTruthy();
  });

  it("saves the chosen groups", async () => {
    const put = vi.fn(async () => ({
      data: withServers({
        groups: ["Passwords/Servers", "Passwords/Personal"],
      }),
    }));
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: { get: vi.fn(async () => ({ data: connected })), put } as never,
    });
    rendered.renderTab("keepass", { isVisible: true });
    fireEvent.click(await screen.findByText("Passwords/Personal"));
    fireEvent.click(screen.getByText(locales.groups.save));
    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/databases/1/config", {
        groups: ["Passwords/Servers", "Passwords/Personal"],
        removeMissing: true,
        passwordReferences: true,
      }),
    );
  });

  it("runs a sync", async () => {
    const post = vi.fn(async () => ({ data: connected }));
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: { get: vi.fn(async () => ({ data: connected })), post } as never,
    });
    rendered.renderTab("keepass", { isVisible: true });
    fireEvent.click(await screen.findByText(locales.sync.now));
    await waitFor(() => expect(post).toHaveBeenCalledWith("/databases/1/sync"));
  });

  it("flags a chosen group that is gone from the database", async () => {
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: {
        get: vi.fn(async () => ({
          data: withServers({ groups: ["Passwords/Servers", "Passwords/Old"] }),
        })),
      } as never,
    });
    rendered.renderTab("keepass", { isVisible: true });
    expect(await screen.findByText("Passwords/Old")).toBeTruthy();
    expect(screen.getByText(locales.groups.missing)).toBeTruthy();
  });

  it("shows every database, adds another and syncs them all", async () => {
    const post = vi.fn(async () => ({ data: { ...both, failed: 0 } }));
    rendered = await renderWithApp(plugin, {
      manifest,
      locales,
      api: {
        get: vi.fn(async (path: string) => ({
          data: path === "/files" ? listing : both,
        })),
        post,
      } as never,
    });
    rendered.renderTab("keepass", { isVisible: true });
    expect(await screen.findByText("team/servers.kdbx")).toBeTruthy();
    expect(screen.getByText("ops/ops.kdbx")).toBeTruthy();
    expect(screen.getByText("Ops/Network")).toBeTruthy();
    expect(screen.getByText("2 databases")).toBeTruthy();

    fireEvent.click(screen.getByText(locales.databases.add));
    expect(await screen.findByText(locales.connect.title)).toBeTruthy();
    fireEvent.click(screen.getByText(locales.connect.cancel));
    await waitFor(() =>
      expect(screen.queryByText(locales.connect.title)).toBeNull(),
    );

    fireEvent.click(screen.getByText(locales.databases.syncAll));
    await waitFor(() => expect(post).toHaveBeenCalledWith("/sync"));
  });
});
