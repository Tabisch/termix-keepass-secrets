import type { Router } from "express";
import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import { databases, items } from "./tables.js";
import { createRepository } from "./repository.js";
import { createSecretResolver } from "./resolver.js";
import { registerRoutes } from "./routes.js";
import { startScheduledSync } from "./schedule.js";
import { createSyncer, loadVault, SECRET_SCHEME } from "./sync.js";
import { createUnlocks } from "./unlocks.js";

export async function activate(ctx: PluginContext) {
  const databasesTable = await ctx.db.define(databases);
  const itemsTable = await ctx.db.define(items);
  const repo = createRepository(ctx, databasesTable, itemsTable);
  const unlocks = createUnlocks(ctx);
  const syncer = createSyncer({ ctx, repo, unlocks });
  const resolver = createSecretResolver({
    repo,
    unlocks,
    fetchVault: (source, unlock) => loadVault(ctx, source, unlock),
  });
  ctx.credentials.registerSecretResolver(SECRET_SCHEME, resolver.resolve);

  registerRoutes(
    ctx.http.router<Router>(),
    ctx,
    repo,
    syncer,
    unlocks,
    resolver,
  );
  startScheduledSync(ctx, repo, syncer);
}

export async function deactivate() {
  // Everything registered through ctx is disposed by core.
}
