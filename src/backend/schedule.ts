import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";
import type { Repository } from "./repository.js";
import type { Syncer } from "./sync.js";

const TICK_MS = 60_000;

/**
 * Checks once a minute for connections due a sync, so a change to the admin
 * interval applies without a restart. Each sync runs as its own user.
 * Failures are recorded on the connection and never thrown, so one broken
 * account can't spend the plugin's error budget.
 */
export function startScheduledSync(
  ctx: PluginContext,
  repo: Repository,
  syncer: Syncer,
): void {
  ctx.schedule.every(
    TICK_MS,
    async () => {
      await runDueSyncs(ctx, repo, syncer);
    },
    {
      jitterMs: 10_000,
    },
  );
}

export async function runDueSyncs(
  ctx: PluginContext,
  repo: Repository,
  syncer: Syncer,
  now = Date.now(),
): Promise<number> {
  const minutes = Number(
    (await ctx.settings.get<number>("syncIntervalMinutes")) ?? 60,
  );
  if (!Number.isFinite(minutes) || minutes <= 0) return 0;

  let ran = 0;
  for (const connection of await repo.listConnections()) {
    if (!connection.groups.length) continue;
    const last = connection.lastSyncAt ? Date.parse(connection.lastSyncAt) : 0;
    if (now - last < minutes * 60_000) continue;
    ran += 1;
    try {
      await ctx.asUser(connection.userId, () => syncer.run(connection.userId));
    } catch (error) {
      ctx.log.warn(
        `scheduled keepass sync failed for user ${connection.userId}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
  return ran;
}
