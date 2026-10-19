# AGENTS.md

This repo is a [Termix](https://github.com/Termix-SSH/Termix) plugin. These notes are for AI coding tools.

## Read first

Before changing anything, read `node_modules/@termix-ssh/plugin-sdk/PLUGIN-GUIDE.md`. It covers the
manifest, backend, database, frontend, UI, testing, releasing and submitting to the community registry,
and it matches the SDK version installed here. If it is missing, run `npm install`. If it is still missing,
the SDK is older than 1.0.6: run `npm install -D @termix-ssh/plugin-sdk@latest` or read
https://docs.termix.site/develop instead.

If the guide and the SDK's TypeScript types disagree, the types are right.

## Commands

```bash
npm run build        # bundle into dist/
npm test             # run the tests
npm run typecheck    # type check
npm run validate     # check manifest.json, migrations, changelog and docs
npm run migrations   # write migrations after changing src/backend/tables.ts
npm run pack         # write <id>-<version>.tmxplug
npm run format       # format with Prettier
```

`npx termix-plugin dev --server <url> --key <tmx_...>` installs the plugin on a Termix server with
developer mode on and reinstalls it on every save. Don't start it unless the user asks.

## Done means

- `npm test`, `npm run typecheck`, `npm run validate`, `npm run build` and `npm run format:check` pass
- `npx termix-plugin migrations --check` passes
- New UI text is in `locales/en.json`, new routes have an `@openapi` block and a test
- `docs/` and the section below still match what the plugin does
- User facing changes are in `CHANGELOG.md` under the version they ship in

## About this plugin

Keep this section current when the plugin changes: what it does, how it is put together, decisions that
aren't obvious from the code, and anything that has bitten you before.

- What it does: imports the entries in chosen KeePass groups as Termix password credentials and keeps
  them in sync, per user, on a schedule or on demand. A user connects any number of databases (the
  `databases` table, one row per user and path, enforced in code because a unique index on a long
  path is too wide for MySQL). Everything per database: groups, options, last sync, secret, items. Modelled on Tabisch/termix-dashlane-secrets; keep
  the two alike where they can be.
- Files come from a local folder, the admin setting `databaseRoot` (default `/keepass`), which is meant to
  be an SMB/DFS share mounted by Docker. SMB and DFS were deliberately left out of the plugin: don't add a
  share client. `src/backend/keepass/files.ts` resolves every user path with `realpath` and refuses
  anything outside the folder (`..`, absolute paths, symlinks out). Keep that check on every read,
  including key files. There is no capability for reading such a folder.
- `src/backend/keepass/database.ts`: opens `.kdbx` with `kdbxweb` (a UMD bundle: import its default,
  and types with `import type`). kdbxweb has no Argon2, so it is set to hash-wasm's on first open.
  Group paths are names from the root group down, joined with `/`, including the root's name. A chosen
  group includes the groups under it (`inGroup`). The recycle bin and everything under it is skipped.
- Entry ids are the KeePass UUID as 32 upper case hex digits (`normalizeId` strips dashes and braces).
- `core-credentials.ts`: Termix's `/credentials` API on `127.0.0.1:30001` with a token from
  `ctx.auth.issueUserToken`. The SDK can only create SSH key credentials, so this is the only way to write
  password credentials.
- `sync.ts`: picks entries by group path (case-insensitive), creates, updates (recreates on 404) and
  removes credentials, and records a hash per item so unchanged entries cost nothing. Nothing from a
  chosen group that vanished from the database is removed. Folder is the entry's group without the root.
- The secret `unlock-<databaseId>` (`unlockSecret`) is JSON `{ password, keyFile? }` (key file base64,
  only for uploads). A key file picked from the folder is stored as `databases.keyFilePath` and read on
  every open. `POST /databases` with a path the user already has updates that row and its secret.
- `unlocks.ts` is the only place that reads or writes master passwords. `databases.rememberPassword` (on by
  default) and the admin setting `allowRememberPassword` decide: remembered goes to ctx.secrets, otherwise a
  Map made inside activate, so a restart or disable/enable locks the database. Locked means no unlock in
  either place: `SyncError("locked")` (423), not recorded as a failed sync; the scheduler and Sync all skip
  it; the resolver says it is locked. `POST /databases/:id/unlock` and `/lock` manage it. When an admin
  forbids remembering, stored secrets are deleted once (per process) the next time they would be read.
  Never write a non-remembered password anywhere, logs and the database included.
- Items are unique per user, database and entry: copies of a database share UUIDs, so the same
  `keepass:<uuid>` tag can be on one credential per database.
- `schedule.ts`: a one-minute tick that syncs databases older than the admin interval, each inside
  `ctx.asUser`. It never throws, so a broken account can't spend the error budget.
- Every credential carries `keepass` and `keepass:<uuid>` (`credentialIdTag`). The id tag is a public
  contract other plugins can match on, so never change its format.
- Password references (`databases.passwordReferences`, on by default): the sync writes
  `keepass://<uuid>/password` (`passwordReference`) instead of the password, and `resolver.ts` answers the
  `keepass` scheme via `ctx.credentials.registerSecretResolver` (`auth:provide`, and the scheme must be in
  the manifest's `contributes.auth.secretSchemes`, or Termix stops the plugin on activate; the SDK mock
  doesn't check this, a test does). Termix calls it at host resolution with the credential owner's id. The
  reference names no database (so it survives a reconnect): it tries the database(s) the entry was
  imported from, then the owner's other databases, reading each secret with `ctx.asUser`, and only
  answers for entries in that database's chosen groups. Opened databases are cached in memory for 30s
  per database and `forget(userId, databaseId?)` drops them on connect, config change and disconnect.
  Never persist resolved passwords.
- The databases column is `chosenGroups`, not `groups`: `GROUPS` is a reserved word in MySQL 8.
- `json()` columns are plain text: the repository `JSON.stringify`s on write.
- Use npm 11 to install. npm 10 crashes resolving the dev dependency peer set.
- Releases: run the Release workflow (shared `plugin-release.yml` from Termix-Registry) from a `dev-X.Y.Z`
  branch. `.github/workflows/registry.yml` then runs `scripts/build-registry.mjs` (copied from
  Tabisch/termix-netbox-import) and pushes `index.json` to the `registry` branch, so the repo is its own
  custom registry. It lists only releases whose `.tmxplug.sig` verifies against `TERMIX_PLUGIN_SIGNING_KEY`
  and derives the index's `publicKey` from that secret. Changing the secret breaks every install.
  `--sign-missing` signs and attaches a `.sig` for any release built without one.
