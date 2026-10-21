# KeePass for Termix

A [Termix](https://github.com/Termix-SSH/Termix) plugin that imports the entries in your KeePass groups as Termix credentials and keeps them in sync.

- Opens `.kdbx` files (KDBX 3.1 and 4) from a folder on the Termix server, typically a Windows or DFS share mounted into the container by Docker
- Connect as many databases per user as you need, each with its own password, groups and sync status
- Unlocks them with a master password, a key file, or both. Works with no one signed in
- Pick which groups to import, with the groups under them
- Each entry becomes a password credential, filed in a folder named after its group and tagged `keepass`
- Each credential also gets a `keepass:<uuid>` tag that never changes, not on edits, moves or a reimport. The tab shows it under each credential
- Syncs on a schedule an admin sets, or when you press Sync now
- Updates changed entries, and can delete credentials whose entry left the groups
- Keep passwords in KeePass (on by default): credentials hold a `keepass://<uuid>/password` reference instead of the password, and Termix asks the plugin for it when a host connects, like Secret Sources does for 1Password. Nothing secret is stored in Termix's credentials

How to set it up and use it, including a Docker Compose example for mounting a DFS share: [docs/index.md](docs/index.md).

## Install from GitHub

This plugin is published in [Tabisch/termix-registry](https://github.com/Tabisch/termix-registry), one Termix plugin registry for all of Tabisch's plugins. Add it once and Termix installs the plugin straight from the GitHub releases and offers every new version under Updates.

1. In Termix, open Plugins, Registries and press Add registry.
2. Paste this URL and press Check:

   ```
   https://raw.githubusercontent.com/Tabisch/termix-registry/registry/index.json
   ```

3. Check that the key id Termix shows matches the one in the latest [Registry workflow run](https://github.com/Tabisch/termix-registry/actions/workflows/registry.yml) summary, then press Trust and add.
4. Open Browse, find KeePass and press Install. Approve the capabilities it asks for.

You can also download `keepass-secrets-<version>.tmxplug` from [Releases](https://github.com/Tabisch/termix-keepass-secrets/releases) and install it from Plugins, Install from file, with Plugin developer mode on under Settings, General. A plugin installed that way doesn't update on its own.

### Releasing (maintainers)

1. Bump the version in `manifest.json`, `package.json` and a new `CHANGELOG.md` section.
2. Make a `dev-X.Y.Z` branch from `main`, then run the Release workflow from it in Actions. It builds the `.tmxplug`, publishes the GitHub release and merges into `main`. Pick `beta` to publish `X.Y.Z-beta.N` instead, or `dry-run` to check without publishing.

[Tabisch/termix-registry](https://github.com/Tabisch/termix-registry) picks up the release within the hour, signs it with its own key and lists it.

## How it works

1. An admin sets the KeePass folder (`databaseRoot`, `/keepass` by default). Users pick a `.kdbx` file inside it. Paths are resolved with `realpath` and refused when they leave the folder, also through symlinks.
2. Each user can connect many databases. Each one's master password, and an uploaded key file, are stored with `ctx.secrets`, encrypted with the Termix installation key, so scheduled syncs can read them.
3. A sync reads the file and opens it with [kdbxweb](https://github.com/keeweb/kdbxweb), with Argon2 from [hash-wasm](https://github.com/Daninet/hash-wasm). Entries in the recycle bin are left out.
4. Entries in the chosen groups are written to Termix's `/credentials` API as the user, with a short-lived session from `ctx.auth.issueUserToken`. The plugin keeps a table of which entry became which credential and a hash of what it wrote, so unchanged entries are not written again.
5. With Keep passwords in KeePass on, the password written is `keepass://<uuid>/password`. The plugin registers the `keepass` scheme with `ctx.credentials.registerSecretResolver`, so when a host connects Termix hands it the reference and the credential's owner. It asks the database the entry was imported from first, then the user's other databases (each cached in memory for 30 seconds), and returns the password.

Capabilities it asks for:

| Capability          | Why                                                                                                      |
| ------------------- | -------------------------------------------------------------------------------------------------------- |
| `users:impersonate` | A short-lived Termix session per sync, to create, update and delete the user's credentials as that user. |
| `auth:provide`      | Resolve `keepass://` references in credentials when a host connects.                                     |
| `network:outbound`  | Reach Termix's own API on `127.0.0.1`.                                                                   |
| `secrets:own`       | Store the master password and uploaded key file of each database encrypted.                              |
| `db:own`            | Remember which credential each KeePass entry became.                                                     |
| `network:serve`     | The tab's API routes.                                                                                    |
| `ui:surface`        | The KeePass tab.                                                                                         |

Reading the KeePass folder needs no capability: Termix has none for reading a folder outside the plugin's own. The plugin reads only inside the folder the admin set, and never writes there.

### Things to know

- SMB and DFS are left to Docker (or the host): the plugin reads a mounted folder and has no share credentials of its own.
- Opening a KDBX 4 database runs its Argon2 key derivation on the server. Databases with very high Argon2 memory or iteration settings make every sync and every first connect after the 30 second cache slower.
- KDBX 1 (`.kdb`, KeePass 1.x) files and YubiKey challenge-response are not supported.

## Development

You need Node 24 and npm 11. npm 10 fails to resolve the dev dependency tree with `Cannot read properties of null (reading 'edgesOut')`.

```bash
npm install
npm test
npm run typecheck
npm run validate
npm run build
```

To try it on a Termix server (26.10 or newer) with Plugin developer mode on:

```bash
npx termix-plugin dev --server http://localhost:30001 --key tmx_your_key
```

Or `npm run build && npm run pack`, then install the `.tmxplug` from Plugins, Install from file.

The tests build real `.kdbx` files with kdbxweb in a temporary folder that stands in for the share, and fake Termix behind `ctx.fetch` (see `tests/backend/fixtures.ts`), so decryption, parsing, the folder checks and the credential calls all run in them.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
