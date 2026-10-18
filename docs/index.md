KeePass imports the entries of your KeePass database as Termix credentials and keeps them in sync. You pick the groups, and each entry becomes a password credential you can use on any host.

## Before you start: the KeePass folder

The plugin reads `.kdbx` files from one folder on the Termix server, the KeePass folder. It never opens a file outside it. An admin sets it in Settings, under KeePass, KeePass folder. It is `/keepass` to start with.

The usual setup is a Windows or DFS share mounted into the Termix container. Docker mounts it, so Termix itself needs no share credentials. With Docker Compose:

```yaml
services:
  termix:
    # ...
    volumes:
      - keepass:/keepass:ro

volumes:
  keepass:
    driver: local
    driver_opts:
      type: cifs
      device: "//corp.example.com/dfs/IT/KeePass"
      o: "username=svc-termix,password=${KEEPASS_SHARE_PASSWORD},domain=CORP,vers=3.0,ro,file_mode=0444,dir_mode=0555"
```

- `device` can be a DFS path. The Docker host's kernel follows the DFS referral, so install `cifs-utils` on the host.
- Mount it read-only (`ro`). The plugin only reads.
- Use an account that may read the databases, and keep its password out of the compose file, for example in an `.env` file.
- Any other way to get the files into that folder works too: a bind mount, an NFS volume, a synced folder.

## Connect

1. Install KeePass from the Plugins tab.
2. Open the KeePass tab from the sidebar.
3. Pick your database under Database, or type its path inside the KeePass folder, like `team/servers.kdbx`.
4. Type the Master password.
5. If the database needs a key file, pick one from the folder under Key file, or upload one with Key file to upload.
6. Press Connect.

Termix opens the database once to check the password and lists its groups. KDBX 3.1 and 4 files work, with AES, ChaCha20 and Argon2 (Argon2d and Argon2id).

The master password, and a key file you upload, are stored encrypted on the server so scheduled syncs can open the database. They are never shown again. A key file picked from the folder is read from there on each sync.

## Pick groups

Tick the groups to import and press Save. Then press Sync now.

A group brings the groups under it. Tick the top group (`Passwords` here) to import the whole database. The recycle bin is never imported.

Every entry with a password becomes a credential:

| Termix field | From KeePass                                                   |
| ------------ | -------------------------------------------------------------- |
| Name         | The entry's title, or else the URL's host name                 |
| Username     | User name                                                      |
| Password     | Password, or a reference to it (see below)                     |
| Description  | URL                                                            |
| Folder       | The entry's group, without the top group, like `Servers/Linux` |
| Tags         | `keepass` and `keepass:<uuid>`                                 |

`<uuid>` is the entry's UUID as KeePass shows it, 32 hex digits like `keepass:11111111AAAA4AAA8AAA111111111111`. It never changes: not when the entry is edited, not when it moves to another group, and not when Termix makes the credential again. So other tools can find the credential by that tag. The tab lists the tag under each imported credential, ready to copy. The [NetBox Sync](https://github.com/Tabisch/termix-netbox-import) plugin can use it to give NetBox hosts a credential: tag a device in NetBox with `keepass:<uuid>`.

An entry under several chosen groups is counted for the first one you ticked. Entries without a password are skipped and counted under skipped.

## Keep passwords in KeePass

Keep passwords in KeePass, under the groups, is on to start with. It keeps the passwords out of Termix, the way the Secret Sources plugin does for 1Password: each credential gets a reference instead of the password, like `keepass://11111111AAAA4AAA8AAA111111111111/password`. When a host using the credential connects, Termix asks this plugin for the password, and it reads it from the database file right then.

- No password is written to Termix's database. Passwords are held in memory for about a minute after a connect, so connecting to several hosts at once opens the database only once.
- A changed password in KeePass works on the next connect, without waiting for a sync.
- Connecting needs the database file to be in the KeePass folder and the stored master password to open it. If it can't, the connect fails and says why.
- Only entries in the groups you import resolve. Untick a group, or disconnect, and its references stop working.
- A reference resolves with the database of the credential's owner, also when the credential is shared.
- Turn it off and press Save to store the passwords in Termix instead: the next sync writes them into the credentials, and connecting no longer needs the file.

You can also type a reference into a credential or host password yourself, as long as the entry is in a group you import. The UUID may have dashes and braces, in any case.

## Keeping in sync

Termix syncs every connected database on a schedule, every 60 minutes by default. Admins set the interval in Settings, under KeePass. 0 turns automatic sync off, and people press Sync now themselves.

On each sync:

- New entries in the chosen groups are added.
- Entries that changed in KeePass are updated in Termix. KeePass wins: an edit you make to an imported credential in Termix is overwritten the next time that entry changes in KeePass.
- If you delete an imported credential in Termix, it comes back the next time its entry changes in KeePass.
- With Delete credentials that leave these groups on (the default), a credential whose entry left the chosen groups, or was deleted or moved to the recycle bin, is deleted from Termix. Only credentials this plugin imported are ever deleted. With it off, they stay and are no longer synced.
- If a chosen group is gone from the database, its credentials are kept and the tab marks it Not in the database any more. That is often a renamed group: tick the new name, untick the old one and press Save.

The tab shows when the last sync ran, what it changed, and why it failed if it did.

## Disconnect

Press Disconnect to delete the master password from Termix and keep the imported credentials, or Disconnect and delete imported credentials to remove those too. With Keep passwords in KeePass on, credentials you keep can't connect any more, since their references no longer resolve.

To use another database or a new master password, disconnect and connect again. Connecting another database starts with no groups chosen.

## Permissions

Using the tab needs the Use KeePass permission, which admins and users get by default. Importing also needs Termix's own credentials permissions (create, edit and delete credentials), because the credentials are made as you.

Anyone with Use KeePass can open any database in the KeePass folder they know the master password of. Put only databases there that those people may see, or give the permission to fewer roles.

## Troubleshooting

- The KeePass folder does not exist on the server: the share is not mounted, or the KeePass folder setting points somewhere else. Check the volume in your compose file.
- There are no .kdbx files in the KeePass folder: the mount is empty, or the account Docker mounts it with can't read it.
- The master password or key file does not open this database: check both. If the password was changed in KeePass, disconnect and connect again.
- Not a KeePass database this plugin can read: the file is a KDBX 1 (`.kdb`) file or damaged. Save it as KDBX 4 in KeePass.
- Points outside the KeePass folder: the path is a symlink to somewhere else. Use the real file.
- Termix refused to create a credential (403): you don't have the credentials permissions. Ask an admin.
- Connecting fails with "KeePass entry ... is not in a group you import": the entry left your chosen groups, or has no password any more. Tick its group again, or pick another credential.
