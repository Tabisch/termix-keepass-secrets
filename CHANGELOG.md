# Changelog

## 1.0.0

### Added

- Connect KeePass (.kdbx, KDBX 3.1 and 4) databases from a folder on the Termix server, like a mounted share. Each user can connect as many as they need, each with its own password, groups and sync status, and sync them one by one or all at once
- Unlock it with a master password, a key file in that folder, an uploaded key file, or a password and key file together
- Remember the master password, or don't: off, it is kept in memory only, never written to the server, and the database locks on every restart until you unlock it in the tab. Admins can forbid storing master passwords for everyone
- Pick which groups to import, with the groups under them
- Entries in those groups become Termix password credentials, in a folder per group and tagged `keepass` and `keepass:<uuid>`
- Keep passwords in KeePass: credentials get a `keepass://<uuid>/password` reference, read from the database each time a host connects. On by default
- Sync on a schedule an admin sets, or with Sync now
- Changed entries are updated, and entries that leave the groups can be deleted from Termix
