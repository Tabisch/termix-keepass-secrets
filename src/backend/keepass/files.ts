import fs from "node:fs/promises";
import path from "node:path";

/**
 * KeePass files are read from one folder on the Termix server, set by an
 * admin (databaseRoot), usually a share mounted into the container. Users
 * name files relative to it, and nothing outside it is ever opened, also not
 * through a symlink.
 */

/** Bigger than any real database, small enough to never hurt the server. */
export const MAX_FILE_BYTES = 64 * 1024 * 1024;

/** Limits for listing the folder, which can be a slow network share. */
const MAX_DEPTH = 6;
const MAX_VISITED = 5_000;
const MAX_LISTED = 500;

export const DATABASE_EXTENSIONS = [".kdbx"];
export const KEY_FILE_EXTENSIONS = [".key", ".keyx"];

export class DatabaseFileError extends Error {
  constructor(
    message: string,
    readonly code:
      "no_root" | "invalid_path" | "outside_root" | "not_found" | "too_large",
  ) {
    super(message);
    this.name = "DatabaseFileError";
  }
}

async function realRoot(root: string): Promise<string> {
  if (!root.trim() || !path.isAbsolute(root.trim())) {
    throw new DatabaseFileError(
      "An admin has to set the KeePass folder in Settings first",
      "no_root",
    );
  }
  try {
    return await fs.realpath(root.trim());
  } catch {
    throw new DatabaseFileError(
      `The KeePass folder ${root.trim()} does not exist on the server`,
      "no_root",
    );
  }
}

/** A path as people type it: either slash, no leading slash, no "..". */
export function normalizeRelativePath(input: string): string {
  const parts = input
    .trim()
    .replace(/\\/g, "/")
    .split("/")
    .filter((part) => part && part !== ".");
  if (!parts.length || parts.some((part) => part === "..")) {
    throw new DatabaseFileError(
      "Give the path of a file inside the KeePass folder",
      "invalid_path",
    );
  }
  return parts.join("/");
}

/** The real path of a file under root, after following every symlink. */
export async function resolveInRoot(
  root: string,
  relative: string,
): Promise<string> {
  const base = await realRoot(root);
  const wanted = path.join(base, ...normalizeRelativePath(relative).split("/"));
  let real: string;
  try {
    real = await fs.realpath(wanted);
  } catch {
    throw new DatabaseFileError(
      `${normalizeRelativePath(relative)} was not found in the KeePass folder`,
      "not_found",
    );
  }
  if (real !== base && !real.startsWith(base + path.sep)) {
    throw new DatabaseFileError(
      `${normalizeRelativePath(relative)} points outside the KeePass folder`,
      "outside_root",
    );
  }
  return real;
}

export async function readFileInRoot(
  root: string,
  relative: string,
): Promise<Buffer> {
  const real = await resolveInRoot(root, relative);
  const stat = await fs.stat(real);
  if (!stat.isFile()) {
    throw new DatabaseFileError(
      `${normalizeRelativePath(relative)} is not a file`,
      "not_found",
    );
  }
  if (stat.size > MAX_FILE_BYTES) {
    throw new DatabaseFileError(
      `${normalizeRelativePath(relative)} is too big to be a KeePass file`,
      "too_large",
    );
  }
  return fs.readFile(real);
}

export interface FolderListing {
  databases: string[];
  keyFiles: string[];
  /** True when the folder had more than was looked at. */
  truncated: boolean;
}

/** Database and key files under root, as relative paths with "/". */
export async function listFolder(root: string): Promise<FolderListing> {
  const base = await realRoot(root);
  const listing: FolderListing = {
    databases: [],
    keyFiles: [],
    truncated: false,
  };
  let visited = 0;

  const walk = async (dir: string, prefix: string, depth: number) => {
    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (++visited > MAX_VISITED) {
        listing.truncated = true;
        return;
      }
      if (entry.name.startsWith(".")) continue;
      const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (depth < MAX_DEPTH) {
          await walk(path.join(dir, entry.name), relative, depth + 1);
        } else {
          listing.truncated = true;
        }
        continue;
      }
      if (!entry.isFile() && !entry.isSymbolicLink()) continue;
      const extension = path.extname(entry.name).toLowerCase();
      const list = DATABASE_EXTENSIONS.includes(extension)
        ? listing.databases
        : KEY_FILE_EXTENSIONS.includes(extension)
          ? listing.keyFiles
          : null;
      if (!list) continue;
      if (listing.databases.length + listing.keyFiles.length >= MAX_LISTED) {
        listing.truncated = true;
        return;
      }
      list.push(relative);
    }
  };

  await walk(base, "", 0);
  return listing;
}
