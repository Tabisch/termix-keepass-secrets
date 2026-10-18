import kdbxweb from "kdbxweb";
import type { Kdbx, KdbxEntry, KdbxGroup, KdbxUuid } from "kdbxweb";
import { argon2d, argon2id } from "hash-wasm";

/** A KeePass entry, with the fields Termix can use. */
export interface VaultEntry {
  /** The entry's UUID as 32 upper case hex digits, the way KeePass shows it. */
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  /** Names from the root group down to the entry's group, joined with "/". */
  groupPath: string;
}

export interface VaultGroup {
  path: string;
  /** Entries in the group and every group under it. */
  entries: number;
}

export interface Vault {
  entries: VaultEntry[];
  groups: VaultGroup[];
}

export interface Unlock {
  password: string;
  /** The key file's bytes, if the database needs one. */
  keyFile?: Buffer | null;
}

export class DatabaseOpenError extends Error {
  constructor(
    message: string,
    readonly code: "wrong_key" | "not_kdbx",
  ) {
    super(message);
    this.name = "DatabaseOpenError";
  }
}

let argon2Ready = false;

/** kdbxweb brings no Argon2 of its own, which KDBX 4 needs. */
function useHashWasmArgon2(): void {
  if (argon2Ready) return;
  kdbxweb.CryptoEngine.setArgon2Impl(
    async (
      password,
      salt,
      memory,
      iterations,
      length,
      parallelism,
      type,
      version,
    ) => {
      if (version !== 0x13) {
        throw new Error(`Argon2 version ${version} is not supported`);
      }
      const hash = await (
        type === kdbxweb.CryptoEngine.Argon2TypeArgon2id ? argon2id : argon2d
      )({
        password: new Uint8Array(password),
        salt: new Uint8Array(salt),
        memorySize: memory,
        iterations,
        hashLength: length,
        parallelism,
        outputType: "binary",
      });
      return hash.buffer.slice(
        hash.byteOffset,
        hash.byteOffset + hash.byteLength,
      ) as ArrayBuffer;
    },
  );
  argon2Ready = true;
}

/** KeePass writes UUIDs as 16 bytes; people and the tag see them as hex. */
export function normalizeId(id: string): string {
  return id.replace(/[{}-]/g, "").trim().toUpperCase();
}

function uuidHex(uuid: KdbxUuid): string {
  return normalizeId(Buffer.from(uuid.bytes).toString("hex"));
}

function fieldText(entry: KdbxEntry, name: string): string {
  const value = entry.fields.get(name);
  if (value == null) return "";
  return typeof value === "string" ? value : value.getText();
}

function toArrayBuffer(bytes: Buffer): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer;
}

export async function openDatabase(
  file: Buffer,
  unlock: Unlock,
): Promise<Vault> {
  useHashWasmArgon2();
  const credentials = new kdbxweb.Credentials(
    unlock.password ? kdbxweb.ProtectedValue.fromString(unlock.password) : null,
    unlock.keyFile ? toArrayBuffer(unlock.keyFile) : null,
  );
  let db: Kdbx;
  try {
    await credentials.ready;
    db = await kdbxweb.Kdbx.load(toArrayBuffer(file), credentials);
  } catch (error) {
    const code = (error as { code?: string })?.code;
    if (code === kdbxweb.Consts.ErrorCodes.InvalidKey) {
      throw new DatabaseOpenError(
        "The master password or key file does not open this database",
        "wrong_key",
      );
    }
    throw new DatabaseOpenError(
      `Not a KeePass database this plugin can read${
        error instanceof Error && error.message ? ` (${error.message})` : ""
      }`,
      "not_kdbx",
    );
  }
  return readVault(db);
}

export function readVault(db: Kdbx): Vault {
  const root = db.getDefaultGroup();
  const recycleBin =
    db.meta.recycleBinEnabled !== false ? db.meta.recycleBinUuid : undefined;
  const entries: VaultEntry[] = [];
  const groups: VaultGroup[] = [];

  const walk = (group: KdbxGroup, parentPath: string): number => {
    if (recycleBin && !recycleBin.empty && group.uuid.equals(recycleBin)) {
      return 0;
    }
    const name = group.name || "Group";
    const groupPath = parentPath ? `${parentPath}/${name}` : name;
    const info: VaultGroup = { path: groupPath, entries: 0 };
    groups.push(info);
    for (const entry of group.entries) {
      entries.push({
        id: uuidHex(entry.uuid),
        title: fieldText(entry, "Title"),
        username: fieldText(entry, "UserName"),
        password: fieldText(entry, "Password"),
        url: fieldText(entry, "URL"),
        notes: fieldText(entry, "Notes"),
        groupPath,
      });
    }
    let count = group.entries.length;
    for (const child of group.groups) count += walk(child, groupPath);
    info.entries = count;
    return count;
  };

  walk(root, "");
  groups.sort((a, b) => a.path.localeCompare(b.path));
  return { entries, groups };
}

/** Whether an entry in groupPath is in the chosen group or one under it. */
export function inGroup(groupPath: string, chosen: string): boolean {
  const entry = groupPath.toLowerCase();
  const wanted = chosen.trim().toLowerCase();
  return entry === wanted || entry.startsWith(`${wanted}/`);
}
