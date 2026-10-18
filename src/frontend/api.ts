import type { TermixApp } from "@termix-ssh/plugin-sdk/frontend";

export interface GroupInfo {
  path: string;
  entries: number;
}

export interface SyncSummary {
  created: number;
  updated: number;
  unchanged: number;
  removed: number;
  skipped: number;
}

export interface ImportedCredential {
  title: string | null;
  group: string;
  credentialId: number;
  /** "keepass:<uuid>", on the credential in Termix and stable across syncs. */
  tag: string;
  updatedAt: string;
}

export interface FolderListing {
  databases: string[];
  keyFiles: string[];
  truncated: boolean;
}

export interface ConnectInput {
  databasePath: string;
  password: string;
  keyFilePath?: string;
  /** An uploaded key file, base64. */
  keyFile?: string;
}

export interface DatabaseStatus {
  id: number;
  databasePath: string;
  keyFilePath: string | null;
  keyFileUploaded: boolean;
  groups: string[];
  availableGroups: GroupInfo[];
  removeMissing: boolean;
  passwordReferences: boolean;
  lastSyncAt: string | null;
  lastStatus: "ok" | "error" | null;
  lastError: string | null;
  lastSummary: SyncSummary | null;
  items: ImportedCredential[];
}

export interface Status {
  syncIntervalMinutes: number;
  databases: DatabaseStatus[];
  /** Only after syncing everything: how many databases failed. */
  failed?: number;
}

type Api = TermixApp["api"];

export function createKeePassApi(api: Api) {
  return {
    status: async () => (await api.get<Status>("/status")).data,
    files: async () => (await api.get<FolderListing>("/files")).data,
    connect: async (input: ConnectInput) =>
      (await api.post<Status>("/databases", input)).data,
    saveConfig: async (
      id: number,
      groups: string[],
      removeMissing: boolean,
      passwordReferences: boolean,
    ) =>
      (
        await api.put<Status>(`/databases/${id}/config`, {
          groups,
          removeMissing,
          passwordReferences,
        })
      ).data,
    refreshGroups: async (id: number) =>
      (await api.post<Status>(`/databases/${id}/groups/refresh`)).data,
    sync: async (id: number) =>
      (await api.post<Status>(`/databases/${id}/sync`)).data,
    syncAll: async () => (await api.post<Status>("/sync")).data,
    disconnect: async (id: number, removeCredentials: boolean) =>
      (
        await api.delete<Status>(
          `/databases/${id}${removeCredentials ? "?removeCredentials=true" : ""}`,
        )
      ).data,
  };
}

export type KeePassApi = ReturnType<typeof createKeePassApi>;

/** The server's own message when there is one, so people see what went wrong. */
export function errorMessage(error: unknown, fallback: string): string {
  const data = (error as { response?: { data?: { error?: unknown } } })
    ?.response?.data;
  if (data && typeof data.error === "string" && data.error) return data.error;
  return fallback;
}

/** A picked file as base64, without the data: URL prefix. */
export async function fileToBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}
