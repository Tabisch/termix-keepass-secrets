import type { PluginContext } from "@termix-ssh/plugin-sdk/backend";

/**
 * Termix's own credentials API, called as one user. The SDK can only save SSH
 * keys (ctx.credentials.createSshKey), and a KeePass entry is a username and
 * password, so this goes through core's /credentials routes with a short-lived
 * session from ctx.auth.issueUserToken. That user's permissions apply
 * unchanged: credentials.create, credentials.edit and credentials.delete.
 */

/** Core's HTTP server, which always listens on loopback in the same process. */
function coreUrl(): string {
  const port = Number(process.env.EMBEDDED_BACKEND_PORT) || 30001;
  return `http://127.0.0.1:${port}`;
}

export interface CredentialInput {
  name: string;
  description: string;
  folder: string;
  tags: string[];
  username: string;
  password: string;
}

export class CoreApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "CoreApiError";
  }
}

export interface CoreCredentials {
  create: (input: CredentialInput) => Promise<number>;
  /** False when the credential is gone, so the caller can make it again. */
  update: (id: number, input: CredentialInput) => Promise<boolean>;
  /** False when the credential was already gone. */
  remove: (id: number) => Promise<boolean>;
}

export async function coreCredentialsFor(
  ctx: PluginContext,
  userId: string,
): Promise<CoreCredentials> {
  const { token } = await ctx.auth.issueUserToken(userId, {
    purpose: "KeePass sync",
    ttlSeconds: 600,
  });
  const base = coreUrl();
  const host = new URL(base).hostname;

  const call = async (method: string, path: string, body?: unknown) => {
    const response = await ctx.fetch(`${base}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${token}`,
        ...(body ? { "content-type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      allowPrivateHosts: [host],
      timeoutMs: 30_000,
    });
    const text = await response.text();
    let json: Record<string, unknown> = {};
    try {
      json = text ? JSON.parse(text) : {};
    } catch {
      // Left empty; the status says what happened.
    }
    return { status: response.status, json };
  };

  const fail = (
    action: string,
    status: number,
    json: Record<string, unknown>,
  ) =>
    new CoreApiError(
      `Termix refused to ${action} a credential (${status}${
        typeof json.error === "string" ? `: ${json.error}` : ""
      })`,
      status,
    );

  return {
    async create(input) {
      const { status, json } = await call("POST", "/credentials", {
        ...input,
        authType: "password",
      });
      if (status !== 201 || typeof json.id !== "number") {
        throw fail("create", status, json);
      }
      return json.id;
    },

    async update(id, input) {
      const { status, json } = await call("PUT", `/credentials/${id}`, {
        ...input,
        authType: "password",
      });
      if (status === 404) return false;
      if (status !== 200) throw fail("update", status, json);
      return true;
    },

    async remove(id) {
      const { status, json } = await call("DELETE", `/credentials/${id}`);
      if (status === 404) return false;
      if (status !== 200) throw fail("delete", status, json);
      return true;
    },
  };
}
