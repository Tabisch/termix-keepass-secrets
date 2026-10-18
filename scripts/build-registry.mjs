#!/usr/bin/env node
// Builds a Termix custom registry index (index.json) from this repo's GitHub
// releases, so admins can add the repo as a registry and install and update
// the plugin from the Plugins tab.
//
// Every listed version must be a release with a <id>-<version>.tmxplug and
// its .sig, signed with TERMIX_PLUGIN_SIGNING_KEY. The index's publicKey is
// derived from that same key, so the repo needs only one secret. Releases
// that are unsigned or signed with another key are left out.
//
// A release built without the key (no .sig) is signed here and gets its .sig
// attached when --sign-missing is passed.
//
// Usage: node scripts/build-registry.mjs <out-file> [--sign-missing]
// Env: GITHUB_REPOSITORY (owner/repo), GH_TOKEN, TERMIX_PLUGIN_SIGNING_KEY

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// DER prefix of an Ed25519 SubjectPublicKeyInfo; the raw 32-byte key follows.
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** A base64 PKCS8 DER (what keygen writes) or PEM Ed25519 private key. */
function loadPrivateKey(value) {
  const trimmed = (value ?? "").trim();
  if (!trimmed) throw new Error("TERMIX_PLUGIN_SIGNING_KEY is not set");
  const privateKey = trimmed.startsWith("-----BEGIN")
    ? crypto.createPrivateKey(trimmed)
    : crypto.createPrivateKey({
        key: Buffer.from(trimmed, "base64"),
        format: "der",
        type: "pkcs8",
      });
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("The signing key must be an Ed25519 key");
  }
  return privateKey;
}

/** The raw base64 public key of a base64 PKCS8 DER or PEM private key. */
export function publicKeyFromPrivate(value) {
  const der = crypto
    .createPublicKey(loadPrivateKey(value))
    .export({ format: "der", type: "spki" });
  return der.subarray(SPKI_PREFIX.length).toString("base64");
}

export function keyId(publicKey) {
  return crypto
    .createHash("sha256")
    .update(Buffer.from(publicKey, "base64"))
    .digest("hex")
    .slice(0, 16);
}

/** Ed25519 over the raw sha256 of the file, base64, like termix-plugin sign. */
function sign(buffer, privateKey) {
  const digest = crypto.createHash("sha256").update(buffer).digest();
  return crypto.sign(null, digest, privateKey).toString("base64");
}

function verify(buffer, signature, publicKey) {
  const digest = crypto.createHash("sha256").update(buffer).digest();
  const key = crypto.createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, Buffer.from(publicKey, "base64")]),
    format: "der",
    type: "spki",
  });
  try {
    return crypto.verify(null, digest, key, Buffer.from(signature, "base64"));
  } catch {
    return false;
  }
}

/** "^1.2" or ">=1.0.0" to "1". */
export function apiMajor(range) {
  const match = /(\d+)/.exec(String(range ?? ""));
  return match ? match[1] : "1";
}

function compareVersions(a, b) {
  const parse = (v) => {
    const [core, pre] = v.split("-", 2);
    return { nums: core.split(".").map(Number), pre: pre ?? null };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < 3; i++) {
    if (x.nums[i] !== y.nums[i]) return x.nums[i] - y.nums[i];
  }
  if (x.pre === y.pre) return 0;
  if (x.pre === null) return 1;
  if (y.pre === null) return -1;
  const xs = x.pre.split(".");
  const ys = y.pre.split(".");
  for (let i = 0; i < Math.max(xs.length, ys.length); i++) {
    if (xs[i] === undefined) return -1;
    if (ys[i] === undefined) return 1;
    const xn = Number(xs[i]);
    const yn = Number(ys[i]);
    if (!Number.isNaN(xn) && !Number.isNaN(yn) && xn !== yn) return xn - yn;
    if (xs[i] !== ys[i]) return xs[i] < ys[i] ? -1 : 1;
  }
  return 0;
}

/**
 * The registry index for one plugin.
 *
 * releases: GitHub release objects. download(url) gives a Buffer;
 * readManifest(tag) gives the manifest.json at that tag. Both are injected
 * so the logic can run without GitHub.
 *
 * With uploadSignature(release, name, text), a release that has a .tmxplug
 * but no .sig is signed here and the .sig is attached to it, so a release
 * built without the key still gets listed.
 */
export async function buildIndex({
  releases,
  download,
  readManifest,
  signingKey,
  repository,
  uploadSignature,
  log = console.log,
  now = new Date(),
}) {
  const privateKey = loadPrivateKey(signingKey);
  const publicKey = publicKeyFromPrivate(signingKey);
  const entries = [];

  for (const release of releases) {
    if (release.draft) continue;
    const tag = release.tag_name;
    const version = String(tag).replace(/^v/, "");
    const plug = release.assets.find((a) => a.name.endsWith(".tmxplug"));
    const sig = release.assets.find((a) => a.name.endsWith(".tmxplug.sig"));
    if (!plug || (!sig && !uploadSignature)) {
      log(`skip ${tag}: no signed .tmxplug`);
      continue;
    }
    const buffer = await download(plug.browser_download_url);
    let signature;
    if (sig) {
      signature = (await download(sig.browser_download_url))
        .toString("utf8")
        .trim();
    } else {
      signature = sign(buffer, privateKey);
      await uploadSignature(release, `${plug.name}.sig`, `${signature}\n`);
      log(`sign ${tag}: attached ${plug.name}.sig`);
    }
    if (!verify(buffer, signature, publicKey)) {
      log(`skip ${tag}: not signed with this registry's key`);
      continue;
    }
    const manifest = await readManifest(tag);
    entries.push({
      manifest,
      prerelease: !!release.prerelease || version.includes("-"),
      version: {
        version,
        api: apiMajor(manifest.engine?.api),
        url: plug.browser_download_url,
        sha256: crypto.createHash("sha256").update(buffer).digest("hex"),
        signature,
        size: buffer.length,
        capabilities: [...new Set(manifest.capabilities ?? [])],
        ...(manifest.dependencies && Object.keys(manifest.dependencies).length
          ? { dependencies: manifest.dependencies }
          : {}),
        releaseNotesUrl: release.html_url,
        ...(release.body
          ? { notes: String(release.body).slice(0, 20000) }
          : {}),
        publishedAt: new Date(
          release.published_at ?? release.created_at ?? now,
        ).toISOString(),
      },
    });
    log(`list ${tag}`);
  }

  entries.sort((a, b) => compareVersions(b.version.version, a.version.version));
  const stable = entries.filter((e) => !e.prerelease);
  const newestStable = stable[0]?.version.version;
  const betas = entries.filter(
    (e) =>
      e.prerelease &&
      (!newestStable || compareVersions(e.version.version, newestStable) > 0),
  );

  const index = {
    $schema:
      "https://raw.githubusercontent.com/Termix-SSH/Termix-Registry/main/registry-index-schema.json",
    registry: "",
    name: "",
    apiVersion: 1,
    publicKey,
    updatedAt: now.toISOString(),
    plugins: [],
  };

  const latest = entries[0]?.manifest;
  if (latest) {
    index.registry = latest.id;
    index.name = latest.name;
    const author =
      typeof latest.author === "string" ? latest.author : latest.author?.name;
    index.plugins.push({
      id: latest.id,
      name: latest.name,
      description: String(latest.description ?? "").slice(0, 500),
      author: author || repository.split("/")[0],
      category: latest.category,
      repository: latest.repository || `https://github.com/${repository}`,
      icon: latest.icon,
      ...(latest.video ? { video: latest.video } : {}),
      ...(latest.features?.length
        ? { features: latest.features.slice(0, 20) }
        : {}),
      ...(latest.docs ? { docs: latest.docs } : {}),
      versions: stable.map((e) => e.version),
      ...(betas.length ? { prereleases: betas.map((e) => e.version) } : {}),
    });
  } else {
    const [owner, repo] = repository.split("/");
    index.registry = repo.toLowerCase().replace(/[^a-z0-9-]/g, "-");
    index.name = `${owner}/${repo}`;
  }
  return index;
}

async function main() {
  const out = process.argv.slice(2).find((arg) => !arg.startsWith("--"));
  if (!out) throw new Error("Pass the file to write, like registry/index.json");
  const repository = process.env.GITHUB_REPOSITORY;
  if (!repository) throw new Error("GITHUB_REPOSITORY is not set");
  const headers = {
    Accept: "application/vnd.github+json",
    "User-Agent": "termix-registry-builder",
    ...(process.env.GH_TOKEN
      ? { Authorization: `Bearer ${process.env.GH_TOKEN}` }
      : {}),
  };

  const get = async (url, extra = {}) => {
    const response = await fetch(url, { headers: { ...headers, ...extra } });
    if (!response.ok) throw new Error(`${response.status} for ${url}`);
    return response;
  };

  const releases = [];
  for (let page = 1; page <= 10; page++) {
    const batch = await (
      await get(
        `https://api.github.com/repos/${repository}/releases?per_page=100&page=${page}`,
      )
    ).json();
    releases.push(...batch);
    if (batch.length < 100) break;
  }

  const index = await buildIndex({
    releases,
    repository,
    signingKey: process.env.TERMIX_PLUGIN_SIGNING_KEY,
    uploadSignature: process.argv.includes("--sign-missing")
      ? async (release, name, text) => {
          const response = await fetch(
            `https://uploads.github.com/repos/${repository}/releases/${release.id}/assets?name=${encodeURIComponent(name)}`,
            {
              method: "POST",
              headers: { ...headers, "Content-Type": "text/plain" },
              body: text,
            },
          );
          if (!response.ok) {
            throw new Error(
              `${response.status} attaching ${name} to ${release.tag_name}`,
            );
          }
        }
      : undefined,
    download: async (url) =>
      Buffer.from(
        await (
          await get(url, { Accept: "application/octet-stream" })
        ).arrayBuffer(),
      ),
    readManifest: async (tag) =>
      JSON.parse(
        Buffer.from(
          (
            await (
              await get(
                `https://api.github.com/repos/${repository}/contents/manifest.json?ref=${encodeURIComponent(tag)}`,
              )
            ).json()
          ).content,
          "base64",
        ).toString("utf8"),
      ),
  });

  fs.mkdirSync(path.dirname(path.resolve(out)), { recursive: true });
  fs.writeFileSync(out, `${JSON.stringify(index, null, 2)}\n`);
  const count = index.plugins[0]
    ? index.plugins[0].versions.length +
      (index.plugins[0].prereleases?.length ?? 0)
    : 0;
  console.log(
    `wrote ${out}: ${count} version(s), key id ${keyId(index.publicKey)}`,
  );
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((error) => {
    console.error(error.message);
    process.exit(1);
  });
}
