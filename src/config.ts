import os from "node:os";
import path from "node:path";
import { hexd } from "./bytes.js";
import type { Mode } from "./types.js";

export const VERSION = "0.1.0";
export const GRANT_TTL_MS = 30_000;
export const HEARTBEAT_STALE_MS = 10_000;
export const DEFAULT_PORT = 8787;
export const SESSION_TIMEOUT_MAX_MS = 10 * 60_000;
export const SESSION_TIMEOUT_DEFAULT_MS = 5 * 60_000;
export const SESSION_TIMEOUT_HEADED_MS = 10 * 60_000;

export function headedEnabled(): boolean {
  return process.env.SAFE_CONNECT_HEADED === "1";
}

export function sessionsEnabled(): boolean {
  return process.env.SAFE_CONNECT_SESSIONS !== "0";
}

export function sessionTimeoutMs(): number {
  const fallback = headedEnabled() ? SESSION_TIMEOUT_HEADED_MS : SESSION_TIMEOUT_DEFAULT_MS;
  const raw = process.env.SAFE_CONNECT_SESSION_TIMEOUT_MS;
  const n = raw ? Number(raw) : fallback;
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(n, SESSION_TIMEOUT_MAX_MS);
}

export interface AppConfig {
  mode: Mode;
  port: number;
  bind: string;
  home: string;
  vaultPath: string;
  companionPath: string;
  pairingKey?: Uint8Array;
  companionPublicKey?: Uint8Array;
  cloudUrl: string;
  autoApprove: boolean;
  passphrase?: string;
}

function parseMode(raw: string | undefined): Mode {
  const mode = (raw ?? "local").trim().toLowerCase();
  if (mode !== "local" && mode !== "cloud") {
    throw new Error("SAFE_CONNECT_MODE must be local or cloud");
  }
  return mode;
}

export function loadConfig(overrides: Partial<AppConfig> = {}): AppConfig {
  const mode = overrides.mode ?? parseMode(process.env.SAFE_CONNECT_MODE);
  const home =
    overrides.home ??
    process.env.SAFE_CONNECT_HOME ??
    path.join(os.homedir(), ".safe-connect");
  const pairingHex = process.env.SAFE_CONNECT_PAIRING_KEY;
  const pubHex = process.env.SAFE_CONNECT_COMPANION_PUBLIC_KEY;
  return {
    mode,
    port: overrides.port ?? Number(process.env.SAFE_CONNECT_PORT ?? DEFAULT_PORT),
    bind: overrides.bind ?? process.env.SAFE_CONNECT_BIND ?? "127.0.0.1",
    home,
    vaultPath:
      overrides.vaultPath ??
      process.env.SAFE_CONNECT_VAULT_PATH ??
      path.join(home, mode === "cloud" ? "cloud-vault.sc" : "vault.sc"),
    companionPath: overrides.companionPath ?? path.join(home, "companion.json"),
    pairingKey: overrides.pairingKey ?? (pairingHex ? hexd(pairingHex) : undefined),
    companionPublicKey: overrides.companionPublicKey ?? (pubHex ? hexd(pubHex) : undefined),
    cloudUrl: overrides.cloudUrl ?? process.env.SAFE_CONNECT_CLOUD_URL ?? "http://127.0.0.1:8787",
    autoApprove:
      overrides.autoApprove ??
      (process.env.SAFE_CONNECT_AUTO_APPROVE === "1" ||
        process.env.SAFE_CONNECT_AUTO_APPROVE === "true"),
    passphrase: overrides.passphrase ?? process.env.SAFE_CONNECT_PASSPHRASE,
  };
}
