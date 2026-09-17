#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { writeAdminToken, readAdminToken, adminTokenPath } from "./admin-token.js";
import { hexe } from "./bytes.js";
import { Broker } from "./broker.js";
import { loadConfig, VERSION, type AppConfig } from "./config.js";
import { cryptoReady } from "./crypto.js";
import { playwrightFill, shutdownFillers } from "./fill.js";
import { createGrant } from "./grants.js";
import { createHttpServer, listen } from "./http.js";
import { logError, logInfo } from "./logger.js";
import { httpBackend, serveMcpStdio } from "./mcp.js";
import { generatePairing, readCompanionFile, writeCompanionFile } from "./pairing.js";
import { promptLine, promptSecret } from "./prompt.js";
import type { Grade, UnwrapChallenge } from "./types.js";
import { CloudVault, LocalVault, originOf, sealCredential } from "./vault.js";

interface Flags {
  command: string;
  rest: string[];
  mode?: "local" | "cloud";
  grade?: Grade;
  label?: string;
  url?: string;
  username?: string;
  password?: string;
  passphrase?: string;
  home?: string;
  port?: number;
  itemId?: string;
  yes: boolean;
  help: boolean;
}

function parseArgs(argv: string[]): Flags {
  const [command = "help", ...tail] = argv;
  const flags: Flags = { command, rest: [], yes: false, help: false };
  for (let i = 0; i < tail.length; i++) {
    const a = tail[i] ?? "";
    const next = () => tail[++i] ?? "";
    switch (a) {
      case "--mode":
        flags.mode = next() as "local" | "cloud";
        break;
      case "--grade":
        flags.grade = next() as Grade;
        break;
      case "--label":
        flags.label = next();
        break;
      case "--url":
        flags.url = next();
        break;
      case "--username":
        flags.username = next();
        break;
      case "--password":
        flags.password = next();
        break;
      case "--passphrase":
        flags.passphrase = next();
        break;
      case "--home":
        flags.home = next();
        break;
      case "--port":
        flags.port = Number(next());
        break;
      case "--item-id":
        flags.itemId = next();
        break;
      case "--yes":
      case "-y":
        flags.yes = true;
        break;
      case "--help":
      case "-h":
        flags.help = true;
        break;
      default:
        flags.rest.push(a);
    }
  }
  return flags;
}

function help(): string {
  return `safe-connect ${VERSION} — credential broker for AI agents

Usage:
  safe-connect init [--mode local|cloud] [--home DIR]
  safe-connect serve [--mode local|cloud] [--port N]
  safe-connect mcp
  safe-connect companion [--yes]
  safe-connect add --grade L0|L1 --label NAME --url URL --username USER
  safe-connect list

Modes:
  local   Vault on this machine. Agents call this broker. No cloud required.
  cloud   Broker on a server. HARD-REQUIRES a paired local companion.
          Cloud-only without companion is unsupported (health 503).

Agent API / MCP (never returns secrets — status only):
  POST /v1/request_browser_login
  GET  /v1/requests/:id
  MCP  request_browser_login / get_login_status

Environment: see .env.example
`;
}

function cfgFromFlags(flags: Flags): AppConfig {
  if (flags.home) process.env.SAFE_CONNECT_HOME = flags.home;
  if (flags.mode) process.env.SAFE_CONNECT_MODE = flags.mode;
  if (flags.port) process.env.SAFE_CONNECT_PORT = String(flags.port);
  return loadConfig();
}

async function cmdInit(flags: Flags): Promise<void> {
  const cfg = cfgFromFlags(flags);
  fs.mkdirSync(cfg.home, { recursive: true });
  fs.chmodSync(cfg.home, 0o700);
  const mode = flags.mode ?? cfg.mode;
  if (mode === "local") {
    if (fs.existsSync(cfg.vaultPath)) {
      throw new Error(`vault already exists at ${cfg.vaultPath}`);
    }
    const pass = await promptSecret("Vault passphrase", flags.passphrase ?? cfg.passphrase);
    const confirm = flags.passphrase ?? cfg.passphrase ?? (await promptSecret("Confirm passphrase"));
    if (pass !== confirm) throw new Error("passphrases do not match");
    const vault = new LocalVault(cfg.vaultPath);
    await vault.init(pass);
    logInfo(`local vault created at ${cfg.vaultPath}`);
    return;
  }

  if (fs.existsSync(cfg.companionPath)) {
    throw new Error(`companion state already exists at ${cfg.companionPath}`);
  }
  const material = generatePairing();
  writeCompanionFile(cfg.companionPath, material);
  console.log(`Companion identity written to ${cfg.companionPath} (mode 0600)`);
  console.log("");
  console.log("Configure the CLOUD broker with:");
  console.log("  SAFE_CONNECT_MODE=cloud");
  console.log(`  SAFE_CONNECT_PAIRING_KEY=${hexe(material.pairingKey)}`);
  console.log(`  SAFE_CONNECT_COMPANION_PUBLIC_KEY=${hexe(material.publicKey)}`);
  console.log("");
  console.log("Keep companion.json on the local machine only.");
  console.log("Cloud-only deploy without this companion is unsupported.");
}

async function cmdServe(flags: Flags): Promise<void> {
  const cfg = cfgFromFlags(flags);
  const mode = flags.mode ?? cfg.mode;
  if (mode === "local") {
    const vault = new LocalVault(cfg.vaultPath);
    if (!fs.existsSync(cfg.vaultPath)) {
      throw new Error(`no vault at ${cfg.vaultPath} — run: safe-connect init --mode local`);
    }
    const pass = await promptSecret("Vault passphrase", flags.passphrase ?? cfg.passphrase);
    await vault.unlock(pass);
    const broker = new Broker({ mode: "local", filler: playwrightFill, localVault: vault });
    const adminToken = writeAdminToken(cfg.home);
    logInfo(`admin token written to ${adminTokenPath(cfg.home)} (localhost add/list)`);
    await runHttp(broker, cfg, { adminToken });
    return;
  }

  if (!cfg.pairingKey || !cfg.companionPublicKey) {
    throw new Error(
      "cloud mode requires SAFE_CONNECT_PAIRING_KEY and SAFE_CONNECT_COMPANION_PUBLIC_KEY (from companion init)",
    );
  }
  const cloudVault = new CloudVault(cfg.vaultPath);
  cloudVault.configure(cfg.pairingKey, cfg.companionPublicKey);
  const broker = new Broker({
    mode: "cloud",
    filler: playwrightFill,
    cloudVault,
    pairing: {
      pairingKey: cfg.pairingKey,
      publicKey: cfg.companionPublicKey,
    },
  });
  logInfo("cloud broker starting — fill requests fail closed until companion heartbeats");
  await runHttp(broker, cfg, { pairingKey: cfg.pairingKey });
}

async function runHttp(
  broker: Broker,
  cfg: AppConfig,
  extra: { pairingKey?: Uint8Array; adminToken?: Uint8Array },
): Promise<void> {
  const server = createHttpServer({
    broker,
    pairingKey: extra.pairingKey,
    adminToken: extra.adminToken,
    bind: cfg.bind,
    port: cfg.port,
  });
  const port = await listen(server, cfg.bind, cfg.port);
  logInfo(`listening on http://${cfg.bind}:${port}`);
  logInfo(`example login page: http://${cfg.bind}:${port}/example/login.html`);
  const stop = async () => {
    server.close();
    await shutdownFillers();
    process.exit(0);
  };
  process.on("SIGINT", () => void stop());
  process.on("SIGTERM", () => void stop());
  await new Promise(() => undefined);
}

async function cmdMcp(flags: Flags): Promise<void> {
  const cfg = cfgFromFlags(flags);
  const base = process.env.SAFE_CONNECT_URL ?? `http://${cfg.bind}:${cfg.port}`;
  logInfo(`MCP stdio proxying to ${base} (tools never return secrets)`);
  await serveMcpStdio(httpBackend(base));
}

async function cmdCompanion(flags: Flags): Promise<void> {
  const cfg = cfgFromFlags(flags);
  const material = readCompanionFile(cfg.companionPath);
  if (!material.privateKey) throw new Error("companion private key missing");
  const base = cfg.cloudUrl.replace(/\/$/, "");
  const auth = { Authorization: `Bearer ${hexe(material.pairingKey)}` };
  logInfo(`companion polling ${base} — approve unwrap grants in this terminal`);
  const handled = new Set<string>();
  const tick = async () => {
    const hb = await fetch(`${base}/v1/companion/heartbeat`, {
      method: "POST",
      headers: { ...auth, "content-type": "application/json" },
      body: JSON.stringify({ public_key: hexe(material.publicKey) }),
    });
    if (!hb.ok) {
      logError(`heartbeat ${hb.status}`);
      return;
    }
    const chRes = await fetch(`${base}/v1/companion/challenges`, { headers: auth });
    if (!chRes.ok) return;
    const body = (await chRes.json()) as { challenges: UnwrapChallenge[] };
    for (const ch of body.challenges ?? []) {
      if (handled.has(ch.request_id)) continue;
      handled.add(ch.request_id);
      const approved = await approveChallenge(ch, flags.yes || cfg.autoApprove);
      if (!approved) {
        await fetch(`${base}/v1/companion/deny`, {
          method: "POST",
          headers: { ...auth, "content-type": "application/json" },
          body: JSON.stringify({ request_id: ch.request_id }),
        });
        continue;
      }
      if (!material.privateKey) throw new Error("companion private key missing");
      const grant = createGrant({
        pairingKey: material.pairingKey,
        publicKey: material.publicKey,
        privateKey: material.privateKey,
        sealedDekB64: ch.sealed_dek,
        requestId: ch.request_id,
        url: ch.url,
        ttlMs: Math.min(ch.expires_in * 1000, 30_000),
      });
      await fetch(`${base}/v1/companion/grant`, {
        method: "POST",
        headers: { ...auth, "content-type": "application/json" },
        body: JSON.stringify(grant),
      });
      logInfo(`grant sent for ${ch.request_id}`);
    }
  };
  await tick();
  setInterval(() => void tick().catch((e) => logError(String(e))), 800);
  await new Promise(() => undefined);
}

async function approveChallenge(ch: UnwrapChallenge, auto: boolean): Promise<boolean> {
  console.log("");
  console.log("=== Safe Connect unwrap challenge ===");
  console.log(`request_id : ${ch.request_id}`);
  console.log(`url        : ${ch.url}`);
  console.log(`purpose    : ${ch.purpose}`);
  console.log(`grade      : ${ch.grade}`);
  console.log(`expires_in : ${ch.expires_in}s`);
  console.log(`confirm    : ${ch.confirm_code}  (UX only; security is the crypto grant)`);
  console.log("=====================================");
  if (auto) {
    logInfo("AUTO_APPROVE enabled — emitting one-time grant");
    return true;
  }
  if (!process.stdin.isTTY) {
    logError("no TTY to approve grant; deny");
    return false;
  }
  const answer = await promptLine("Type the confirm code to approve, or n to deny: ");
  if (answer.toLowerCase() === "n" || answer.toLowerCase() === "no") return false;
  return answer === ch.confirm_code;
}

async function cmdAdd(flags: Flags): Promise<void> {
  const cfg = cfgFromFlags(flags);
  const grade = flags.grade;
  if (grade !== "L0" && grade !== "L1") throw new Error("--grade L0|L1 required");
  const label = flags.label ?? (await promptLine("Label: "));
  const url = flags.url ?? (await promptLine("Login URL: "));
  const username = flags.username ?? (await promptLine("Username: "));
  const password = flags.password ?? (await promptSecret("Password"));
  const origin = originOf(url);
  const mode = flags.mode ?? inferAddMode(cfg);

  if (mode === "local") {
    if (grade === "L0" || fs.existsSync(adminTokenPath(cfg.home))) {
      const token = hexe(readAdminToken(cfg.home));
      const res = await fetch(`http://${cfg.bind}:${cfg.port}/v1/admin/items`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ grade, label, url, username, password }),
      });
      if (!res.ok) throw new Error(`local add failed: HTTP ${res.status} (is serve running?)`);
      console.log(JSON.stringify(await res.json()));
      return;
    }
    if (grade === "L1") {
      const vault = new LocalVault(cfg.vaultPath);
      if (!fs.existsSync(cfg.vaultPath)) throw new Error("run safe-connect init --mode local first");
      const pass = await promptSecret("Vault passphrase", flags.passphrase ?? cfg.passphrase);
      await vault.unlock(pass);
      const item = await vault.addL1({ label, origin, username, password });
      console.log(JSON.stringify(item));
      logInfo("added to vault file — restart serve if it is already running");
      return;
    }
  }

  const material = readCompanionFile(cfg.companionPath);
  const sealed = sealCredential(material.publicKey, { username, password });
  const id = crypto.randomUUID();
  const res = await fetch(`${cfg.cloudUrl.replace(/\/$/, "")}/v1/companion/items`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${hexe(material.pairingKey)}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ id, label, origin, grade, sealed }),
  });
  if (!res.ok) throw new Error(`cloud add failed: HTTP ${res.status}`);
  console.log(JSON.stringify(await res.json()));
}

async function cmdList(flags: Flags): Promise<void> {
  const cfg = cfgFromFlags(flags);
  const mode = flags.mode ?? inferAddMode(cfg);
  if (mode === "cloud" || (fs.existsSync(cfg.companionPath) && !fs.existsSync(cfg.vaultPath))) {
    const material = readCompanionFile(cfg.companionPath);
    const res = await fetch(`${cfg.cloudUrl.replace(/\/$/, "")}/v1/companion/items`, {
      headers: { Authorization: `Bearer ${hexe(material.pairingKey)}` },
    });
    if (!res.ok) throw new Error(`list failed: HTTP ${res.status}`);
    console.log(JSON.stringify(await res.json(), null, 2));
    return;
  }
  if (fs.existsSync(adminTokenPath(cfg.home))) {
    try {
      const token = hexe(readAdminToken(cfg.home));
      const res = await fetch(`http://${cfg.bind}:${cfg.port}/v1/admin/items`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        console.log(JSON.stringify(await res.json(), null, 2));
        return;
      }
    } catch {
      // fall through to vault file
    }
  }
  const vault = new LocalVault(cfg.vaultPath);
  const pass = await promptSecret("Vault passphrase", flags.passphrase ?? cfg.passphrase);
  await vault.unlock(pass);
  console.log(JSON.stringify({ items: vault.list() }, null, 2));
}

function inferAddMode(cfg: AppConfig): "local" | "cloud" {
  if (cfg.mode === "cloud") return "cloud";
  if (fs.existsSync(cfg.companionPath) && !fs.existsSync(cfg.vaultPath)) return "cloud";
  return "local";
}

export async function main(argv = process.argv.slice(2)): Promise<void> {
  await cryptoReady();
  const flags = parseArgs(argv);
  if (flags.help || flags.command === "help" || flags.command === "--help") {
    console.log(help());
    return;
  }
  switch (flags.command) {
    case "init":
      await cmdInit(flags);
      break;
    case "serve":
      await cmdServe(flags);
      break;
    case "mcp":
      await cmdMcp(flags);
      break;
    case "companion":
      await cmdCompanion(flags);
      break;
    case "add":
      await cmdAdd(flags);
      break;
    case "list":
      await cmdList(flags);
      break;
    case "version":
      console.log(VERSION);
      break;
    default:
      console.log(help());
      process.exitCode = 1;
  }
}

const invoked = process.argv[1] ? path.basename(process.argv[1]) : "";
if (invoked === "cli.js" || invoked === "cli.ts" || invoked === "safe-connect") {
  main().catch((err) => {
    logError(err instanceof Error ? err.message : "fatal");
    process.exit(1);
  });
}
