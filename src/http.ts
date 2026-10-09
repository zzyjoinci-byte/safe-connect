import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { hexd, timingSafeEqual } from "./bytes.js";
import type { Broker } from "./broker.js";
import { VERSION } from "./config.js";
import { logError } from "./logger.js";
import { ControlledSessions, PUBLIC_SESSION, SessionError, type SessionView } from "./sessions.js";
import type { CryptoGrant, Grade, SealedItem } from "./types.js";

const RequestLoginSchema = z.object({
  purpose: z.string().min(1),
  url: z.string().url(),
  item_id: z.string().min(1).optional(),
  grade: z.enum(["L0", "L1"]).optional(),
  ttl_seconds: z.number().int().positive().max(300).optional(),
});

const GrantSchema = z.object({
  request_id: z.string().min(1),
  url: z.string().min(1),
  expires_at: z.number().int().positive(),
  nonce: z.string().min(1),
  ciphertext: z.string().min(1),
});

const DenySchema = z.object({
  request_id: z.string().min(1),
});

const SealedItemSchema = z.object({
  id: z.string().min(1).optional(),
  label: z.string().min(1),
  origin: z.string().min(1),
  grade: z.enum(["L0", "L1"]),
  sealed: z.object({
    nonce: z.string().min(1),
    ciphertext: z.string().min(1),
    sealed_dek: z.string().min(1),
  }),
});

const AdminItemSchema = z.object({
  grade: z.enum(["L0", "L1"]),
  label: z.string().min(1),
  url: z.string().url(),
  username: z.string().min(1),
  password: z.string().min(1),
});

export interface HttpOptions {
  broker: Broker;
  pairingKey?: Uint8Array;
  adminToken?: Uint8Array;
  bind: string;
  port: number;
  /** Trusted integration. `serve` supplies built-in profiles unless SAFE_CONNECT_SESSIONS=0. */
  sessions?: ControlledSessions;
}

function exampleLoginPath(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(here, "..", "examples", "login.html");
}

async function readBody(req: http.IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    if (chunks.reduce((n, c) => n + c.length, 0) > 1_000_000) {
      throw new Error("body too large");
    }
  }
  return Buffer.concat(chunks).toString("utf8");
}

function send(res: http.ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-safe-connect-version": VERSION,
  });
  res.end(json);
}

function sendText(res: http.ServerResponse, status: number, type: string, body: string | Buffer): void {
  res.writeHead(status, {
    "content-type": type,
    "cache-control": "no-store",
  });
  res.end(body);
}

function bearerHex(req: http.IncomingMessage, expected?: Uint8Array): boolean {
  if (!expected) return false;
  const header = req.headers.authorization ?? "";
  const prefix = "Bearer ";
  if (!header.startsWith(prefix)) return false;
  try {
    const provided = hexd(header.slice(prefix.length).trim());
    return timingSafeEqual(provided, expected);
  } catch {
    return false;
  }
}

function publicRequest(view: { request_id: string; status: string; error?: string }) {
  return {
    request_id: view.request_id,
    status: view.status,
    ...(view.error ? { error: view.error } : {}),
  };
}

function publicSessionView(view: SessionView & { control_token: string }): SessionView {
  const { control_token: _ignored, ...rest } = view;
  return rest;
}

async function dispatchSession(
  res: http.ServerResponse,
  req: http.IncomingMessage,
  method: string,
  sessions: ControlledSessions | undefined,
  id: string | undefined,
  action: string | undefined,
  token: string | null,
  opts: { public: boolean },
): Promise<void> {
  if (!sessions) { send(res, 503, { error: "sessions_not_configured" }); return; }
  try {
    if (method === "GET" && id && !action) { send(res, 200, sessions.status(id, token)); return; }
    if (method !== "POST") { send(res, 405, { error: "method_not_allowed" }); return; }
    let body: unknown;
    try { body = JSON.parse(await readBody(req) || "{}"); }
    catch { send(res, 400, { error: "invalid_request" }); return; }
    if (!id) {
      const parsed = z.object({ profile_id: z.string().min(1).max(64) }).strict().safeParse(body);
      if (!parsed.success) { send(res, 400, { error: "invalid_request" }); return; }
      const created = await sessions.create(parsed.data.profile_id);
      send(res, 201, opts.public ? publicSessionView(created) : created);
      return;
    }
    if (action === "credentials") {
      const parsed = z.object({ revision: z.number().int().nonnegative(), item_id: z.string().min(1), grade: z.enum(["L0", "L1"]).optional() }).strict().safeParse(body);
      if (!parsed.success) { send(res, 400, { error: "invalid_request" }); return; }
      send(res, 200, await sessions.credentials(id, token, parsed.data.revision, parsed.data.item_id, parsed.data.grade));
      return;
    }
    if (action === "continue") {
      const parsed = z.object({ revision: z.number().int().nonnegative() }).strict().safeParse(body);
      if (!parsed.success) { send(res, 400, { error: "invalid_request" }); return; }
      send(res, 200, await sessions.continue(id, token, parsed.data.revision));
      return;
    }
    if (action === "cancel") {
      if (!z.object({}).strict().safeParse(body).success) { send(res, 400, { error: "invalid_request" }); return; }
      send(res, 200, await sessions.cancel(id, token));
      return;
    }
    send(res, 404, { error: "not_found" });
  } catch (err) {
    // Do not log browser errors, page data, control tokens, or request bodies.
    send(res, err instanceof SessionError ? err.status : 500, { error: err instanceof SessionError ? err.code : "session_operation_failed" });
  }
}

export function createHttpServer(opts: HttpOptions): http.Server {
  const { broker, pairingKey, adminToken } = opts;
  const server = http.createServer(async (req, res) => {
    try {
      const host = req.headers.host ?? "127.0.0.1";
      const url = new URL(req.url ?? "/", `http://${host}`);
      const method = req.method ?? "GET";

      if (method === "GET" && url.pathname === "/v1/session_profiles") {
        if (!opts.sessions) { send(res, 503, { error: "sessions_not_configured" }); return; }
        send(res, 200, { profiles: opts.sessions.listProfiles() });
        return;
      }

      const publicSession = url.pathname.match(/^\/v1\/sessions(?:\/([^/]+)(?:\/(credentials|continue|cancel))?)?$/);
      if (publicSession) {
        await dispatchSession(res, req, method, opts.sessions, publicSession[1], publicSession[2], PUBLIC_SESSION, { public: true });
        return;
      }

      const sessionRoute = url.pathname.match(/^\/v1\/(admin|companion)\/sessions(?:\/([^/]+)(?:\/(credentials|continue|cancel))?)?$/);
      if (sessionRoute) {
        const scope = broker.mode === "cloud" ? "companion" : "admin";
        if (sessionRoute[1] !== scope) { send(res, 404, { error: "not_found" }); return; }
        if (!bearerHex(req, scope === "companion" ? pairingKey : adminToken)) { send(res, 401, { error: "unauthorized" }); return; }
        // Operator-to-broker calls only. No browser-origin API/CORS credential relay.
        if (req.headers.origin) { send(res, 403, { error: "browser_origin_forbidden" }); return; }
        const token = typeof req.headers["x-safe-connect-session"] === "string" ? req.headers["x-safe-connect-session"] : "";
        await dispatchSession(res, req, method, opts.sessions, sessionRoute[2], sessionRoute[3], token, { public: false });
        return;
      }

      if (method === "GET" && url.pathname === "/v1/health") {
        const h = broker.health();
        send(res, h.httpStatus, h.body);
        return;
      }

      if (method === "GET" && (url.pathname === "/example/login.html" || url.pathname === "/example/login")) {
        const file = exampleLoginPath();
        if (!fs.existsSync(file)) {
          send(res, 404, { error: "example_missing" });
          return;
        }
        sendText(res, 200, "text/html; charset=utf-8", fs.readFileSync(file));
        return;
      }

      if (method === "POST" && url.pathname === "/v1/request_browser_login") {
        const raw = await readBody(req);
        const parsed = RequestLoginSchema.safeParse(raw ? JSON.parse(raw) : {});
        if (!parsed.success) {
          send(res, 400, { error: "invalid_request" });
          return;
        }
        if (broker.mode === "cloud" && broker.companionStatus() !== "paired") {
          send(res, 503, {
            request_id: null,
            status: "denied",
            error: "companion_missing",
          });
          return;
        }
        const view = await broker.requestBrowserLogin(parsed.data);
        send(res, 200, publicRequest(view));
        return;
      }

      const reqMatch = url.pathname.match(/^\/v1\/requests\/([^/]+)$/);
      if (method === "GET" && reqMatch) {
        const id = decodeURIComponent(reqMatch[1] ?? "");
        send(res, 200, publicRequest(broker.getLoginStatus(id)));
        return;
      }

      if (url.pathname.startsWith("/v1/companion/")) {
        if (!bearerHex(req, pairingKey)) {
          send(res, 401, { error: "unauthorized" });
          return;
        }
        if (method === "POST" && url.pathname === "/v1/companion/heartbeat") {
          const raw = await readBody(req);
          let pub: Uint8Array | undefined;
          if (raw) {
            try {
              const body = JSON.parse(raw) as { public_key?: string };
              if (body.public_key) pub = hexd(body.public_key);
            } catch {
              send(res, 400, { error: "invalid_request" });
              return;
            }
          }
          try {
            broker.heartbeat(pub);
          } catch {
            send(res, 403, { error: "companion_mismatch" });
            return;
          }
          send(res, 200, { ok: true, companion: "paired" });
          return;
        }
        if (method === "GET" && url.pathname === "/v1/companion/challenges") {
          const challenges = broker.pullChallenges().map((c) => ({
            request_id: c.request_id,
            url: c.url,
            purpose: c.purpose,
            grade: c.grade,
            expires_in: c.expires_in,
            confirm_code: c.confirm_code,
            sealed_dek: c.sealed_dek,
            ...(c.session_id ? { session_id: c.session_id } : {}),
          }));
          send(res, 200, { challenges });
          return;
        }
        if (method === "POST" && url.pathname === "/v1/companion/grant") {
          const raw = await readBody(req);
          const parsed = GrantSchema.safeParse(raw ? JSON.parse(raw) : {});
          if (!parsed.success) {
            send(res, 400, { error: "invalid_request" });
            return;
          }
          const grant: CryptoGrant = parsed.data;
          send(res, 200, publicRequest(broker.applyGrant(grant)));
          return;
        }
        if (method === "POST" && url.pathname === "/v1/companion/deny") {
          const raw = await readBody(req);
          const parsed = DenySchema.safeParse(raw ? JSON.parse(raw) : {});
          if (!parsed.success) {
            send(res, 400, { error: "invalid_request" });
            return;
          }
          send(res, 200, publicRequest(broker.deny(parsed.data.request_id)));
          return;
        }
        if (method === "POST" && url.pathname === "/v1/companion/items") {
          const raw = await readBody(req);
          const parsed = SealedItemSchema.safeParse(raw ? JSON.parse(raw) : {});
          if (!parsed.success) {
            send(res, 400, { error: "invalid_request" });
            return;
          }
          const data = parsed.data;
          const item: SealedItem = {
            id: data.id ?? crypto.randomUUID(),
            label: data.label,
            origin: data.origin,
            grade: data.grade as Grade,
            sealed: data.sealed,
          };
          const pub = broker.addSealedItem(item);
          send(res, 200, pub);
          return;
        }
        if (method === "GET" && url.pathname === "/v1/companion/items") {
          send(res, 200, { items: broker.listItems() });
          return;
        }
        send(res, 404, { error: "not_found" });
        return;
      }

      if (url.pathname.startsWith("/v1/admin/")) {
        if (broker.mode !== "local") {
          send(res, 404, { error: "not_found" });
          return;
        }
        if (!bearerHex(req, adminToken)) {
          send(res, 401, { error: "unauthorized" });
          return;
        }
        if (method === "GET" && url.pathname === "/v1/admin/items") {
          send(res, 200, { items: broker.listItems() });
          return;
        }
        if (method === "POST" && url.pathname === "/v1/admin/items") {
          const raw = await readBody(req);
          const parsed = AdminItemSchema.safeParse(raw ? JSON.parse(raw) : {});
          if (!parsed.success) {
            send(res, 400, { error: "invalid_request" });
            return;
          }
          const origin = new URL(parsed.data.url).origin;
          const pub =
            parsed.data.grade === "L0"
              ? broker.addLocalL0({
                  label: parsed.data.label,
                  origin,
                  username: parsed.data.username,
                  password: parsed.data.password,
                })
              : await broker.addLocalL1({
                  label: parsed.data.label,
                  origin,
                  username: parsed.data.username,
                  password: parsed.data.password,
                });
          send(res, 200, pub);
          return;
        }
        send(res, 404, { error: "not_found" });
        return;
      }

      send(res, 404, { error: "not_found" });
    } catch (err) {
      logError(err instanceof Error ? err.message : "internal");
      send(res, 500, { error: "internal" });
    }
  });

  return server;
}

export async function listen(server: http.Server, bind: string, port: number): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.listen(port, bind, () => resolve());
    server.on("error", reject);
  });
  const addr = server.address();
  if (addr && typeof addr === "object") return addr.port;
  return port;
}
