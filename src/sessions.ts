import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { chromium, type Browser, type BrowserContext, type CDPSession, type Page } from "playwright";
import type { Broker } from "./broker.js";
import { fillInput } from "./fill.js";
import type { Grade } from "./types.js";

export type SessionState = "opening" | "ready_for_credentials" | "awaiting_grant" | "filling"
  | "awaiting_user_submit" | "manual_required" | "authenticated" | "blocked" | "cancelled" | "expired";

/** Trusted server configuration, never accepted as selectors/origins from agent APIs. */
export interface LoginProfile {
  id: string;
  entryUrl: string;
  credentialOrigin: string;
  usernameSelector: string;
  passwordSelector: string;
  /** Optional username-only Next button. Never a final password/OTP submit button. */
  usernameNextSelector?: string;
  success: { origin: string; pathname: string; selector: string };
  manual?: Array<{ origin: string; selector: string; kind: "otp" | "captcha" | "passkey" }>;
}

export interface SessionView {
  session_id: string;
  profile_id: string;
  state: SessionState;
  revision: number;
  expires_at: number;
  request_id?: string;
  reason?: string;
  /** No browser handoff is implemented by these control APIs. */
  operator_surface: "unavailable";
}

interface RecordState {
  id: string;
  tokenHash: Buffer;
  profile: LoginProfile;
  origins: Set<string>;
  state: SessionState;
  revision: number;
  expiresAt: number;
  requestId?: string;
  reason?: string;
  credentialsFilled: boolean;
  credentialStarted: boolean;
  busy: boolean;
  context?: BrowserContext;
  page?: Page;
  timer?: ReturnType<typeof setTimeout>;
  grantTimer?: ReturnType<typeof setTimeout>;
  closing?: Promise<void>;
}

export class SessionError extends Error {
  constructor(readonly code: string, readonly status = 409) { super(code); }
}

export interface SessionOptions {
  broker: Broker;
  profiles: LoginProfile[];
  /** Trusted host integration/test seam. Never exposed as an HTTP option. */
  browserFactory?: () => Promise<Browser>;
  sessionTimeoutMs?: number;
  retentionMs?: number;
  maxSessions?: number;
}

const terminal = new Set<SessionState>(["blocked", "cancelled", "expired"]);
const hash = (token: string) => createHash("sha256").update(token).digest();

function origin(url: string): string {
  const parsed = new URL(url);
  if (parsed.username || parsed.password || parsed.hostname.includes("*") || (parsed.protocol !== "https:" &&
    !(parsed.protocol === "http:" && ["127.0.0.1", "[::1]", "localhost"].includes(parsed.hostname)))) {
    throw new SessionError("invalid_profile", 400);
  }
  return parsed.origin;
}

function exactOrigin(value: string): string {
  const normalized = origin(value);
  if (value !== normalized) throw new SessionError("invalid_profile", 400);
  return normalized;
}

export class ControlledSessions {
  private readonly profiles = new Map<string, LoginProfile>();
  private readonly records = new Map<string, RecordState>();
  private browser?: Promise<Browser>;
  private stopped = false;
  private readonly sessionTimeoutMs: number;
  private readonly retentionMs: number;
  private readonly maxSessions: number;
  private readonly watchdog: ReturnType<typeof setInterval>;

  constructor(private readonly options: SessionOptions) {
    this.sessionTimeoutMs = options.sessionTimeoutMs ?? 5 * 60_000;
    this.retentionMs = options.retentionMs ?? 60_000;
    this.maxSessions = options.maxSessions ?? 8;
    if (!(this.sessionTimeoutMs > 0 && this.sessionTimeoutMs <= 10 * 60_000) ||
      !(this.retentionMs > 0 && this.retentionMs <= 5 * 60_000) ||
      !Number.isInteger(this.maxSessions) || this.maxSessions < 1 || this.maxSessions > 32) {
      throw new SessionError("invalid_limits", 400);
    }
    for (const raw of options.profiles) {
      const p = structuredClone(raw);
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(p.id) || this.profiles.has(p.id)) throw new SessionError("invalid_profile", 400);
      origin(p.entryUrl);
      exactOrigin(p.credentialOrigin);
      exactOrigin(p.success.origin);
      if (!p.success.pathname.startsWith("/") || /[?#]/.test(p.success.pathname)) throw new SessionError("invalid_profile", 400);
      const selectors = [p.usernameSelector, p.passwordSelector, p.success.selector, p.usernameNextSelector ?? "x"];
      for (const m of p.manual ?? []) { exactOrigin(m.origin); selectors.push(m.selector); }
      if (selectors.some((s) => !s || s.length > 512)) throw new SessionError("invalid_profile", 400);
      this.profiles.set(p.id, p);
    }
    this.watchdog = setInterval(() => {
      for (const record of this.records.values()) this.guard(record);
    }, 250);
    this.watchdog.unref();
  }

  async create(profileId: string): Promise<SessionView & { control_token: string }> {
    if (this.stopped) throw new SessionError("sessions_closed", 503);
    this.requireCompanion();
    const profile = this.profiles.get(profileId);
    if (!profile) throw new SessionError("unknown_profile", 400);
    if ([...this.records.values()].filter((r) => !terminal.has(r.state)).length >= this.maxSessions) throw new SessionError("session_limit", 429);
    // Keep only bounded, secret-free terminal metadata, never browser storage.
    if (this.records.size >= 128) {
      const old = [...this.records.values()].find((r) => terminal.has(r.state));
      if (old) this.records.delete(old.id);
    }
    const token = randomBytes(32).toString("hex");
    const r: RecordState = {
      id: randomUUID(), tokenHash: hash(token), profile,
      origins: new Set([origin(profile.entryUrl), profile.credentialOrigin, profile.success.origin,
        ...(profile.manual ?? []).map((m) => m.origin)]),
      state: "opening", revision: 0, expiresAt: Date.now() + this.sessionTimeoutMs,
      credentialsFilled: false, credentialStarted: false, busy: false,
    };
    this.records.set(r.id, r);
    this.armExpiry(r);
    try {
      this.browser ??= (this.options.browserFactory ?? (() => chromium.launch({ headless: true })))();
      const b = await this.browser;
      this.ensureActive(r);
      const context = await b.newContext({ acceptDownloads: false, serviceWorkers: "block" });
      r.context = context;
      this.ensureActive(r);
      const page = await context.newPage();
      r.page = page;
      page.setDefaultTimeout(5_000);
      context.on("page", (other) => { if (other !== page) void this.end(r, "blocked", "popup_not_supported"); });
      page.on("close", () => { if (!terminal.has(r.state)) void this.end(r, "cancelled", "browser_closed"); });
      context.on("close", () => { if (!terminal.has(r.state)) void this.end(r, "cancelled", "browser_closed"); });
      page.on("download", (download) => { void download.cancel(); void this.end(r, "blocked", "download_not_supported"); });
      page.on("framenavigated", (frame) => {
        if (frame.url() === "about:blank") return;
        try {
          const current = origin(frame.url());
          if (!r.origins.has(current) || (r.state === "filling" && current !== profile.credentialOrigin)) {
            void this.end(r, "blocked", "origin_mismatch");
          }
        } catch { void this.end(r, "blocked", "origin_mismatch"); }
      });
      await context.route("**/*", async (route) => {
        try {
          if (terminal.has(r.state) || !r.origins.has(origin(route.request().url()))) {
            await route.abort();
            void this.end(r, "blocked", "origin_mismatch");
            return;
          }
          await route.continue();
        } catch { if (!terminal.has(r.state)) void this.end(r, "blocked", "navigation_failed"); }
      });
      await page.goto(profile.entryUrl, { waitUntil: "domcontentloaded", timeout: Math.min(15_000, this.sessionTimeoutMs) });
      this.ensureActive(r);
      if (origin(page.url()) !== profile.credentialOrigin) this.set(r, "manual_required", "credential_origin_not_reached");
      else if (!await this.manual(r)) this.set(r, "ready_for_credentials");
    } catch {
      if (!terminal.has(r.state)) await this.end(r, "blocked", "navigation_failed");
      else await r.context?.close().catch(() => undefined);
    }
    return { ...this.view(r), control_token: token };
  }

  status(id: string, token: string): SessionView {
    const r = this.get(id, token);
    this.guard(r);
    return this.view(r);
  }

  async credentials(id: string, token: string, revision: number, itemId: string, grade?: Grade): Promise<SessionView> {
    const r = this.lock(id, token, revision);
    try {
      if (r.state !== "ready_for_credentials" || r.credentialStarted) throw new SessionError("invalid_state");
      this.requireCompanion();
      this.checkCredentialOrigin(r);
      if (await this.manual(r)) return this.view(r);
      this.ensureActive(r);
      // Immutable association: this grant's request ID can fill only this context.
      r.credentialStarted = true;
      this.set(r, "awaiting_grant");
      const result = await this.options.broker.requestControlledLogin({
        purpose: `controlled-session:${r.profile.id}`, url: r.page!.url(), item_id: itemId, grade, ttl_seconds: 30,
      }, {
        sessionId: r.id,
        fill: async (request, username, password) => {
          r.requestId = request.request_id;
          let cdp: CDPSession | undefined;
          const expiresAt = Math.min(request.expires_at, r.expiresAt, Date.now() + 30_000);
          try {
            this.ensureActive(r);
            if (r.state !== "awaiting_grant" || origin(request.url) !== r.profile.credentialOrigin || Date.now() >= expiresAt) {
              throw new SessionError("grant_expired");
            }
            this.checkCredentialOrigin(r);
            this.set(r, "filling");
            r.grantTimer = setTimeout(() => { void this.end(r, "expired", "credential_deadline"); }, Math.max(1, expiresAt - Date.now()));
            r.grantTimer.unref();
            cdp = await r.context!.newCDPSession(r.page!);
            const user = r.page!.locator(r.profile.usernameSelector).first();
            await fillInput(cdp, user, r.profile.usernameSelector, username, r.profile.credentialOrigin, expiresAt);
            this.checkCredentialOrigin(r);
            const pass = r.page!.locator(r.profile.passwordSelector).first();
            if (r.profile.usernameNextSelector && !await pass.count()) {
              await this.nextUsername(r, cdp, expiresAt);
            }
            this.checkCredentialOrigin(r);
            if (await this.manual(r)) return { ok: false, error: "manual_required" };
            await fillInput(cdp, pass, r.profile.passwordSelector, password, r.profile.credentialOrigin, expiresAt);
            this.checkCredentialOrigin(r);
            r.credentialsFilled = true;
            this.set(r, "awaiting_user_submit", "operator_surface_unavailable");
            return { ok: true };
          } catch {
            if (!terminal.has(r.state)) {
              // Playwright's bounded wait can win the timer race by a few ms.
              // End early rather than allow that near-expiry operation to retry.
              if (Date.now() >= expiresAt - 25) await this.end(r, "expired", "credential_deadline");
              else await this.end(r, "blocked", "credential_phase_failed");
            }
            return { ok: false, error: "controlled_fill_failed" };
          } finally {
            username = "";
            password = "";
            clearTimeout(r.grantTimer);
            await cdp?.detach().catch(() => undefined);
            // No credential is stored in a session record. Broker releases/zeroizes
            // decrypted material as soon as this bounded credential phase returns.
          }
        },
      });
      r.requestId = result.request_id;
      if (result.status === "denied" || result.status === "expired") await this.end(r, "blocked", "credential_request_denied");
      return this.view(r);
    } finally { r.busy = false; }
  }

  async continue(id: string, token: string, revision: number): Promise<SessionView> {
    const r = this.lock(id, token, revision);
    try {
      if (!["awaiting_user_submit", "manual_required", "ready_for_credentials"].includes(r.state)) throw new SessionError("invalid_state");
      this.requireCompanion();
      const current = new URL(r.page!.url());
      if (!r.origins.has(origin(current.href))) { await this.end(r, "blocked", "origin_mismatch"); return this.view(r); }
      if (await this.manual(r)) return this.view(r);
      this.ensureActive(r);
      const success = r.profile.success;
      if (r.credentialsFilled && current.origin === success.origin && current.pathname === success.pathname &&
        await r.page!.locator(success.selector).first().isVisible()) {
        this.ensureActive(r);
        // Recheck URL after the asynchronous marker observation. No generic
        // 'filled' result or caller assertion is accepted as login success.
        const verified = new URL(r.page!.url());
        if (verified.origin !== success.origin || verified.pathname !== success.pathname) throw new SessionError("page_changed");
        this.set(r, "authenticated");
        r.expiresAt = Math.min(r.expiresAt, Date.now() + this.retentionMs);
        this.armExpiry(r);
      } else if (!r.credentialStarted && current.origin === r.profile.credentialOrigin) {
        this.set(r, "ready_for_credentials");
      } else {
        this.set(r, "manual_required", "user_action_or_success_evidence_required");
      }
      return this.view(r);
    } finally { r.busy = false; }
  }

  async cancel(id: string, token: string): Promise<SessionView> {
    const r = this.get(id, token);
    await this.end(r, "cancelled", "user_cancelled");
    return this.view(r);
  }

  async close(): Promise<void> {
    this.stopped = true;
    clearInterval(this.watchdog);
    await Promise.all([...this.records.values()].map((r) => this.end(r, "cancelled", "controller_closed")));
    await this.browser?.then((b) => b.close()).catch(() => undefined);
  }

  private async nextUsername(r: RecordState, cdp: CDPSession, expiresAt: number): Promise<void> {
    this.checkCredentialOrigin(r);
    const { frameTree } = await cdp.send("Page.getFrameTree");
    const { executionContextId } = await cdp.send("Page.createIsolatedWorld", { frameId: frameTree.frame.id, worldName: "safe-connect-fill" });
    const result = await cdp.send("Runtime.callFunctionOn", {
      executionContextId,
      functionDeclaration: `function(origin, selector, passwordSelector, expiresAt) {
        if (location.origin !== origin || Date.now() >= expiresAt) return false;
        if (document.querySelector(passwordSelector)) return false;
        const button = document.querySelector(selector);
        if (!(button instanceof HTMLElement)) return false;
        button.click(); return true;
      }`,
      arguments: [r.profile.credentialOrigin, r.profile.usernameNextSelector, r.profile.passwordSelector, expiresAt].map((value) => ({ value })),
      returnByValue: true,
    });
    if (result.exceptionDetails || result.result.value !== true) throw new SessionError("username_step_failed");
  }

  private async manual(r: RecordState): Promise<boolean> {
    for (const step of r.profile.manual ?? []) {
      if (origin(r.page!.url()) === step.origin && await r.page!.locator(step.selector).first().isVisible()) {
        this.ensureActive(r);
        this.set(r, "manual_required", `${step.kind}_requires_user`);
        return true;
      }
    }
    return false;
  }

  private checkCredentialOrigin(r: RecordState): void {
    this.ensureActive(r);
    if (!r.page || origin(r.page.url()) !== r.profile.credentialOrigin) throw new SessionError("origin_mismatch");
  }

  private requireCompanion(): void {
    if (this.options.broker.mode === "cloud" && this.options.broker.companionStatus() !== "paired") throw new SessionError("companion_missing", 503);
  }

  private get(id: string, token: string): RecordState {
    const r = this.records.get(id);
    if (!r || !/^[a-f0-9]{64}$/.test(token) || !timingSafeEqual(r.tokenHash, hash(token))) throw new SessionError("session_not_found", 404);
    return r;
  }

  private lock(id: string, token: string, revision: number): RecordState {
    const r = this.get(id, token);
    this.ensureActive(r);
    if (revision !== r.revision) throw new SessionError("stale_revision");
    if (r.busy) throw new SessionError("session_busy");
    r.busy = true;
    r.revision++;
    return r;
  }

  private ensureActive(r: RecordState): void {
    this.guard(r);
    if (terminal.has(r.state) || this.stopped) throw new SessionError("session_closed");
  }

  private guard(r: RecordState): void {
    if (terminal.has(r.state)) return;
    if (Date.now() >= r.expiresAt) void this.end(r, "expired", "session_deadline");
    else if (this.options.broker.mode === "cloud" && this.options.broker.companionStatus() !== "paired") void this.end(r, "blocked", "companion_missing");
    else if (r.state === "awaiting_grant" && r.requestId) {
      const request = this.options.broker.getLoginStatus(r.requestId);
      if (["denied", "expired"].includes(request.status)) void this.end(r, "blocked", "credential_request_denied");
    }
  }

  private set(r: RecordState, state: SessionState, reason?: string): void {
    if (terminal.has(r.state)) return;
    r.state = state; r.reason = reason; r.revision++;
  }

  private armExpiry(r: RecordState): void {
    clearTimeout(r.timer);
    r.timer = setTimeout(() => { void this.end(r, "expired", "session_deadline"); }, Math.max(1, r.expiresAt - Date.now()));
    r.timer.unref();
  }

  private end(r: RecordState, state: "blocked" | "cancelled" | "expired", reason: string): Promise<void> {
    if (!terminal.has(r.state)) {
      this.set(r, state, reason);
      clearTimeout(r.timer); clearTimeout(r.grantTimer);
      if (r.requestId && this.options.broker.getLoginStatus(r.requestId).status === "pending") this.options.broker.deny(r.requestId);
    }
    r.closing ??= (r.context?.close().catch(() => undefined) ?? Promise.resolve()).finally(() => {
      r.page = undefined;
      r.context = undefined;
    });
    return r.closing;
  }

  private view(r: RecordState): SessionView {
    return { session_id: r.id, profile_id: r.profile.id, state: r.state, revision: r.revision, expires_at: r.expiresAt,
      ...(r.requestId ? { request_id: r.requestId } : {}), ...(r.reason ? { reason: r.reason } : {}), operator_surface: "unavailable" };
  }
}
