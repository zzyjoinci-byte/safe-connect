import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { chromium, type Browser, type BrowserContext, type CDPSession, type Frame, type Page } from "playwright";
import type { Broker } from "./broker.js";
import { clickVisibleControl, fillInput, visibleInputExists, type FillFrameTarget } from "./fill.js";
import type { Grade } from "./types.js";

export type SessionState = "opening" | "ready_for_credentials" | "awaiting_grant" | "filling"
  | "awaiting_user_submit" | "manual_required" | "authenticated" | "blocked" | "cancelled" | "expired";

/** Trusted server configuration, never accepted as selectors/origins from agent APIs. */
export interface LoginProfile {
  id: string;
  entryUrl: string;
  /** Exact top-level portal origin. Defaults to origin(entryUrl). */
  portalOrigin?: string;
  credentialOrigin: string;
  /**
   * `direct-child` fills the unique child frame whose origin equals credentialOrigin,
   * while the top-level page must stay on portalOrigin. Nested frames are never a target.
   */
  credentialFrame?: "direct-child";
  usernameSelector: string;
  passwordSelector: string;
  /** Optional username-only Next button. Never a final password/OTP submit button. */
  usernameNextSelector?: string;
  success: {
    origin: string;
    pathname?: string;
    pathnamePrefix?: string;
    denyPathnames?: string[];
    selector: string;
  };
  manual?: Array<{ origin: string; selector: string; kind: "otp" | "captcha" | "passkey" }>;
}

export type OperatorSurface = "unavailable" | "local_headed_browser";

export interface SessionView {
  session_id: string;
  profile_id: string;
  state: SessionState;
  revision: number;
  expires_at: number;
  request_id?: string;
  reason?: string;
  /** Headed local Chromium when SAFE_CONNECT_HEADED=1; never a remote browser handoff. */
  operator_surface: OperatorSurface;
}

export interface ProfileView {
  id: string;
  entry_url: string;
  portal_origin: string;
  credential_origin: string;
  credential_frame: FillFrameTarget;
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
  /** How long create() waits for a direct child credential frame. */
  credentialFrameTimeoutMs?: number;
  /** Visible Chromium on the existing DISPLAY. Not a remote operator UI. */
  headed?: boolean;
}

/** Lookup by session_id only (agent HTTP/MCP). Operator APIs still require the control token. */
export const PUBLIC_SESSION = null;

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
  private readonly headed: boolean;
  private readonly credentialFrameTimeoutMs: number;
  private readonly watchdog: ReturnType<typeof setInterval>;

  constructor(private readonly options: SessionOptions) {
    this.sessionTimeoutMs = options.sessionTimeoutMs ?? 5 * 60_000;
    this.retentionMs = options.retentionMs ?? 60_000;
    this.maxSessions = options.maxSessions ?? 8;
    this.credentialFrameTimeoutMs = options.credentialFrameTimeoutMs ?? 10_000;
    this.headed = options.headed ?? process.env.SAFE_CONNECT_HEADED === "1";
    if (!(this.sessionTimeoutMs > 0 && this.sessionTimeoutMs <= 10 * 60_000) ||
      !(this.retentionMs > 0 && this.retentionMs <= 5 * 60_000) ||
      !(this.credentialFrameTimeoutMs > 0 && this.credentialFrameTimeoutMs <= 15_000) ||
      !Number.isInteger(this.maxSessions) || this.maxSessions < 1 || this.maxSessions > 32) {
      throw new SessionError("invalid_limits", 400);
    }
    for (const raw of options.profiles) {
      const p = structuredClone(raw);
      if (!/^[a-zA-Z0-9_-]{1,64}$/.test(p.id) || this.profiles.has(p.id)) throw new SessionError("invalid_profile", 400);
      const entryOrigin = origin(p.entryUrl);
      p.portalOrigin = p.portalOrigin ? exactOrigin(p.portalOrigin) : entryOrigin;
      if (p.portalOrigin !== entryOrigin) throw new SessionError("invalid_profile", 400);
      exactOrigin(p.credentialOrigin);
      exactOrigin(p.success.origin);
      if (p.credentialFrame && p.credentialFrame !== "direct-child") throw new SessionError("invalid_profile", 400);
      if (p.credentialFrame === "direct-child" && p.credentialOrigin === p.portalOrigin) {
        throw new SessionError("invalid_profile", 400);
      }
      const hasPath = typeof p.success.pathname === "string" && p.success.pathname.startsWith("/") && !/[?#]/.test(p.success.pathname);
      const hasPrefix = typeof p.success.pathnamePrefix === "string" && p.success.pathnamePrefix.startsWith("/") &&
        !/[?#]/.test(p.success.pathnamePrefix);
      if (p.success.pathname !== undefined && !hasPath) throw new SessionError("invalid_profile", 400);
      if (p.success.pathnamePrefix !== undefined && !hasPrefix) throw new SessionError("invalid_profile", 400);
      if (!hasPath && !hasPrefix) throw new SessionError("invalid_profile", 400);
      for (const deny of p.success.denyPathnames ?? []) {
        if (!deny.startsWith("/") || /[?#]/.test(deny) || deny.length > 512) throw new SessionError("invalid_profile", 400);
      }
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

  listProfiles(): ProfileView[] {
    return [...this.profiles.values()].map((p) => ({
      id: p.id,
      entry_url: p.entryUrl,
      portal_origin: p.portalOrigin ?? origin(p.entryUrl),
      credential_origin: p.credentialOrigin,
      credential_frame: p.credentialFrame ?? "top",
    }));
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
    const portalOrigin = profile.portalOrigin ?? origin(profile.entryUrl);
    const r: RecordState = {
      id: randomUUID(), tokenHash: hash(token), profile,
      origins: new Set([portalOrigin, profile.credentialOrigin, profile.success.origin,
        ...(profile.manual ?? []).map((m) => m.origin)]),
      state: "opening", revision: 0, expiresAt: Date.now() + this.sessionTimeoutMs,
      credentialsFilled: false, credentialStarted: false, busy: false,
    };
    this.records.set(r.id, r);
    this.armExpiry(r);
    try {
      this.browser ??= (this.options.browserFactory ?? (() => chromium.launch({ headless: !this.headed })))();
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
        if (frame.url() === "about:blank" || frame !== page.mainFrame()) return;
        try {
          const current = origin(frame.url());
          if (!r.origins.has(current)) {
            void this.end(r, "blocked", "origin_mismatch");
            return;
          }
          if (r.state === "filling" && current !== this.expectedTopOrigin(r)) {
            void this.end(r, "blocked", "origin_mismatch");
          }
        } catch { void this.end(r, "blocked", "origin_mismatch"); }
      });
      await context.route("**/*", async (route) => {
        try {
          if (terminal.has(r.state)) { await route.abort(); return; }
          const req = route.request();
          const isMainDocument = req.resourceType() === "document" && req.frame() === page.mainFrame();
          if (isMainDocument) {
            let reqOrigin: string;
            try { reqOrigin = origin(req.url()); }
            catch {
              await route.abort();
              void this.end(r, "blocked", "origin_mismatch");
              return;
            }
            if (!r.origins.has(reqOrigin)) {
              await route.abort();
              void this.end(r, "blocked", "origin_mismatch");
              return;
            }
          }
          await route.continue();
        } catch { if (!terminal.has(r.state)) void this.end(r, "blocked", "navigation_failed"); }
      });
      await page.goto(profile.entryUrl, { waitUntil: "domcontentloaded", timeout: Math.min(15_000, this.sessionTimeoutMs) });
      this.ensureActive(r);
      const top = origin(page.url());
      if (profile.credentialFrame === "direct-child") {
        if (top !== portalOrigin) this.set(r, "manual_required", "credential_origin_not_reached");
        else if (!await this.waitForDirectChild(r, profile.credentialOrigin, Math.min(this.credentialFrameTimeoutMs, this.sessionTimeoutMs))) {
          this.set(r, "manual_required", "credential_origin_not_reached");
        } else if (!await this.manual(r)) this.set(r, "ready_for_credentials");
      } else if (top !== profile.credentialOrigin) {
        this.set(r, "manual_required", "credential_origin_not_reached");
      } else if (!await this.manual(r)) this.set(r, "ready_for_credentials");
    } catch {
      if (!terminal.has(r.state)) await this.end(r, "blocked", "navigation_failed");
      else await r.context?.close().catch(() => undefined);
    }
    return { ...this.view(r), control_token: token };
  }

  status(id: string, token: string | null): SessionView {
    const r = this.get(id, token);
    this.guard(r);
    return this.view(r);
  }

  async credentials(id: string, token: string | null, revision: number, itemId: string, grade?: Grade): Promise<SessionView> {
    const r = this.lock(id, token, revision);
    try {
      if (r.state !== "ready_for_credentials" || r.credentialStarted) throw new SessionError("invalid_state");
      this.requireCompanion();
      this.checkFillOrigins(r);
      if (await this.manual(r)) return this.view(r);
      this.ensureActive(r);
      const grantUrl = this.credentialUrl(r);
      // Immutable association: this grant's request ID can fill only this context.
      r.credentialStarted = true;
      this.set(r, "awaiting_grant");
      const result = await this.options.broker.requestControlledLogin({
        purpose: `controlled-session:${r.profile.id}`, url: grantUrl, item_id: itemId, grade, ttl_seconds: 30,
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
            const target = this.checkFillOrigins(r);
            this.set(r, "filling");
            r.grantTimer = setTimeout(() => { void this.end(r, "expired", "credential_deadline"); }, Math.max(1, expiresAt - Date.now()));
            r.grantTimer.unref();
            cdp = await r.context!.newCDPSession(r.page!);
            const user = target.locator(r.profile.usernameSelector).first();
            await fillInput(cdp, user, r.profile.usernameSelector, username, r.profile.credentialOrigin, expiresAt, this.fillTarget(r));
            this.checkFillOrigins(r);
            if (r.profile.usernameNextSelector &&
              !await visibleInputExists(cdp, r.profile.credentialOrigin, r.profile.passwordSelector, expiresAt, this.fillTarget(r))) {
              await this.nextUsername(r, cdp, expiresAt);
              if (!await this.waitForVisiblePassword(r, cdp, expiresAt)) {
                if (Date.now() >= expiresAt - 25) {
                  await this.end(r, "expired", "credential_deadline");
                  return { ok: false, error: "controlled_fill_failed" };
                }
                this.set(r, "manual_required", "password_field_not_visible");
                return { ok: false, error: "password_field_not_visible" };
              }
            }
            this.checkFillOrigins(r);
            if (await this.manual(r)) return { ok: false, error: "manual_required" };
            if (!await visibleInputExists(cdp, r.profile.credentialOrigin, r.profile.passwordSelector, expiresAt, this.fillTarget(r))) {
              this.set(r, "manual_required", "password_not_filled");
              return { ok: false, error: "password_not_filled" };
            }
            const passFrame = this.checkFillOrigins(r);
            const pass = passFrame.locator(r.profile.passwordSelector).first();
            await fillInput(cdp, pass, r.profile.passwordSelector, password, r.profile.credentialOrigin, expiresAt, this.fillTarget(r));
            this.checkFillOrigins(r);
            if (!await visibleInputExists(cdp, r.profile.credentialOrigin, r.profile.passwordSelector, expiresAt, this.fillTarget(r))) {
              this.set(r, "manual_required", "password_not_filled");
              return { ok: false, error: "password_not_filled" };
            }
            r.credentialsFilled = true;
            this.set(r, "awaiting_user_submit", this.headed ? "local_headed_browser" : "operator_surface_unavailable");
            return { ok: true };
          } catch (err) {
            const code = err instanceof Error ? err.message : "";
            if (!terminal.has(r.state)) {
              // Playwright's bounded wait can win the timer race by a few ms.
              // End early rather than allow that near-expiry operation to retry.
              if (Date.now() >= expiresAt - 25) await this.end(r, "expired", "credential_deadline");
              else if (code === "password_not_filled" || code === "password_field_not_visible" ||
                code === "username_step_failed" || code === "input_not_visible" || code === "write_not_confirmed") {
                this.set(r, "manual_required", code === "username_step_failed" ? "username_step_failed" : "password_not_filled");
              } else {
                await this.end(r, "blocked", "credential_phase_failed");
              }
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
      if ((result.status === "denied" || result.status === "expired") && stillInCredentialPhase(r)) {
        await this.end(r, "blocked", "credential_request_denied");
      }
      return this.view(r);
    } finally { r.busy = false; }
  }

  async continue(id: string, token: string | null, revision: number): Promise<SessionView> {
    const r = this.lock(id, token, revision);
    try {
      if (!["awaiting_user_submit", "manual_required", "ready_for_credentials"].includes(r.state)) throw new SessionError("invalid_state");
      this.requireCompanion();
      const current = new URL(r.page!.url());
      if (!r.origins.has(origin(current.href))) { await this.end(r, "blocked", "origin_mismatch"); return this.view(r); }
      if (await this.manual(r)) return this.view(r);
      this.ensureActive(r);
      const success = r.profile.success;
      if (r.credentialsFilled && current.origin === success.origin && matchSuccessPath(current, success) &&
        await r.page!.mainFrame().locator(success.selector).first().isVisible()) {
        this.ensureActive(r);
        // Recheck URL after the asynchronous marker observation. No generic
        // 'filled' result or caller assertion is accepted as login success.
        const verified = new URL(r.page!.url());
        if (verified.origin !== success.origin || !matchSuccessPath(verified, success)) throw new SessionError("page_changed");
        this.set(r, "authenticated");
        r.expiresAt = Math.min(r.expiresAt, Date.now() + this.retentionMs);
        this.armExpiry(r);
      } else if (!r.credentialStarted && this.credentialsReachable(r)) {
        this.set(r, "ready_for_credentials");
      } else {
        this.set(r, "manual_required", "user_action_or_success_evidence_required");
      }
      return this.view(r);
    } finally { r.busy = false; }
  }

  async cancel(id: string, token: string | null): Promise<SessionView> {
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
    this.checkFillOrigins(r);
    while (Date.now() < expiresAt) {
      this.ensureActive(r);
      const result = await clickVisibleControl(
        cdp, r.profile.credentialOrigin, r.profile.usernameNextSelector ?? "", expiresAt, this.fillTarget(r),
      );
      if (result === true) return;
      if (result === false) throw new SessionError("username_step_failed");
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    throw new SessionError("username_step_failed");
  }

  private async waitForVisiblePassword(r: RecordState, cdp: CDPSession, expiresAt: number): Promise<boolean> {
    while (Date.now() < expiresAt) {
      this.ensureActive(r);
      this.checkFillOrigins(r);
      if (await visibleInputExists(cdp, r.profile.credentialOrigin, r.profile.passwordSelector, expiresAt, this.fillTarget(r))) {
        return true;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return false;
  }

  private async manual(r: RecordState): Promise<boolean> {
    for (const step of r.profile.manual ?? []) {
      if (await this.selectorVisibleOnOrigin(r, step.origin, step.selector)) {
        this.ensureActive(r);
        this.set(r, "manual_required", `${step.kind}_requires_user`);
        return true;
      }
    }
    return false;
  }

  private async selectorVisibleOnOrigin(r: RecordState, expectedOrigin: string, selector: string): Promise<boolean> {
    for (const frame of r.page!.frames()) {
      try {
        if (origin(frame.url()) !== expectedOrigin) continue;
        if (await frame.locator(selector).first().isVisible()) return true;
      } catch { /* frame navigated during inspection */ }
    }
    return false;
  }

  private checkFillOrigins(r: RecordState): Frame {
    this.ensureActive(r);
    if (!r.page) throw new SessionError("origin_mismatch");
    const top = origin(r.page.url());
    if (top !== this.expectedTopOrigin(r)) throw new SessionError("origin_mismatch");
    const target = this.credentialFrame(r.page, r.profile);
    if (!target || origin(target.url()) !== r.profile.credentialOrigin) throw new SessionError("origin_mismatch");
    return target;
  }

  private expectedTopOrigin(r: RecordState): string {
    return r.profile.credentialFrame === "direct-child"
      ? (r.profile.portalOrigin ?? origin(r.profile.entryUrl))
      : r.profile.credentialOrigin;
  }

  private fillTarget(r: RecordState): FillFrameTarget {
    return r.profile.credentialFrame === "direct-child" ? "direct-child" : "top";
  }

  private credentialFrame(page: Page, profile: LoginProfile): Frame | undefined {
    if (profile.credentialFrame === "direct-child") {
      const matches = this.directChildren(page, profile.credentialOrigin);
      return matches.length === 1 ? matches[0] : undefined;
    }
    return origin(page.url()) === profile.credentialOrigin ? page.mainFrame() : undefined;
  }

  private directChildren(page: Page, expectedOrigin: string): Frame[] {
    return page.frames().filter((frame) => {
      if (frame.parentFrame() !== page.mainFrame()) return false;
      try { return origin(frame.url()) === expectedOrigin; } catch { return false; }
    });
  }

  private credentialUrl(r: RecordState): string {
    const frame = this.credentialFrame(r.page!, r.profile);
    if (!frame) throw new SessionError("origin_mismatch");
    return frame.url();
  }

  private credentialsReachable(r: RecordState): boolean {
    try { return this.credentialFrame(r.page!, r.profile) !== undefined; } catch { return false; }
  }

  private async waitForDirectChild(r: RecordState, expectedOrigin: string, timeoutMs: number): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      this.ensureActive(r);
      if (this.directChildren(r.page!, expectedOrigin).length === 1) return true;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    return this.directChildren(r.page!, expectedOrigin).length === 1;
  }

  private requireCompanion(): void {
    if (this.options.broker.mode === "cloud" && this.options.broker.companionStatus() !== "paired") throw new SessionError("companion_missing", 503);
  }

  private get(id: string, token: string | null): RecordState {
    const r = this.records.get(id);
    if (!r) throw new SessionError("session_not_found", 404);
    if (token !== PUBLIC_SESSION) {
      if (!/^[a-f0-9]{64}$/.test(token) || !timingSafeEqual(r.tokenHash, hash(token))) {
        throw new SessionError("session_not_found", 404);
      }
    }
    return r;
  }

  private lock(id: string, token: string | null, revision: number): RecordState {
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
      ...(r.requestId ? { request_id: r.requestId } : {}), ...(r.reason ? { reason: r.reason } : {}),
      operator_surface: this.headed ? "local_headed_browser" : "unavailable" };
  }
}

function stillInCredentialPhase(r: { state: SessionState }): boolean {
  return r.state === "awaiting_grant" || r.state === "filling";
}

function matchSuccessPath(current: URL, success: LoginProfile["success"]): boolean {
  if (success.pathname && current.pathname !== success.pathname) return false;
  if (success.pathnamePrefix && !current.pathname.startsWith(success.pathnamePrefix)) return false;
  for (const deny of success.denyPathnames ?? []) {
    if (current.pathname === deny || current.pathname.startsWith(`${deny}/`)) return false;
  }
  return true;
}
