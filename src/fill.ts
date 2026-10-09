import { chromium, type Browser, type CDPSession, type Locator } from "playwright";
import type { FillResult, Filler } from "./types.js";
import { logInfo } from "./logger.js";
import { originOf } from "./vault.js";

/** Where an isolated-world credential write is allowed to run. */
export type FillFrameTarget = "top" | "direct-child";

export interface FrameTreeNode {
  frame: { id: string; url: string };
  childFrames?: FrameTreeNode[];
}

function frameOrigin(url: string): string | undefined {
  if (!url || url === "about:blank") return undefined;
  try {
    const origin = originOf(url);
    return origin === "null" ? undefined : origin;
  } catch {
    return undefined;
  }
}

/**
 * Pick the CDP frame that may receive a credential write.
 * `top` — the main frame, whose origin must equal `expectedOrigin`.
 * `direct-child` — exactly one direct child of the main frame with that origin.
 * Nested frames are never a fill target (fail-closed).
 */
export function selectCredentialFrameId(
  tree: FrameTreeNode,
  expectedOrigin: string,
  target: FillFrameTarget = "top",
): string {
  if (expectedOrigin === "null") throw new Error("origin_mismatch");
  if (target === "top") {
    if (frameOrigin(tree.frame.url) !== expectedOrigin) throw new Error("origin_mismatch");
    return tree.frame.id;
  }
  const matches = (tree.childFrames ?? []).filter((child) => frameOrigin(child.frame.url) === expectedOrigin);
  if (matches.length !== 1) throw new Error("credential_frame_mismatch");
  return matches[0]!.frame.id;
}

let browser: Browser | null = null;

async function getBrowser(): Promise<Browser> {
  if (browser && browser.isConnected()) return browser;
  browser = await chromium.launch({
    headless: process.env.SAFE_CONNECT_HEADED !== "1",
  });
  return browser;
}

export async function closeBrowser(): Promise<void> {
  if (browser) {
    await browser.close().catch(() => undefined);
    browser = null;
  }
}

/**
 * Fill a username/password login form. Credentials are passed only to the
 * requested page in this process — never returned to the caller.
 */
export const playwrightFill: Filler = async (url, username, password) => {
  const expectedOrigin = originOf(url);
  const b = await getBrowser();
  const page = await b.newPage();
  let session: CDPSession | undefined;
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15_000 });
    if (expectedOrigin === "null" || originOf(page.url()) !== expectedOrigin) {
      return { ok: false, error: "origin_mismatch" };
    }
    session = await page.context().newCDPSession(page);
    const userSelector = 'input[name="username"], input#username, input[type="email"], input[autocomplete="username"]';
    const passSelector = 'input[name="password"], input#password, input[type="password"]';
    const user = page.locator(userSelector).first();
    const pass = page.locator(passSelector).first();
    await fillInput(session, user, userSelector, username, expectedOrigin);
    await fillInput(session, pass, passSelector, password, expectedOrigin);
    if (originOf(page.url()) !== expectedOrigin) {
      return { ok: false, error: "origin_mismatch" };
    }
    const submit = page.locator(
      'button[type="submit"], input[type="submit"], button#login, button:has-text("Log in"), button:has-text("Sign in")',
    ).first();
    await submit.click({ timeout: 5_000 }).catch(async () => {
      await pass.press("Enter");
    });
    await new Promise((r) => setTimeout(r, 250));
    const result = page.locator("#login-result");
    if (await result.count()) {
      const status = await result.getAttribute("data-status");
      if (status === "ok") return { ok: true };
      return { ok: false, error: "fill_rejected_by_page" };
    }
    return { ok: true };
  } catch (err) {
    const message = err instanceof Error ? err.message : "fill_failed";
    logInfo(`browser fill failed: ${message.split(/password|secret/i)[0] ?? "fill_failed"}`);
    return { ok: false, error: message.includes("origin_mismatch") ? "origin_mismatch" : "fill_failed" };
  } finally {
    await session?.detach().catch(() => undefined);
    await page.close().catch(() => undefined);
  }
};

export async function isolatedWorldCall(
  session: CDPSession,
  frameId: string,
  functionDeclaration: string,
  args: unknown[],
): Promise<unknown> {
  const { executionContextId } = await session.send("Page.createIsolatedWorld", {
    frameId,
    worldName: "safe-connect-fill",
  });
  const result = await session.send("Runtime.callFunctionOn", {
    executionContextId,
    functionDeclaration,
    arguments: args.map((value) => ({ value })),
    returnByValue: true,
  });
  if (result.exceptionDetails) throw new Error("fill_failed");
  return result.result.value;
}

function waitMs(expiresAt?: number): number {
  return expiresAt ? Math.max(1, Math.min(5_000, expiresAt - Date.now())) : 5_000;
}

async function credentialFrameId(session: CDPSession, expectedOrigin: string, target: FillFrameTarget): Promise<string> {
  const { frameTree } = await session.send("Page.getFrameTree");
  return selectCredentialFrameId(frameTree as FrameTreeNode, expectedOrigin, target);
}

/**
 * Isolated-world visibility. Apple's idmsa widget keeps #password_text_field in
 * the DOM on step 1: checkVisibility can be true and the input has a non-zero
 * rect, but it is tabindex=-1 inside an aria-hidden ancestor whose overflow
 * wrapper has height 0. Those fields must not count as visible.
 */
const VISIBLE = `const visible = (el, allowDisabled) => {
  if (!(el instanceof HTMLElement) || el.hidden) return false;
  if (!allowDisabled && (el instanceof HTMLButtonElement || el instanceof HTMLInputElement) && el.disabled) return false;
  if (el instanceof HTMLInputElement && el.readOnly) return false;
  if (el.closest('[aria-hidden="true"], [inert]')) return false;
  if (el instanceof HTMLInputElement && el.getAttribute("tabindex") === "-1") return false;
  if (typeof el.checkVisibility === "function") {
    try { if (!el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) return false; } catch (e) {}
  }
  const style = getComputedStyle(el);
  if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") return false;
  const rect = el.getBoundingClientRect();
  if (!(rect.width > 0 && rect.height > 0)) return false;
  let left = rect.left, top = rect.top, right = rect.right, bottom = rect.bottom;
  for (let n = el.parentElement; n && n !== document.documentElement; n = n.parentElement) {
    const ps = getComputedStyle(n);
    if (/(hidden|clip|scroll|auto)/.test(ps.overflow + ps.overflowX + ps.overflowY)) {
      const pr = n.getBoundingClientRect();
      left = Math.max(left, pr.left); top = Math.max(top, pr.top);
      right = Math.min(right, pr.right); bottom = Math.min(bottom, pr.bottom);
      if (right - left < 1 || bottom - top < 1) return false;
    }
  }
  return true;
};`;

export async function visibleInputExists(
  session: CDPSession, expectedOrigin: string, selector: string, expiresAt: number, target: FillFrameTarget = "top",
): Promise<boolean> {
  const frameId = await credentialFrameId(session, expectedOrigin, target);
  const result = await isolatedWorldCall(session, frameId, `function(origin, selector, expiresAt) {
      ${VISIBLE}
      if (Date.now() >= expiresAt || location.origin !== origin) return false;
      for (const el of document.querySelectorAll(selector)) {
        if (el instanceof HTMLInputElement && visible(el, false)) return true;
      }
      return false;
    }`, [expectedOrigin, selector, expiresAt]);
  return result === true;
}

export async function clickVisibleControl(
  session: CDPSession, expectedOrigin: string, selector: string, expiresAt: number, target: FillFrameTarget = "top",
): Promise<true | "disabled" | false> {
  const frameId = await credentialFrameId(session, expectedOrigin, target);
  const result = await isolatedWorldCall(session, frameId, `function(origin, selector, expiresAt) {
      ${VISIBLE}
      if (Date.now() >= expiresAt || location.origin !== origin) return false;
      const candidates = [];
      for (const el of document.querySelectorAll(selector)) candidates.push(el);
      for (const el of document.querySelectorAll("button, input[type=submit], [role=button]")) {
        const text = ((el instanceof HTMLInputElement ? el.value : el.textContent) || "").replace(/\\s+/g, " ").trim();
        if (/^(Continue|Next)$/i.test(text)) candidates.push(el);
      }
      let disabled = false;
      for (const el of candidates) {
        if (!(el instanceof HTMLElement)) continue;
        const isDisabled = (el instanceof HTMLButtonElement || el instanceof HTMLInputElement) && el.disabled;
        if (!visible(el, true)) continue;
        if (isDisabled) { disabled = true; continue; }
        el.click();
        return true;
      }
      return disabled ? "disabled" : false;
    }`, [expectedOrigin, selector, expiresAt]);
  if (result === true || result === "disabled") return result;
  return false;
}

export async function fillInput(session: CDPSession, locator: Locator, selector: string,
  value: string, expectedOrigin: string, expiresAt?: number, target: FillFrameTarget = "top"): Promise<void> {
  await locator.waitFor({ state: "visible", timeout: waitMs(expiresAt) });
  const frameId = await credentialFrameId(session, expectedOrigin, target);
  // Check and write synchronously in an isolated, document-bound context.
  // Navigation destroys the context instead of retargeting the write. Isolation
  // also prevents page scripts from replacing eval/DOM getters to steal args or
  // forge an origin check. Never grant this world universal cross-origin access.
  // Only the first *visible* matching input is written; hidden fields are not targets.
  const result = await isolatedWorldCall(session, frameId, `function(selector, value, expectedOrigin, expiresAt) {
      ${VISIBLE}
      if (expiresAt !== null && Date.now() >= expiresAt) return "grant_expired";
      if (location.origin !== expectedOrigin) return "origin_mismatch";
      let element = null;
      for (const el of document.querySelectorAll(selector)) {
        if (el instanceof HTMLInputElement && visible(el, false)) { element = el; break; }
      }
      if (!(element instanceof HTMLInputElement) || !visible(element, false)) return "input_not_visible";
      const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
      element.focus();
      setValue.call(element, value);
      element.dispatchEvent(new Event("input", { bubbles: true }));
      try { element.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertFromPaste" })); } catch (e) {}
      element.dispatchEvent(new Event("change", { bubbles: true }));
      element.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));
      if (!visible(element, false) || element.value !== value) return "write_not_confirmed";
      return null;
    }`, [selector, value, expectedOrigin, expiresAt ?? null]);
  if (result !== null) throw new Error((result as string | null) ?? "fill_failed");
}

export function mockFiller(store: { last?: { url: string; username: string; password: string } }): Filler {
  return async (url, username, password) => {
    store.last = { url, username, password };
    return { ok: true };
  };
}

export async function shutdownFillers(): Promise<void> {
  await closeBrowser();
}
