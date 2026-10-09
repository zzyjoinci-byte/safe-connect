import { chromium, type Browser, type CDPSession, type Locator } from "playwright";
import type { FillResult, Filler } from "./types.js";
import { logInfo } from "./logger.js";
import { originOf } from "./vault.js";

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

export async function fillInput(session: CDPSession, locator: Locator, selector: string,
  value: string, expectedOrigin: string, expiresAt?: number): Promise<void> {
  await locator.waitFor({ state: "attached", timeout: expiresAt ? Math.max(1, Math.min(5_000, expiresAt - Date.now())) : 5_000 });
  const { frameTree } = await session.send("Page.getFrameTree");
  const { executionContextId } = await session.send("Page.createIsolatedWorld", {
    frameId: frameTree.frame.id,
    worldName: "safe-connect-fill",
  });
  // Check and write synchronously in an isolated, document-bound context.
  // Navigation destroys the context instead of retargeting the write. Isolation
  // also prevents page scripts from replacing eval/DOM getters to steal args or
  // forge an origin check. Never grant this world universal cross-origin access.
  const result = await session.send("Runtime.callFunctionOn", {
    executionContextId,
    functionDeclaration: `function(selector, value, expectedOrigin, expiresAt) {
      if (expiresAt !== null && Date.now() >= expiresAt) return "grant_expired";
      if (location.origin !== expectedOrigin) return "origin_mismatch";
      const element = document.querySelector(selector);
      if (!(element instanceof HTMLInputElement) || element.disabled || element.readOnly) {
        return "input_not_editable";
      }
      const setValue = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;
      setValue.call(element, value);
      element.dispatchEvent(new Event("input", { bubbles: true }));
      element.dispatchEvent(new Event("change", { bubbles: true }));
      return null;
    }`,
    arguments: [{ value: selector }, { value }, { value: expectedOrigin }, { value: expiresAt ?? null }],
    returnByValue: true,
  });
  if (result.exceptionDetails) throw new Error("fill_failed");
  if (result.result.value !== null) throw new Error(result.result.value ?? "fill_failed");
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
