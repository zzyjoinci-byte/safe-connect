import { chromium, type Browser } from "playwright";
import type { FillResult, Filler } from "./types.js";
import { logInfo } from "./logger.js";

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
  const b = await getBrowser();
  const page = await b.newPage();
  try {
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15_000 });
    const user = page.locator(
      'input[name="username"], input#username, input[type="email"], input[autocomplete="username"]',
    ).first();
    const pass = page.locator(
      'input[name="password"], input#password, input[type="password"]',
    ).first();
    await user.fill(username);
    await pass.fill(password);
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
    return { ok: false, error: "fill_failed" };
  } finally {
    await page.close().catch(() => undefined);
  }
};

export function mockFiller(store: { last?: { url: string; username: string; password: string } }): Filler {
  return async (url, username, password) => {
    store.last = { url, username, password };
    return { ok: true };
  };
}

export async function shutdownFillers(): Promise<void> {
  await closeBrowser();
}
