import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { after, before, test } from "node:test";
import { Broker } from "../src/broker.js";
import { cryptoReady } from "../src/crypto.js";
import { playwrightFill, closeBrowser } from "../src/fill.js";
import { createHttpServer, listen } from "../src/http.js";
import { LocalVault, originOf } from "../src/vault.js";
import { testHome, waitStatus } from "./helpers.ts";

process.env.NODE_ENV = "test";
process.env.SAFE_CONNECT_KDF = "fast";

let home: string;
let skipPlaywright = false;

before(async () => {
  await cryptoReady();
  home = testHome();
  try {
    const { chromium } = await import("playwright");
    const browser = await chromium.launch({ headless: true });
    await browser.close();
  } catch {
    skipPlaywright = true;
  }
});

after(async () => {
  await closeBrowser();
  fs.rmSync(home, { recursive: true, force: true });
});

test("Playwright fills the example HTML login page", async (t) => {
  if (skipPlaywright) {
    t.skip("Chromium not installed — run: npx playwright install chromium");
    return;
  }
  const vault = new LocalVault(path.join(home, "vault.sc"));
  await vault.init("passphrase-for-tests");
  const broker = new Broker({
    mode: "local",
    filler: playwrightFill,
    localVault: vault,
  });
  const server = createHttpServer({ broker, bind: "127.0.0.1", port: 0 });
  const port = await listen(server, "127.0.0.1", 0);
  const loginUrl = `http://127.0.0.1:${port}/example/login.html`;
  try {
    const page = await fetch(loginUrl);
    assert.equal(page.status, 200);
    await vault.addL1({
      label: "example",
      origin: originOf(loginUrl),
      username: "demo",
      password: "demo-pass-NOT-SECRET",
    });
    const pending = await broker.requestBrowserLogin({
      purpose: "playwright-demo",
      url: loginUrl,
    });
    const done = await waitStatus(broker, pending.request_id, 20_000);
    assert.equal(done.status, "filled", done.error);
    assert.equal(JSON.stringify(done).includes("demo-pass-NOT-SECRET"), false);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
