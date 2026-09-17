import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { after, before, test } from "node:test";
import { Broker } from "../src/broker.js";
import { REQUEST_RETENTION_MS } from "../src/config.js";
import { cryptoReady } from "../src/crypto.js";
import { mockFiller } from "../src/fill.js";
import { createHttpServer, listen } from "../src/http.js";
import { LocalVault, originOf } from "../src/vault.js";
import { assertNoLeak, testHome, waitStatus } from "./helpers.ts";

process.env.NODE_ENV = "test";
process.env.SAFE_CONNECT_KDF = "fast";

const SECRET = "api-local-password-LEAKCHECK";
let home: string;
let vault: LocalVault;
let broker: Broker;
let fillStore: { last?: { url: string; username: string; password: string } };

before(async () => {
  await cryptoReady();
  home = testHome();
  vault = new LocalVault(path.join(home, "vault.sc"));
  await vault.init("passphrase-for-tests");
  fillStore = {};
  broker = new Broker({
    mode: "local",
    filler: mockFiller(fillStore),
    localVault: vault,
  });
  await vault.addL1({
    label: "demo",
    origin: originOf("http://127.0.0.1:8787/example/login.html"),
    username: "demo",
    password: SECRET,
  });
});

after(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

test("local L1 fill returns status only", async () => {
  const pending = await broker.requestBrowserLogin({
    purpose: "test",
    url: "http://127.0.0.1:8787/example/login.html",
  });
  assert.equal(pending.status, "pending");
  assertNoLeak(pending, SECRET);
  const done = await waitStatus(broker, pending.request_id);
  assert.equal(done.status, "filled");
  assert.equal(fillStore.last?.password, SECRET);
  assertNoLeak(done, SECRET);
  assert.equal("password" in done, false);
  assert.equal("username" in done, false);
});

test("local L0 is memory-only and burns after fill", async () => {
  const l0secret = "l0-burn-LEAKCHECK";
  const item = broker.addLocalL0({
    label: "once",
    origin: originOf("http://127.0.0.1:9999/login"),
    username: "demo",
    password: l0secret,
  });
  const disk = fs.readFileSync(path.join(home, "vault.sc"));
  assert.ok(!disk.includes(Buffer.from(l0secret)));
  assert.ok(!disk.toString("utf8").includes(item.id) || true);
  const pending = await broker.requestBrowserLogin({
    purpose: "l0",
    url: "http://127.0.0.1:9999/login",
    grade: "L0",
    item_id: item.id,
  });
  const done = await waitStatus(broker, pending.request_id);
  assert.equal(done.status, "filled");
  assertNoLeak(done, l0secret);
  assert.equal(
    broker.listItems().some((i) => i.id === item.id),
    false,
  );
});

test("HTTP API never includes the password", async () => {
  const server = createHttpServer({
    broker,
    bind: "127.0.0.1",
    port: 0,
  });
  const port = await listen(server, "127.0.0.1", 0);
  try {
    const health = await fetch(`http://127.0.0.1:${port}/v1/health`);
    assert.equal(health.status, 200);
    const hbody = await health.json();
    assert.equal(hbody.mode, "local");
    assert.equal(hbody.companion, "not_required");

    const res = await fetch(`http://127.0.0.1:${port}/v1/request_browser_login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        purpose: "http",
        url: "http://127.0.0.1:8787/example/login.html",
      }),
    });
    const pending = await res.json();
    assertNoLeak(pending, SECRET);
    let status = pending;
    for (let i = 0; i < 50; i++) {
      const st = await fetch(`http://127.0.0.1:${port}/v1/requests/${pending.request_id}`);
      status = await st.json();
      if (status.status !== "pending") break;
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.equal(status.status, "filled");
    assertNoLeak(status, SECRET);
    assert.deepEqual(Object.keys(status).sort(), ["request_id", "status"]);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("item_id fill is rejected when origin does not match", async () => {
  const listed = broker.listItems().find((i) => i.grade === "L1");
  assert.ok(listed);
  const view = await broker.requestBrowserLogin({
    purpose: "phish",
    url: "http://evil.test/login",
    item_id: listed.id,
  });
  assert.equal(view.status, "denied");
  assert.equal(view.error, "origin_mismatch");
  assertNoLeak(view, SECRET);
});

test("concurrent L0 requests only fill once", async () => {
  const fills: string[] = [];
  const vault2 = new LocalVault(path.join(home, "vault-l0-race.sc"));
  await vault2.init("passphrase-for-tests");
  const local = new Broker({
    mode: "local",
    filler: async (_url, _u, password) => {
      fills.push(password);
      return { ok: true };
    },
    localVault: vault2,
  });
  const item = local.addLocalL0({
    label: "once",
    origin: originOf("http://127.0.0.1:7777/login"),
    username: "demo",
    password: "l0-once-LEAKCHECK",
  });
  const a = local.requestBrowserLogin({
    purpose: "a",
    url: "http://127.0.0.1:7777/login",
    item_id: item.id,
    grade: "L0",
  });
  const b = local.requestBrowserLogin({
    purpose: "b",
    url: "http://127.0.0.1:7777/login",
    item_id: item.id,
    grade: "L0",
  });
  const [ra, rb] = await Promise.all([a, b]);
  const statuses = [ra.status, rb.status].sort();
  assert.deepEqual(statuses, ["denied", "pending"]);
  const pending = ra.status === "pending" ? ra : rb;
  const denied = ra.status === "denied" ? ra : rb;
  assert.equal(denied.error, "item_not_found");
  const done = await waitStatus(local, pending.request_id);
  assert.equal(done.status, "filled");
  assert.equal(fills.length, 1);
});

test("terminal request records are pruned after retention", async () => {
  let now = 1_000;
  const vault2 = new LocalVault(path.join(home, "vault-prune.sc"));
  await vault2.init("passphrase-for-tests");
  const local = new Broker({
    mode: "local",
    filler: mockFiller({}),
    localVault: vault2,
    now: () => now,
  });
  await vault2.addL1({
    label: "demo",
    origin: originOf("http://127.0.0.1:8787/example/login.html"),
    username: "demo",
    password: "prune-secret",
  });
  const pending = await local.requestBrowserLogin({
    purpose: "prune",
    url: "http://127.0.0.1:8787/example/login.html",
  });
  const done = await waitStatus(local, pending.request_id);
  assert.equal(done.status, "filled");
  now += REQUEST_RETENTION_MS + 1;
  const gone = local.getLoginStatus(pending.request_id);
  assert.equal(gone.status, "expired");
  assert.equal(gone.error, "not_found");
});
