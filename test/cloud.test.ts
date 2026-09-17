import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { after, before, test } from "node:test";
import { hexe } from "../src/bytes.js";
import { Broker } from "../src/broker.js";
import { cryptoReady } from "../src/crypto.js";
import { mockFiller } from "../src/fill.js";
import { createGrant } from "../src/grants.js";
import { createHttpServer, listen } from "../src/http.js";
import { generatePairing } from "../src/pairing.js";
import { CloudVault, originOf, sealCredential } from "../src/vault.js";
import { assertNoLeak, testHome, waitStatus } from "./helpers.ts";

process.env.NODE_ENV = "test";
process.env.SAFE_CONNECT_KDF = "fast";

const SECRET = "cloud-password-LEAKCHECK";
let home: string;

before(async () => {
  await cryptoReady();
  home = testHome();
});

after(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

test("cloud health and fill fail closed without companion", async () => {
  const pairing = generatePairing();
  const vault = new CloudVault(path.join(home, "cloud.sc"));
  vault.configure(pairing.pairingKey, pairing.publicKey);
  const fillStore: { last?: { url: string; username: string; password: string } } = {};
  const broker = new Broker({
    mode: "cloud",
    filler: mockFiller(fillStore),
    cloudVault: vault,
    pairing: { pairingKey: pairing.pairingKey, publicKey: pairing.publicKey },
  });
  const health = broker.health();
  assert.equal(health.httpStatus, 503);
  assert.equal(health.body.companion, "missing");
  assert.equal(health.body.status, "fail_closed");

  const sealed = sealCredential(pairing.publicKey, { username: "demo", password: SECRET });
  broker.addSealedItem({
    id: "c1",
    label: "demo",
    origin: originOf("http://127.0.0.1:8787/example/login.html"),
    grade: "L1",
    sealed,
  });
  const view = await broker.requestBrowserLogin({
    purpose: "no-companion",
    url: "http://127.0.0.1:8787/example/login.html",
    item_id: "c1",
  });
  assert.equal(view.status, "denied");
  assert.equal(view.error, "companion_missing");
  assert.equal(fillStore.last, undefined);
  assertNoLeak(view, SECRET);
});

test("HTTP 503 when companion missing", async () => {
  const pairing = generatePairing();
  const vault = new CloudVault(path.join(home, "cloud-http.sc"));
  vault.configure(pairing.pairingKey, pairing.publicKey);
  const broker = new Broker({
    mode: "cloud",
    filler: mockFiller({}),
    cloudVault: vault,
    pairing: { pairingKey: pairing.pairingKey, publicKey: pairing.publicKey },
  });
  const server = createHttpServer({
    broker,
    pairingKey: pairing.pairingKey,
    bind: "127.0.0.1",
    port: 0,
  });
  const port = await listen(server, "127.0.0.1", 0);
  try {
    const health = await fetch(`http://127.0.0.1:${port}/v1/health`);
    assert.equal(health.status, 503);
    const fill = await fetch(`http://127.0.0.1:${port}/v1/request_browser_login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        purpose: "x",
        url: "http://127.0.0.1:8787/example/login.html",
      }),
    });
    assert.equal(fill.status, 503);
    const body = await fill.json();
    assert.equal(body.error, "companion_missing");
    assertNoLeak(body, SECRET);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("cloud L1 fill succeeds with companion grant; plaintext not in API", async () => {
  const pairing = generatePairing();
  assert.ok(pairing.privateKey);
  const vaultPath = path.join(home, "cloud-grant.sc");
  const vault = new CloudVault(vaultPath);
  vault.configure(pairing.pairingKey, pairing.publicKey);
  const fillStore: { last?: { url: string; username: string; password: string } } = {};
  const broker = new Broker({
    mode: "cloud",
    filler: mockFiller(fillStore),
    cloudVault: vault,
    pairing: { pairingKey: pairing.pairingKey, publicKey: pairing.publicKey },
  });
  broker.heartbeat(pairing.publicKey);
  assert.equal(broker.health().httpStatus, 200);

  const sealed = sealCredential(pairing.publicKey, { username: "demo", password: SECRET });
  broker.addSealedItem({
    id: "l1",
    label: "demo",
    origin: originOf("http://127.0.0.1:8787/example/login.html"),
    grade: "L1",
    sealed,
  });
  assert.ok(!fs.readFileSync(vaultPath).includes(Buffer.from(SECRET)));

  const pending = await broker.requestBrowserLogin({
    purpose: "login",
    url: "http://127.0.0.1:8787/example/login.html",
    item_id: "l1",
  });
  assert.equal(pending.status, "pending");
  assertNoLeak(pending, SECRET);

  let challenge;
  for (let i = 0; i < 50; i++) {
    challenge = broker.pullChallenges().find((c) => c.request_id === pending.request_id);
    if (challenge) break;
    await sleep(20);
  }
  assert.ok(challenge);
  const grant = createGrant({
    pairingKey: pairing.pairingKey,
    publicKey: pairing.publicKey,
    privateKey: pairing.privateKey,
    sealedDekB64: challenge.sealed_dek,
    requestId: challenge.request_id,
    url: challenge.url,
  });
  broker.applyGrant(grant);
  const done = await waitStatus(broker, pending.request_id);
  assert.equal(done.status, "filled");
  assert.equal(fillStore.last?.password, SECRET);
  assertNoLeak(done, SECRET);
});

test("cloud L0 stays off disk and still needs grant", async () => {
  const pairing = generatePairing();
  assert.ok(pairing.privateKey);
  const vaultPath = path.join(home, "cloud-l0.sc");
  const vault = new CloudVault(vaultPath);
  vault.configure(pairing.pairingKey, pairing.publicKey);
  const fillStore: { last?: { url: string; username: string; password: string } } = {};
  const broker = new Broker({
    mode: "cloud",
    filler: mockFiller(fillStore),
    cloudVault: vault,
    pairing: { pairingKey: pairing.pairingKey, publicKey: pairing.publicKey },
  });
  broker.heartbeat(pairing.publicKey);
  const l0secret = "cloud-l0-LEAKCHECK";
  const sealed = sealCredential(pairing.publicKey, { username: "demo", password: l0secret });
  const item = broker.addSealedItem({
    id: "l0-item-unique-aabbccddeeff",
    label: "once",
    origin: originOf("http://127.0.0.1:8888/login"),
    grade: "L0",
    sealed,
  });
  const disk = fs.readFileSync(vaultPath);
  assert.ok(!disk.includes(Buffer.from(l0secret)));
  assert.ok(!disk.includes(Buffer.from(item.id)));

  const pending = await broker.requestBrowserLogin({
    purpose: "l0",
    url: "http://127.0.0.1:8888/login",
    item_id: "l0-item-unique-aabbccddeeff",
    grade: "L0",
  });
  let challenge;
  for (let i = 0; i < 50; i++) {
    challenge = broker.pullChallenges()[0];
    if (challenge) break;
    await sleep(20);
  }
  assert.ok(challenge);
  broker.applyGrant(
    createGrant({
      pairingKey: pairing.pairingKey,
      publicKey: pairing.publicKey,
      privateKey: pairing.privateKey,
      sealedDekB64: challenge.sealed_dek,
      requestId: challenge.request_id,
      url: challenge.url,
    }),
  );
  const done = await waitStatus(broker, pending.request_id);
  assert.equal(done.status, "filled");
  assertNoLeak(done, l0secret);
  assert.equal(broker.listItems().some((i) => i.id === "l0-item-unique-aabbccddeeff"), false);
});

test("companion deny marks request denied", async () => {
  const pairing = generatePairing();
  const vault = new CloudVault(path.join(home, "cloud-deny.sc"));
  vault.configure(pairing.pairingKey, pairing.publicKey);
  const broker = new Broker({
    mode: "cloud",
    filler: mockFiller({}),
    cloudVault: vault,
    pairing: { pairingKey: pairing.pairingKey, publicKey: pairing.publicKey },
  });
  broker.heartbeat(pairing.publicKey);
  const sealed = sealCredential(pairing.publicKey, { username: "demo", password: SECRET });
  broker.addSealedItem({
    id: "d1",
    label: "demo",
    origin: originOf("http://127.0.0.1:8787/x"),
    grade: "L1",
    sealed,
  });
  const pending = await broker.requestBrowserLogin({
    purpose: "deny-me",
    url: "http://127.0.0.1:8787/x",
    item_id: "d1",
  });
  for (let i = 0; i < 50; i++) {
    if (broker.pullChallenges().length) break;
    await sleep(20);
  }
  broker.deny(pending.request_id);
  const done = await waitStatus(broker, pending.request_id);
  assert.equal(done.status, "denied");
  assert.equal(done.error, "user_denied");
});

test("pairing bearer is required for companion routes", async () => {
  const pairing = generatePairing();
  const vault = new CloudVault(path.join(home, "cloud-auth.sc"));
  vault.configure(pairing.pairingKey, pairing.publicKey);
  const broker = new Broker({
    mode: "cloud",
    filler: mockFiller({}),
    cloudVault: vault,
    pairing: { pairingKey: pairing.pairingKey, publicKey: pairing.publicKey },
  });
  const server = createHttpServer({
    broker,
    pairingKey: pairing.pairingKey,
    bind: "127.0.0.1",
    port: 0,
  });
  const port = await listen(server, "127.0.0.1", 0);
  try {
    const unauth = await fetch(`http://127.0.0.1:${port}/v1/companion/challenges`);
    assert.equal(unauth.status, 401);
    const ok = await fetch(`http://127.0.0.1:${port}/v1/companion/heartbeat`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${hexe(pairing.pairingKey)}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ public_key: hexe(pairing.publicKey) }),
    });
    assert.equal(ok.status, 200);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});
