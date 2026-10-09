import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { before, test, type TestContext } from "node:test";
import { Broker } from "../src/broker.js";
import { cryptoReady } from "../src/crypto.js";
import { generatePairing } from "../src/pairing.js";
import type { Filler, Grade, Mode } from "../src/types.js";
import { CloudVault, LocalVault, sealCredential } from "../src/vault.js";
import { testHome, waitStatus } from "./helpers.ts";

const origin = "https://login.example";
const url = `${origin}/login`;
const credential = { username: "demo", password: "regression-FAKE-password" };
before(cryptoReady);

async function fixture(t: TestContext, mode: Mode, grade: Grade, filler: Filler,
  storedOrigin = origin) {
  const home = testHome();
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  let broker: Broker;
  let id: string;
  if (mode === "local") {
    const vault = new LocalVault(path.join(home, "vault.sc"));
    await vault.init("fake-test-passphrase");
    broker = new Broker({ mode, filler, localVault: vault });
    const input = { label: "regression", origin: storedOrigin, ...credential };
    id = (grade === "L0" ? broker.addLocalL0(input) : await broker.addLocalL1(input)).id;
  } else {
    // Test-only pairing material; never saved as a companion configuration.
    const pairing = generatePairing();
    const vault = new CloudVault(path.join(home, "cloud.sc"));
    vault.configure(pairing.pairingKey, pairing.publicKey);
    broker = new Broker({ mode, filler, cloudVault: vault, pairing });
    broker.heartbeat(pairing.publicKey);
    id = broker.addSealedItem({ id: "test-item", label: "regression", origin: storedOrigin,
      grade, sealed: sealCredential(pairing.publicKey, credential) }).id;
  }
  t.after(() => {
    for (const challenge of broker.pullChallenges()) broker.deny(challenge.request_id);
  });
  const approve = (requestId: string) => {
    if (mode !== "cloud") return;
    const challenge = broker.pullChallenges().find((c) => c.request_id === requestId);
    assert.ok(challenge);
    broker.applyGrant(broker.createCompanionGrant(challenge));
  };
  return { broker, id, approve };
}

for (const mode of ["local", "cloud"] as const) {
  for (const grade of ["L0", "L1"] as const) {
    test(`${mode} ${grade}: explicit item_id enforces normalized origin`, async (t) => {
      let fills = 0;
      const { broker, id, approve } = await fixture(t, mode, grade, async () => {
        fills++;
        return { ok: true };
      }, "https://LOGIN.example:443");
      for (const wrongUrl of ["https://evil.example/login", "http://login.example/login",
        "https://login.example:444/login", "https://sub.login.example/login",
        "https://login.example@evil.example/login"]) {
        const denied = await broker.requestBrowserLogin({ purpose: "wrong origin", url: wrongUrl, item_id: id });
        assert.equal(denied.status, "denied", wrongUrl);
        assert.equal(denied.error, "item_not_found");
        assert.equal(fills, 0);
        assert.deepEqual(broker.pullChallenges(), []);
        assert.ok(broker.listItems().some((item) => item.id === id), "mismatch must not consume L0");
      }
      const allowed = await broker.requestBrowserLogin({ purpose: "normalized origin",
        url: "https://LOGIN.EXAMPLE:443/another/path?q=1#fragment", item_id: id });
      approve(allowed.request_id);
      assert.equal((await waitStatus(broker, allowed.request_id)).status, "filled");
      assert.equal(fills, 1);
    });
  }

  for (const explicitId of [false, true]) {
    test(`${mode} L0: concurrent ${explicitId ? "item_id" : "origin"} requests fill at most once`, async (t) => {
      let calls = 0;
      let release!: () => void;
      let entered!: () => void;
      const gate = new Promise<void>((resolve) => { release = resolve; });
      const started = new Promise<void>((resolve) => { entered = resolve; });
      t.after(() => release());
      const { broker, id, approve } = await fixture(t, mode, "L0", async () => {
        calls++;
        entered();
        await gate;
        return { ok: true };
      });
      const input = { purpose: "concurrent", url, grade: "L0" as const,
        ...(explicitId ? { item_id: id } : {}) };
      const results = await Promise.all(Array.from({ length: 8 }, () => broker.requestBrowserLogin(input)));
      const accepted = results.filter((r) => r.status === "pending");
      assert.equal(accepted.length, 1);
      assert.equal(results.filter((r) => r.status === "denied").length, 7);
      assert.equal(broker.ephemeral.has(id), false, "consumed before any async work completes");
      if (mode === "cloud") assert.equal(broker.pullChallenges().length, 1);
      approve(accepted[0]!.request_id);
      await started;
      assert.equal(calls, 1);
      const duringFill = await broker.requestBrowserLogin(input);
      assert.equal(duringFill.status, "denied");
      release();
      assert.equal((await waitStatus(broker, accepted[0]!.request_id)).status, "filled");
      assert.equal((await broker.requestBrowserLogin(input)).status, "denied");
      assert.equal(calls, 1);
    });
  }

  for (const throws of [false, true]) {
    test(`${mode} L0: ${throws ? "throwing" : "failed"} fill cannot reuse consumed item`, async (t) => {
      let calls = 0;
      const { broker, id, approve } = await fixture(t, mode, "L0", async () => {
        calls++;
        if (throws) throw new Error("fake failure");
        return { ok: false, error: "fake_failure" };
      });
      const input = { purpose: "failed attempt", url, item_id: id };
      const request = await broker.requestBrowserLogin(input);
      approve(request.request_id);
      assert.equal((await waitStatus(broker, request.request_id)).status, "denied");
      assert.equal((await broker.requestBrowserLogin(input)).status, "denied");
      assert.equal(calls, 1);
    });
  }

  test(`${mode} L1 remains reusable`, async (t) => {
    let calls = 0;
    const { broker, id, approve } = await fixture(t, mode, "L1", async () => {
      calls++;
      return { ok: true };
    });
    for (let i = 0; i < 2; i++) {
      const request = await broker.requestBrowserLogin({ purpose: "reusable", url, item_id: id });
      approve(request.request_id);
      assert.equal((await waitStatus(broker, request.request_id)).status, "filled");
    }
    assert.equal(calls, 2);
  });
}

for (const outcome of ["deny", "timeout", "invalid grant"] as const) {
  test(`cloud L0: ${outcome} burns the reserved item without filling`, async (t) => {
    let calls = 0;
    const { broker, id } = await fixture(t, "cloud", "L0", async () => {
      calls++;
      return { ok: true };
    });
    const input = { purpose: outcome, url, item_id: id, ttl_seconds: outcome === "timeout" ? 0.05 : 30 };
    const request = await broker.requestBrowserLogin(input);
    if (outcome === "deny") broker.deny(request.request_id);
    if (outcome === "invalid grant") {
      const grant = broker.createCompanionGrant(broker.pullChallenges()[0]!);
      grant.url = "https://evil.example/login";
      broker.applyGrant(grant);
    }
    assert.equal((await waitStatus(broker, request.request_id)).status, outcome === "timeout" ? "expired" : "denied");
    assert.equal((await broker.requestBrowserLogin(input)).status, "denied");
    assert.equal(calls, 0);
  });
}
