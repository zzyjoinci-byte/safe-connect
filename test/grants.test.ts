import assert from "node:assert/strict";
import { before, test } from "node:test";
import { cryptoReady } from "../src/crypto.js";
import { createGrant, openGrant, decryptItem } from "../src/grants.js";
import { generatePairing } from "../src/pairing.js";
import { sealCredential } from "../src/vault.js";

process.env.NODE_ENV = "test";
process.env.SAFE_CONNECT_KDF = "fast";

before(async () => {
  await cryptoReady();
});

test("grant unwraps DEK bound to request_id + url", () => {
  const pairing = generatePairing();
  assert.ok(pairing.privateKey);
  const sealed = sealCredential(pairing.publicKey, {
    username: "demo",
    password: "grant-secret-LEAKCHECK",
  });
  const grant = createGrant({
    pairingKey: pairing.pairingKey,
    publicKey: pairing.publicKey,
    privateKey: pairing.privateKey,
    sealedDekB64: sealed.sealed_dek,
    requestId: "req-1",
    url: "http://127.0.0.1:8787/example/login.html",
    ttlMs: 30_000,
    now: 1_000,
  });
  const dek = openGrant({
    pairingKey: pairing.pairingKey,
    grant,
    requestId: "req-1",
    url: "http://127.0.0.1:8787/example/login.html",
    now: 1_500,
  });
  const cred = decryptItem(dek, sealed.nonce, sealed.ciphertext);
  assert.equal(cred.password, "grant-secret-LEAKCHECK");
});

test("grant expires after ttl", () => {
  const pairing = generatePairing();
  assert.ok(pairing.privateKey);
  const sealed = sealCredential(pairing.publicKey, { username: "u", password: "p" });
  const grant = createGrant({
    pairingKey: pairing.pairingKey,
    publicKey: pairing.publicKey,
    privateKey: pairing.privateKey,
    sealedDekB64: sealed.sealed_dek,
    requestId: "req-exp",
    url: "http://example.test/login",
    ttlMs: 30_000,
    now: 1_000,
  });
  assert.throws(
    () =>
      openGrant({
        pairingKey: pairing.pairingKey,
        grant,
        requestId: "req-exp",
        url: "http://example.test/login",
        now: grant.expires_at + 1,
      }),
    /grant expired/,
  );
});

test("grant refuses URL or request_id mismatch", () => {
  const pairing = generatePairing();
  assert.ok(pairing.privateKey);
  const sealed = sealCredential(pairing.publicKey, { username: "u", password: "p" });
  const grant = createGrant({
    pairingKey: pairing.pairingKey,
    publicKey: pairing.publicKey,
    privateKey: pairing.privateKey,
    sealedDekB64: sealed.sealed_dek,
    requestId: "req-bind",
    url: "http://good.test/login",
    now: 1_000,
  });
  assert.throws(
    () =>
      openGrant({
        pairingKey: pairing.pairingKey,
        grant,
        requestId: "req-bind",
        url: "http://evil.test/login",
        now: 1_001,
      }),
    /url mismatch/,
  );
  assert.throws(
    () =>
      openGrant({
        pairingKey: pairing.pairingKey,
        grant,
        requestId: "other",
        url: "http://good.test/login",
        now: 1_001,
      }),
    /request_id mismatch/,
  );
});

test("grant is single-use", () => {
  const pairing = generatePairing();
  assert.ok(pairing.privateKey);
  const sealed = sealCredential(pairing.publicKey, { username: "u", password: "p" });
  const grant = createGrant({
    pairingKey: pairing.pairingKey,
    publicKey: pairing.publicKey,
    privateKey: pairing.privateKey,
    sealedDekB64: sealed.sealed_dek,
    requestId: "req-once",
    url: "http://good.test/login",
    now: 1_000,
  });
  const consumed = new Set<string>();
  openGrant({
    pairingKey: pairing.pairingKey,
    grant,
    requestId: "req-once",
    url: "http://good.test/login",
    now: 1_001,
    consumed,
  });
  assert.throws(
    () =>
      openGrant({
        pairingKey: pairing.pairingKey,
        grant,
        requestId: "req-once",
        url: "http://good.test/login",
        now: 1_002,
        consumed,
      }),
    /already used/,
  );
});

test("grant ttl is capped at 30s", () => {
  const pairing = generatePairing();
  assert.ok(pairing.privateKey);
  const sealed = sealCredential(pairing.publicKey, { username: "u", password: "p" });
  const grant = createGrant({
    pairingKey: pairing.pairingKey,
    publicKey: pairing.publicKey,
    privateKey: pairing.privateKey,
    sealedDekB64: sealed.sealed_dek,
    requestId: "req-cap",
    url: "http://good.test/login",
    ttlMs: 120_000,
    now: 0,
  });
  assert.equal(grant.expires_at, 30_000);
});
