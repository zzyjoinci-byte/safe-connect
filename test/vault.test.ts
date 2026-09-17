import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { after, before, test } from "node:test";
import { cryptoReady, memzero } from "../src/crypto.js";
import { CloudVault, LocalVault, originOf, sealCredential } from "../src/vault.js";
import { generatePairing } from "../src/pairing.js";
import { testHome } from "./helpers.ts";

process.env.NODE_ENV = "test";
process.env.SAFE_CONNECT_KDF = "fast";

const SECRET = "vault-test-password-LEAKCHECK";
let home: string;

before(async () => {
  await cryptoReady();
  home = testHome();
});

after(() => {
  fs.rmSync(home, { recursive: true, force: true });
});

test("local L1 vault seal/unseal roundtrip", async () => {
  const file = path.join(home, "vault.sc");
  const vault = new LocalVault(file);
  await vault.init("passphrase-for-tests");
  const item = await vault.addL1({
    label: "demo",
    origin: originOf("http://127.0.0.1:8787/example/login.html"),
    username: "demo",
    password: SECRET,
  });
  vault.lock();

  const raw = fs.readFileSync(file);
  assert.equal(raw.subarray(0, 4).toString(), "SC01");
  assert.ok(!raw.includes(Buffer.from(SECRET)));

  const unlocked = new LocalVault(file);
  await unlocked.unlock("passphrase-for-tests");
  const got = unlocked.get(item.id);
  assert.ok(got);
  assert.equal(got.password, SECRET);
  assert.equal(got.username, "demo");
});

test("L0 is not written to the local vault file", async () => {
  const file = path.join(home, "vault-l0.sc");
  const vault = new LocalVault(file);
  await vault.init("passphrase-for-tests");
  const before = fs.readFileSync(file);
  // L0 lives in EphemeralStore (tested in api); vault list is L1 only
  assert.deepEqual(vault.list(), []);
  const after = fs.readFileSync(file);
  assert.equal(before.length, after.length);
});

test("wrong passphrase fails closed", async () => {
  const file = path.join(home, "vault-wrong.sc");
  const vault = new LocalVault(file);
  await vault.init("correct-horse");
  const other = new LocalVault(file);
  await assert.rejects(() => other.unlock("wrong-pass"), /aead decrypt failed|decrypt/);
});

test("cloud vault stores sealed L1 only; plaintext absent on disk", async () => {
  const file = path.join(home, "cloud-vault.sc");
  const pairing = generatePairing();
  const vault = new CloudVault(file);
  vault.configure(pairing.pairingKey, pairing.publicKey);
  const sealed = sealCredential(pairing.publicKey, { username: "demo", password: SECRET });
  vault.addSealed({
    id: "item-1",
    label: "cloud-demo",
    origin: "http://127.0.0.1:8787",
    grade: "L1",
    sealed,
  });
  const disk = fs.readFileSync(file);
  assert.ok(!disk.includes(Buffer.from(SECRET)));
  assert.equal(vault.list()[0]?.grade, "L1");
  memzero(pairing.privateKey);
});
