import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import { createServer } from "node:http";
import path from "node:path";
import { before, test, type TestContext } from "node:test";
import { chromium, type Browser } from "playwright";
import { hexe } from "../src/bytes.js";
import { Broker } from "../src/broker.js";
import { cryptoReady } from "../src/crypto.js";
import { createGrant } from "../src/grants.js";
import { createHttpServer, listen } from "../src/http.js";
import { generatePairing } from "../src/pairing.js";
import { ControlledSessions, type LoginProfile } from "../src/sessions.js";
import { CloudVault, LocalVault, sealCredential } from "../src/vault.js";
import { assertNoLeak, testHome } from "./helpers.ts";

const fakeUser = "synthetic-user";
const fakePass = "synthetic-password-NOT-REAL";
const fakeOtp = "123456";
before(cryptoReady);

async function until(check: () => boolean, timeout = 5_000) {
  const end = Date.now() + timeout;
  while (!check()) {
    assert.ok(Date.now() < end, "timed out waiting for session state");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

async function setup(t: TestContext, opts: {
  local?: boolean; l1?: boolean; entry?: string; wrongItemOrigin?: boolean;
  nextRedirect?: string; delayedPassword?: boolean; noSuccessMarker?: boolean;
  sessionTimeoutMs?: number; retentionMs?: number;
} = {}) {
  const home = testHome("safe-connect-sessions-");
  let submittedPasswords = 0;
  let completedOtp = 0;
  const site = createServer(async (req, res) => {
    const route = new URL(req.url!, "http://127.0.0.1").pathname;
    let data = "";
    for await (const chunk of req) data += chunk;
    const form = new URLSearchParams(data); // Synthetic fixture input only.
    const redirect = (to: string, cookie?: string) => {
      res.writeHead(303, { location: to, ...(cookie ? { "set-cookie": `${cookie}; HttpOnly; SameSite=Strict; Path=/` } : {}) }); res.end();
    };
    res.setHeader("content-type", "text/html");
    if (route === "/login") res.end('<form method="post" action="/username"><input id="username" name="username"><button id="next">Next</button></form>');
    else if (route === "/username") {
      assert.equal(form.get("username"), fakeUser);
      redirect(opts.nextRedirect ?? "/password", "stage=username");
    } else if (route === "/password" && req.method === "GET") {
      const html = '<form method="post" action="/password"><input id="password" name="password" type="password"><button id="submit">Sign in</button></form>';
      res.end(opts.delayedPassword ? `<script>setTimeout(() => { document.body.innerHTML = ${JSON.stringify(html)}; }, 3000)</script>` : html);
    } else if (route === "/password") {
      submittedPasswords++;
      assert.equal(form.get("password"), fakePass);
      redirect("/otp", "stage=password");
    } else if (route === "/otp" && req.method === "GET") res.end('<div id="otp-challenge">Enter synthetic verification code</div><form method="post" action="/otp"><input id="otp" name="otp"><button id="verify">Verify</button></form>');
    else if (route === "/otp") {
      completedOtp++;
      assert.equal(form.get("otp"), fakeOtp);
      redirect("/dashboard", "authenticated=yes");
    } else if (route === "/dashboard") {
      const authenticated = req.headers.cookie?.includes("authenticated=yes");
      res.end(authenticated && !opts.noSuccessMarker ? '<main id="authenticated">Authenticated synthetic fixture</main>' : '<main>No verified session</main>');
    } else if (route === "/captcha") res.end('<div id="captcha-challenge">Human challenge</div>');
    else if (route === "/passkey") res.end('<div id="passkey-challenge">Authenticator required</div>');
    else if (route === "/unknown") redirect("http://127.0.0.1:1/untrusted");
    else { res.statusCode = 404; res.end("missing"); }
  });
  const port = await listen(site, "127.0.0.1", 0);
  const origin = `http://127.0.0.1:${port}`;
  const pairing = generatePairing(); // Disposable test-only companion; never persisted.
  let clock = Date.now();
  const grade = opts.l1 ? "L1" as const : "L0" as const;
  const itemOrigin = opts.wrongItemOrigin ? "https://different.example" : origin;
  let broker: Broker;
  let itemId: string;
  const legacyFiller = async () => { throw new Error("legacy one-page filler must not be used for controlled sessions"); };
  if (opts.local) {
    const vault = new LocalVault(path.join(home, "vault.sc"));
    await vault.init("synthetic-test-passphrase");
    broker = new Broker({ mode: "local", localVault: vault, filler: legacyFiller });
    const input = { label: "synthetic", origin: itemOrigin, username: fakeUser, password: fakePass };
    itemId = (grade === "L0" ? broker.addLocalL0(input) : await broker.addLocalL1(input)).id;
  } else {
    const vault = new CloudVault(path.join(home, "vault.sc"));
    vault.configure(pairing.pairingKey, pairing.publicKey);
    broker = new Broker({ mode: "cloud", cloudVault: vault, filler: legacyFiller,
      pairing: { pairingKey: pairing.pairingKey, publicKey: pairing.publicKey }, now: () => clock });
    broker.heartbeat(pairing.publicKey);
    itemId = broker.addSealedItem({ id: "synthetic-item", label: "synthetic", origin: itemOrigin, grade,
      sealed: sealCredential(pairing.publicKey, { username: fakeUser, password: fakePass }) }).id;
  }
  const profile: LoginProfile = {
    id: "synthetic", entryUrl: origin + (opts.entry ?? "/login"), credentialOrigin: origin,
    usernameSelector: "#username", passwordSelector: "#password", usernameNextSelector: "#next",
    success: { origin, pathname: "/dashboard", selector: "#authenticated" },
    manual: [
      { origin, selector: "#otp-challenge", kind: "otp" },
      { origin, selector: "#captcha-challenge", kind: "captcha" },
      { origin, selector: "#passkey-challenge", kind: "passkey" },
    ],
  };
  let browser: Browser;
  const sessions = new ControlledSessions({ broker, profiles: [profile],
    sessionTimeoutMs: opts.sessionTimeoutMs, retentionMs: opts.retentionMs,
    browserFactory: async () => browser = await chromium.launch({ headless: true }),
  });
  const adminToken = randomBytes(32);
  const api = createHttpServer({ broker, sessions, pairingKey: pairing.pairingKey, adminToken, bind: "127.0.0.1", port: 0 });
  const apiPort = await listen(api, "127.0.0.1", 0);
  const apiBase = `http://127.0.0.1:${apiPort}/v1/${opts.local ? "admin" : "companion"}/sessions`;
  const bearer = `Bearer ${hexe(opts.local ? adminToken : pairing.pairingKey)}`;
  t.after(async () => {
    await sessions.close();
    await new Promise<void>((resolve) => api.close(() => resolve()));
    await new Promise<void>((resolve) => site.close(() => resolve()));
    fs.rmSync(home, { recursive: true, force: true });
  });
  const grant = (requestId: string, ttlMs = 30_000) => {
    const challenge = broker.pullChallenges().find((c) => c.request_id === requestId);
    assert.ok(challenge);
    return createGrant({ pairingKey: pairing.pairingKey, publicKey: pairing.publicKey, privateKey: pairing.privateKey!,
      sealedDekB64: challenge.sealed_dek, requestId, url: challenge.url, ttlMs });
  };
  const apiCall = async (suffix: string, body?: unknown, controlToken?: string, auth = true) => {
    const response = await fetch(apiBase + suffix, { method: body === undefined ? "GET" : "POST",
      headers: { ...(auth ? { authorization: bearer } : {}), "content-type": "application/json", ...(controlToken ? { "x-safe-connect-session": controlToken } : {}) },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const json = await response.json();
    assertNoLeak(json, fakePass); assertNoLeak(json, fakeOtp);
    return { status: response.status, json };
  };
  return { sessions, broker, itemId, origin, profile, grant, apiCall, apiBase, bearer,
    browser: () => browser!, page: () => browser!.contexts()[0]!.pages()[0]!,
    counts: () => ({ submittedPasswords, completedOtp }), staleCompanion: () => { clock += 11_000; } };
}

test("controlled cloud grant fills both steps in one retained session; only synthetic user submits password/MFA", async (t) => {
  const f = await setup(t);
  const created = await f.apiCall("", { profile_id: "synthetic" });
  assert.equal(created.status, 201);
  const s = created.json;
  assert.equal(s.state, "ready_for_credentials");
  const request = await f.apiCall(`/${s.session_id}/credentials`, { revision: s.revision, item_id: f.itemId }, s.control_token);
  assert.equal(request.json.state, "awaiting_grant");
  assert.equal(f.broker.ephemeral.has(f.itemId), false);
  assert.equal(await f.page().locator("#username").inputValue(), "");
  assert.equal(f.broker.pullChallenges()[0]!.session_id, s.session_id);
  const grant = f.grant(request.json.request_id);
  f.broker.applyGrant(grant);
  const status = () => f.sessions.status(s.session_id, s.control_token);
  await until(() => status().state === "awaiting_user_submit");
  assert.equal(await f.page().locator("#password").inputValue(), fakePass);
  assert.deepEqual(f.counts(), { submittedPasswords: 0, completedOtp: 0 });
  assert.equal(f.broker.getLoginStatus(request.json.request_id).status, "filled");
  assert.notEqual(status().state, "authenticated");
  assert.equal(f.broker.applyGrant(grant).error, "no_challenge");

  // Test-only simulated human in the SAME browser context, not a production UI.
  await f.page().locator("#submit").click();
  await f.page().waitForURL(`${f.origin}/otp`);
  const waiting = await f.apiCall(`/${s.session_id}/continue`, { revision: status().revision }, s.control_token);
  assert.equal(waiting.json.state, "manual_required");
  assert.equal(waiting.json.reason, "otp_requires_user");
  assert.equal(waiting.json.operator_surface, "unavailable");
  await f.page().locator("#otp").fill(fakeOtp);
  await f.page().locator("#verify").click();
  await f.page().waitForURL(`${f.origin}/dashboard`);
  const done = await f.apiCall(`/${s.session_id}/continue`, { revision: status().revision }, s.control_token);
  assert.equal(done.json.state, "authenticated");
  assert.equal(f.browser().contexts().length, 1, "authenticated context remains bounded and retained");
  assert.deepEqual(f.counts(), { submittedPasswords: 1, completedOtp: 1 });
  assert.equal((await f.apiCall(`/${s.session_id}/cancel`, {}, s.control_token)).json.state, "cancelled");
  assert.equal(f.browser().contexts().length, 0);
});

test("controlled local L1 uses the existing broker and never reports filled as authenticated", async (t) => {
  const f = await setup(t, { local: true, l1: true });
  const s = await f.sessions.create("synthetic");
  await f.sessions.credentials(s.session_id, s.control_token, s.revision, f.itemId);
  const state = () => f.sessions.status(s.session_id, s.control_token);
  await until(() => state().state === "awaiting_user_submit");
  assert.equal(await f.page().locator("#password").inputValue(), fakePass);
  assert.equal(f.broker.listItems().some((i) => i.id === f.itemId), true);
  assert.equal((await f.sessions.continue(s.session_id, s.control_token, state().revision)).state, "manual_required");
  assert.equal(f.counts().submittedPasswords, 0);
});

test("controlled credential origin mismatch preserves L0 and closes the session", async (t) => {
  const f = await setup(t, { wrongItemOrigin: true });
  const s = await f.sessions.create("synthetic");
  const result = await f.sessions.credentials(s.session_id, s.control_token, s.revision, f.itemId);
  assert.equal(result.state, "blocked");
  assert.equal(f.broker.ephemeral.has(f.itemId), true);
  assert.deepEqual(f.broker.pullChallenges(), []);
  assert.equal(f.browser().contexts().length, 0);
});

test("unknown navigation origin blocks before any credential request", async (t) => {
  const f = await setup(t, { entry: "/unknown" });
  const s = await f.sessions.create("synthetic");
  assert.equal(s.state, "blocked");
  assert.equal(f.broker.ephemeral.has(f.itemId), true);
  assert.deepEqual(f.broker.pullChallenges(), []);
  assert.equal(f.browser().contexts().length, 0);
});

test("cross-origin redirect between credential steps aborts the controlled grant", async (t) => {
  const f = await setup(t, { nextRedirect: "http://127.0.0.1:1/untrusted" });
  const s = await f.sessions.create("synthetic");
  const pending = await f.sessions.credentials(s.session_id, s.control_token, s.revision, f.itemId);
  f.broker.applyGrant(f.grant(pending.request_id!));
  await until(() => f.sessions.status(s.session_id, s.control_token).state === "blocked");
  await until(() => f.browser().contexts().length === 0);
  assert.equal(f.counts().submittedPasswords, 0);
});

test("session capabilities, cookie jars and revisions isolate concurrent sessions and L0 use", async (t) => {
  const f = await setup(t);
  const a = await f.sessions.create("synthetic");
  const contextA = f.browser().contexts()[0]!;
  await contextA.addCookies([{ name: "synthetic-isolation", value: "only-a", url: f.origin }]);
  const b = await f.sessions.create("synthetic");
  const contextB = f.browser().contexts()[1]!;
  assert.equal((await contextB.cookies()).length, 0);
  assert.throws(() => f.sessions.status(b.session_id, a.control_token), /session_not_found/);
  await assert.rejects(() => f.sessions.cancel(b.session_id, a.control_token), /session_not_found/);
  const requests = await Promise.all([
    f.sessions.credentials(a.session_id, a.control_token, a.revision, f.itemId),
    f.sessions.credentials(b.session_id, b.control_token, b.revision, f.itemId),
  ]);
  assert.equal(requests.filter((r) => r.state === "awaiting_grant").length, 1);
  assert.equal(requests.filter((r) => r.state === "blocked").length, 1);
  assert.equal(f.broker.pullChallenges().length, 1);
  const winner = requests.find((r) => r.state === "awaiting_grant")!;
  const auth = winner.session_id === a.session_id ? a : b;
  await assert.rejects(() => f.sessions.credentials(auth.session_id, auth.control_token, auth.revision, f.itemId), /stale_revision/);
  f.broker.applyGrant(f.grant(winner.request_id!));
  await until(() => f.sessions.status(auth.session_id, auth.control_token).state === "awaiting_user_submit");
  const current = f.sessions.status(auth.session_id, auth.control_token);
  const advances = await Promise.allSettled([
    f.sessions.continue(auth.session_id, auth.control_token, current.revision),
    f.sessions.continue(auth.session_id, auth.control_token, current.revision),
  ]);
  assert.equal(advances.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal(advances.filter((r) => r.status === "rejected").length, 1);
});

test("cancel pending grant rejects late grant and cleans isolated storage", async (t) => {
  const f = await setup(t);
  const s = await f.sessions.create("synthetic");
  const pending = await f.sessions.credentials(s.session_id, s.control_token, s.revision, f.itemId);
  const grant = f.grant(pending.request_id!);
  await f.sessions.cancel(s.session_id, s.control_token);
  assert.equal(f.broker.applyGrant(grant).error, "no_challenge");
  assert.equal(f.sessions.status(s.session_id, s.control_token).state, "cancelled");
  assert.equal(f.browser().contexts().length, 0);
  assert.equal(f.broker.ephemeral.has(f.itemId), false);
});

test("a grant for one same-origin session cannot be reassigned to another session", async (t) => {
  const f = await setup(t, { l1: true });
  const a = await f.sessions.create("synthetic");
  const b = await f.sessions.create("synthetic");
  const ra = await f.sessions.credentials(a.session_id, a.control_token, a.revision, f.itemId);
  const rb = await f.sessions.credentials(b.session_id, b.control_token, b.revision, f.itemId);
  const grant = f.grant(ra.request_id!);
  f.broker.applyGrant({ ...grant, request_id: rb.request_id! });
  await until(() => f.sessions.status(b.session_id, b.control_token).state === "blocked");
  assert.equal(f.sessions.status(a.session_id, a.control_token).state, "awaiting_grant");
  assert.equal(await f.page().locator("#username").inputValue(), "");
  f.broker.applyGrant(grant);
  await until(() => f.sessions.status(a.session_id, a.control_token).state === "awaiting_user_submit");
  assert.equal(f.counts().submittedPasswords, 0);
});

test("profiles reject wildcard origins and do not infer identity origin from a portal", async (t) => {
  const f = await setup(t);
  assert.throws(() => new ControlledSessions({ broker: f.broker, profiles: [{ ...f.profile, credentialOrigin: "https://*.example.com" }] }), /invalid_profile/);
  assert.throws(() => new ControlledSessions({ broker: f.broker, profiles: [{ ...f.profile, credentialOrigin: "https://identity.example/login" }] }), /invalid_profile/);
  const isolated = new ControlledSessions({ broker: f.broker,
    profiles: [{ ...f.profile, credentialOrigin: "https://identity.example" }],
    browserFactory: () => chromium.launch({ headless: true }),
  });
  try {
    const s = await isolated.create("synthetic");
    assert.equal(s.state, "manual_required");
    assert.equal(s.reason, "credential_origin_not_reached");
    await assert.rejects(() => isolated.credentials(s.session_id, s.control_token, s.revision, f.itemId), /invalid_state/);
    assert.equal(f.broker.ephemeral.has(f.itemId), true);
  } finally { await isolated.close(); }
});

for (const action of ["cancel", "grant deadline"] as const) {
  test(`${action} interrupts a credential phase waiting for the password page`, async (t) => {
    const f = await setup(t, { delayedPassword: true });
    const s = await f.sessions.create("synthetic");
    const pending = await f.sessions.credentials(s.session_id, s.control_token, s.revision, f.itemId);
    f.broker.applyGrant(f.grant(pending.request_id!, action === "grant deadline" ? 500 : 30_000));
    await until(() => f.sessions.status(s.session_id, s.control_token).state === "filling");
    if (action === "cancel") await f.sessions.cancel(s.session_id, s.control_token);
    await until(() => f.sessions.status(s.session_id, s.control_token).state === (action === "cancel" ? "cancelled" : "expired"));
    await until(() => f.browser().contexts().length === 0);
    assert.equal(f.counts().submittedPasswords, 0);
    assert.notEqual(f.broker.getLoginStatus(pending.request_id!).status, "filled");
  });
}

test("session deadline and loss of companion fail closed", async (t) => {
  const f = await setup(t, { sessionTimeoutMs: 1200 });
  const s = await f.sessions.create("synthetic");
  assert.equal(s.state, "ready_for_credentials");
  await until(() => f.sessions.status(s.session_id, s.control_token).state === "expired", 2_000);
  await until(() => f.browser().contexts().length === 0);
  const next = await f.sessions.create("synthetic");
  f.staleCompanion();
  assert.equal(f.sessions.status(next.session_id, next.control_token).state, "blocked");
  await until(() => f.browser().contexts().length === 0);
  await assert.rejects(() => f.sessions.create("synthetic"), /companion_missing/);
});

for (const kind of ["captcha", "passkey"] as const) {
  test(`${kind} stays manual_required without a fictional operator UI or credential fill`, async (t) => {
    const f = await setup(t, { entry: `/${kind}` });
    const s = await f.sessions.create("synthetic");
    assert.equal(s.state, "manual_required");
    assert.equal(s.reason, `${kind}_requires_user`);
    assert.equal((await f.sessions.continue(s.session_id, s.control_token, s.revision)).state, "manual_required");
    await assert.rejects(() => f.sessions.credentials(s.session_id, s.control_token, f.sessions.status(s.session_id, s.control_token).revision, f.itemId), /invalid_state/);
    assert.equal(f.broker.ephemeral.has(f.itemId), true);
  });
}

test("operator HTTP API requires both authentication and session capability; refuses plaintext and agent-selected profiles", async (t) => {
  const f = await setup(t);
  assert.equal((await f.apiCall("", { profile_id: "synthetic" }, undefined, false)).status, 401);
  assert.equal((await f.apiCall("", { profile_id: "synthetic", origin: "https://evil.example" })).status, 400);
  assert.equal((await f.apiCall("", { profile_id: "unknown" })).status, 400);
  const s = (await f.apiCall("", { profile_id: "synthetic" })).json;
  assert.equal((await f.apiCall(`/${s.session_id}`)).status, 404);
  for (const action of ["credentials", "continue", "cancel"]) {
    const result = await f.apiCall(`/${s.session_id}/${action}`, { revision: s.revision, item_id: f.itemId, password: "fake", otp: "fake" }, s.control_token);
    assert.equal(result.status, 400);
  }
  const browserOrigin = await fetch(f.apiBase, { method: "POST", headers: { authorization: f.bearer, origin: "http://untrusted.example", "content-type": "application/json" }, body: JSON.stringify({ profile_id: "synthetic" }) });
  assert.equal(browserOrigin.status, 403);
  assert.deepEqual(f.broker.pullChallenges(), []);
});

for (const noSuccessMarker of [false, true]) {
  test(noSuccessMarker ? "missing success evidence never authenticates" : "authenticated session expires and destroys its retained context", async (t) => {
    const f = await setup(t, { local: true, noSuccessMarker, retentionMs: 150 });
    const s = await f.sessions.create("synthetic");
    await f.sessions.credentials(s.session_id, s.control_token, s.revision, f.itemId);
    const state = () => f.sessions.status(s.session_id, s.control_token);
    await until(() => state().state === "awaiting_user_submit");
    await f.page().locator("#submit").click();
    await f.page().waitForURL(`${f.origin}/otp`);
    await f.page().locator("#otp").fill(fakeOtp);
    await f.page().locator("#verify").click();
    await f.page().waitForURL(`${f.origin}/dashboard`);
    const result = await f.sessions.continue(s.session_id, s.control_token, state().revision);
    assert.equal(result.state, noSuccessMarker ? "manual_required" : "authenticated");
    if (!noSuccessMarker) {
      await until(() => state().state === "expired");
      await until(() => f.browser().contexts().length === 0);
    }
  });
}
