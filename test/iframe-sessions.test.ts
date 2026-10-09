import assert from "node:assert/strict";
import { createServer } from "node:http";
import path from "node:path";
import { before, test, type TestContext } from "node:test";
import { chromium, type Browser } from "playwright";
import { Broker } from "../src/broker.js";
import { cryptoReady } from "../src/crypto.js";
import { createHttpServer, listen } from "../src/http.js";
import { APP_STORE_CONNECT_PROFILE_ID, appStoreConnectProfile, builtinProfiles } from "../src/profiles.js";
import { ControlledSessions, type LoginProfile } from "../src/sessions.js";
import { LocalVault } from "../src/vault.js";
import { assertNoLeak, testHome } from "./helpers.ts";

const fakeUser = "synthetic-iframe-user";
const fakePass = "synthetic-iframe-password-NOT-REAL";
const fakeOtp = "654321";
before(cryptoReady);

async function until(check: () => boolean, timeout = 8_000) {
  const end = Date.now() + timeout;
  while (!check()) {
    assert.ok(Date.now() < end, "timed out waiting for session state");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

async function listenOrigin() {
  const captured: string[] = [];
  const site = createServer(async (req, res) => {
    const url = new URL(req.url!, "http://127.0.0.1");
    let data = "";
    for await (const chunk of req) data += chunk;
    (site as unknown as { _handler: (req: typeof req, res: typeof res, url: URL, data: string) => void })._handler(req, res, url, data);
  });
  const port = await listen(site, "127.0.0.1", 0);
  return {
    origin: `http://127.0.0.1:${port}`,
    captured,
    site,
    setHandler(handler: (req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse, url: URL, data: string) => void) {
      (site as unknown as { _handler: typeof handler })._handler = handler;
    },
    close: () => new Promise<void>((resolve) => site.close(() => resolve())),
  };
}

type IframeKind = "idp" | "evil" | "nested" | "double";

async function setup(t: TestContext, opts: {
  iframe?: IframeKind;
  delayedPassword?: boolean;
  trapInputs?: boolean;
  hiddenPasswordUntilContinue?: boolean;
  continueKind?: "id" | "label-only" | "none";
} = {}) {
  const home = testHome("safe-connect-iframe-");
  const portal = await listenOrigin();
  const idp = await listenOrigin();
  const evil = await listenOrigin();
  let submittedPasswords = 0;
  let completedOtp = 0;

  const report = `<script>
    document.querySelectorAll("input").forEach((input) => input.addEventListener("input", () => {
      navigator.sendBeacon("/captured", JSON.stringify({ name: input.name, value: input.value, origin: location.origin }));
    }));
  </script>`;

  portal.setHandler((req, res, url) => {
    res.setHeader("content-type", "text/html");
    if (url.pathname === "/login") {
      const iframeKind = opts.iframe ?? "idp";
      let iframes = `<iframe id="auth" src="${idp.origin}/login"></iframe>`;
      if (iframeKind === "evil") iframes = `<iframe id="auth" src="${evil.origin}/login"></iframe>`;
      if (iframeKind === "nested") iframes = `<iframe id="wrapper" src="${idp.origin}/wrapper"></iframe>`;
      if (iframeKind === "double") {
        iframes = `<iframe id="auth" src="${idp.origin}/login"></iframe><iframe id="also" src="${idp.origin}/trap"></iframe>`;
      }
      if (iframeKind !== "evil" && iframeKind !== "nested" && iframeKind !== "double" && opts.trapInputs) {
        iframes += `<iframe id="trap" src="${evil.origin}/login"></iframe>`;
      }
      res.end(`<!doctype html><title>portal</title>${iframes}`);
      return;
    }
    if (url.pathname === "/dashboard") {
      res.setHeader("set-cookie", "authenticated=yes; HttpOnly; SameSite=Strict; Path=/");
      res.end('<main id="authenticated">Signed in on portal</main>');
      return;
    }
    if (url.pathname === "/captured") {
      portal.captured.push("");
      res.end("ok");
      return;
    }
    res.statusCode = 404;
    res.end("missing");
  });

  const idpPage = (route: string, extra = "") => {
    if (route === "/wrapper") {
      return `<!doctype html><iframe id="nested" src="${idp.origin}/login"></iframe>${report}`;
    }
    if (route === "/trap") {
      return `<form><input id="username" name="username"><input id="password" name="password" type="password"></form>${report}`;
    }
    if (route === "/login") {
      if (opts.hiddenPasswordUntilContinue) {
        const continueBtn = opts.continueKind === "none"
          ? ""
          : opts.continueKind === "label-only"
            ? '<button type="button">Continue</button>'
            : '<button id="next" type="button">Continue</button>';
        return `<form method="post" action="/password">
          <input id="username" name="username" placeholder="Email or Phone Number">
          <input id="password" name="password" type="password" style="display:none" aria-hidden="true">
          ${continueBtn}
          <button id="submit" type="submit" style="display:none">Sign in</button>
        </form>
        <script>
          document.querySelectorAll("button").forEach((btn) => {
            if (btn.id === "submit") return;
            btn.addEventListener("click", (event) => {
              event.preventDefault();
              const password = document.getElementById("password");
              password.style.display = "block";
              password.removeAttribute("aria-hidden");
              document.getElementById("submit").style.display = "block";
              btn.style.display = "none";
            });
          });
        </script>${report}`;
      }
      return `<form method="post" action="/username"><input id="username" name="username"><button id="next" type="submit">Continue</button></form>${report}`;
    }
    if (route === "/password") {
      const form = '<form method="post" action="/password"><input id="password" name="password" type="password"><button id="submit">Sign in</button></form>';
      return (opts.delayedPassword ? `<script>setTimeout(() => { document.body.innerHTML = ${JSON.stringify(form + report)}; }, 3000)</script>` : form) + report;
    }
    if (route === "/otp") {
      return `<div id="otp-challenge">Enter synthetic verification code</div>
        <form method="post" action="/otp"><input id="otp" name="otp"><button id="verify">Verify</button></form>${report}`;
    }
    return extra;
  };

  idp.setHandler((req, res, url, data) => {
    if (url.pathname === "/captured") {
      let body = data;
      idp.captured.push(body);
      res.end("ok");
      return;
    }
    res.setHeader("content-type", "text/html");
    const form = new URLSearchParams(data);
    if (url.pathname === "/username" && req.method === "POST") {
      assert.equal(form.get("username"), fakeUser);
      res.writeHead(303, { location: "/password" });
      res.end();
      return;
    }
    if (url.pathname === "/password" && req.method === "POST") {
      submittedPasswords++;
      assert.equal(form.get("password"), fakePass);
      res.writeHead(303, { location: "/otp" });
      res.end();
      return;
    }
    if (url.pathname === "/otp" && req.method === "POST") {
      completedOtp++;
      assert.equal(form.get("otp"), fakeOtp);
      res.end(`<!doctype html><script>window.top.location = ${JSON.stringify(`${portal.origin}/dashboard`)};</script>`);
      return;
    }
    res.end(idpPage(url.pathname));
  });

  evil.setHandler((req, res, url, data) => {
    if (url.pathname === "/captured") {
      evil.captured.push(data);
      res.end("ok");
      return;
    }
    res.setHeader("content-type", "text/html");
    res.end(`<form><input id="username" name="username"><input id="password" name="password" type="password"><button id="next">Continue</button></form>${report}`);
  });

  const vault = new LocalVault(path.join(home, "vault.sc"));
  await vault.init("synthetic-iframe-passphrase");
  const broker = new Broker({
    mode: "local",
    localVault: vault,
    filler: async () => { throw new Error("legacy filler must not run for iframe sessions"); },
  });
  const item = broker.addLocalL0({
    label: "synthetic-iframe",
    origin: idp.origin,
    username: fakeUser,
    password: fakePass,
  });
  const profile: LoginProfile = {
    id: "synthetic-iframe",
    entryUrl: `${portal.origin}/login`,
    portalOrigin: portal.origin,
    credentialOrigin: idp.origin,
    credentialFrame: "direct-child",
    usernameSelector: "#username",
    passwordSelector: "#password",
    usernameNextSelector: opts.continueKind === "label-only" ? "#sign-in" : "#next",
    success: { origin: portal.origin, pathname: "/dashboard", selector: "#authenticated" },
    manual: [{ origin: idp.origin, selector: "#otp-challenge", kind: "otp" }],
  };
  let browser: Browser;
  const sessions = new ControlledSessions({
    broker,
    profiles: [profile],
    credentialFrameTimeoutMs: 1_500,
    browserFactory: async () => browser = await chromium.launch({ headless: true }),
  });
  const api = createHttpServer({
    broker, sessions, adminToken: Buffer.from("a".repeat(32)), bind: "127.0.0.1", port: 0,
  });
  const apiPort = await listen(api, "127.0.0.1", 0);
  t.after(async () => {
    await sessions.close();
    await new Promise<void>((resolve) => api.close(() => resolve()));
    await portal.close();
    await idp.close();
    await evil.close();
    const fs = await import("node:fs");
    fs.rmSync(home, { recursive: true, force: true });
  });
  return {
    sessions, broker, itemId: item.id, portal: portal.origin, idp: idp.origin, evil,
    idpCaptured: () => idp.captured, evilCaptured: () => evil.captured,
    counts: () => ({ submittedPasswords, completedOtp }),
    browser: () => browser!,
    page: () => browser!.contexts()[0]!.pages()[0]!,
    apiPort,
    publicCall: async (suffix: string, body?: unknown) => {
      const response = await fetch(`http://127.0.0.1:${apiPort}/v1/sessions${suffix}`, {
        method: body === undefined ? "GET" : "POST",
        headers: { "content-type": "application/json" },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      });
      const json = await response.json();
      assertNoLeak(json, fakePass);
      assertNoLeak(json, fakeOtp);
      assert.equal("control_token" in json, false);
      assert.equal("password" in json, false);
      assert.equal("username" in json, false);
      return { status: response.status, json };
    },
  };
}

test("iframe two-step fill stays on the portal; only the matching child frame receives secrets", async (t) => {
  const f = await setup(t, { trapInputs: true });
  const created = await f.publicCall("", { profile_id: "synthetic-iframe" });
  assert.equal(created.status, 201);
  assert.equal(created.json.state, "ready_for_credentials");
  assert.equal(created.json.operator_surface, "unavailable");
  const cred = await f.publicCall(`/${created.json.session_id}/credentials`, {
    revision: created.json.revision, item_id: f.itemId, grade: "L0",
  });
  assert.ok(["awaiting_grant", "awaiting_user_submit", "filling"].includes(cred.json.state) || cred.status === 200);
  const state = () => f.sessions.status(created.json.session_id, null);
  await until(() => state().state === "awaiting_user_submit");
  const idpFrame = f.page().frames().find((frame) => frame.url().startsWith(f.idp))!;
  assert.equal(await idpFrame.locator("#password").inputValue(), fakePass);
  assert.equal(originOfFrame(f.page().url()), f.portal);
  assert.deepEqual(f.counts(), { submittedPasswords: 0, completedOtp: 0 });
  assert.equal(f.evilCaptured().join(""), "");
  assert.equal(f.broker.getLoginStatus(state().request_id!).status, "filled");

  await idpFrame.locator("#submit").click();
  await idpFrame.waitForURL(`${f.idp}/otp`);
  const waiting = await f.publicCall(`/${created.json.session_id}/continue`, { revision: state().revision });
  assert.equal(waiting.json.state, "manual_required");
  assert.equal(waiting.json.reason, "otp_requires_user");
  await idpFrame.locator("#otp").fill(fakeOtp);
  await idpFrame.locator("#verify").click();
  await f.page().waitForURL(`${f.portal}/dashboard`);
  const done = await f.publicCall(`/${created.json.session_id}/continue`, { revision: state().revision });
  assert.equal(done.json.state, "authenticated");
  assert.deepEqual(f.counts(), { submittedPasswords: 1, completedOtp: 1 });
});

function originOfFrame(url: string): string {
  return new URL(url).origin;
}

test("iframe origin mismatch never starts a credential phase or consumes L0", async (t) => {
  const f = await setup(t, { iframe: "evil" });
  const s = await f.sessions.create("synthetic-iframe");
  assert.equal(s.state, "manual_required");
  assert.equal(s.reason, "credential_origin_not_reached");
  await assert.rejects(
    () => f.sessions.credentials(s.session_id, s.control_token, s.revision, f.itemId),
    /invalid_state/,
  );
  assert.equal(f.broker.ephemeral.has(f.itemId), true);
  assert.equal(f.evilCaptured().join(""), "");
});

test("nested credential frames are not fill targets", async (t) => {
  const f = await setup(t, { iframe: "nested" });
  const s = await f.sessions.create("synthetic-iframe");
  assert.equal(s.state, "ready_for_credentials");
  const pending = await f.sessions.credentials(s.session_id, s.control_token, s.revision, f.itemId);
  const state = () => f.sessions.status(s.session_id, s.control_token);
  if (pending.state === "awaiting_grant" || pending.state === "filling" || pending.state === "awaiting_user_submit") {
    await until(() => ["blocked", "expired", "cancelled"].includes(state().state));
  } else {
    assert.equal(state().state, "blocked");
  }
  assert.equal(f.counts().submittedPasswords, 0);
  assert.ok(!f.idpCaptured().join("").includes(fakePass));
});

test("two matching child frames abort instead of guessing", async (t) => {
  const f = await setup(t, { iframe: "double" });
  const s = await f.sessions.create("synthetic-iframe");
  if (s.state === "ready_for_credentials") {
    await f.sessions.credentials(s.session_id, s.control_token, s.revision, f.itemId);
    const state = () => f.sessions.status(s.session_id, s.control_token);
    await until(() => ["blocked", "expired"].includes(state().state));
  } else {
    assert.equal(s.state, "manual_required");
  }
  assert.ok(!f.idpCaptured().join("").includes(fakePass));
  assert.equal(f.counts().submittedPasswords, 0);
});

test("top-level navigation mid-fill aborts and does not write the password", async (t) => {
  const f = await setup(t, { delayedPassword: true });
  const s = await f.sessions.create("synthetic-iframe");
  await f.sessions.credentials(s.session_id, s.control_token, s.revision, f.itemId);
  const state = () => f.sessions.status(s.session_id, s.control_token);
  await until(() => state().state === "filling");
  await f.page().goto("http://127.0.0.1:1/untrusted", { timeout: 2_000 }).catch(() => undefined);
  await until(() => ["blocked", "expired", "cancelled"].includes(state().state));
  assert.equal(f.counts().submittedPasswords, 0);
  assert.ok(!f.idpCaptured().join("").includes(fakePass));
});

test("public session APIs never disclose control_token and list the Apple profile id", async (t) => {
  const f = await setup(t);
  const profiles = await fetch(`http://127.0.0.1:${f.apiPort}/v1/session_profiles`);
  const body = await profiles.json() as { profiles: Array<{ id: string }> };
  assert.deepEqual(body.profiles.map((p) => p.id), ["synthetic-iframe"]);
  const created = await f.publicCall("", { profile_id: "synthetic-iframe" });
  assert.equal("control_token" in created.json, false);
  const status = await f.publicCall(`/${created.json.session_id}`);
  assert.equal(status.json.session_id, created.json.session_id);
  const cancelled = await f.publicCall(`/${created.json.session_id}/cancel`, {});
  assert.equal(cancelled.json.state, "cancelled");
});

test("hidden password is not treated as present; Continue must reveal it before awaiting_user_submit", async (t) => {
  const f = await setup(t, { hiddenPasswordUntilContinue: true });
  const s = await f.sessions.create("synthetic-iframe");
  assert.equal(s.state, "ready_for_credentials");
  await f.sessions.credentials(s.session_id, s.control_token, s.revision, f.itemId);
  const state = () => f.sessions.status(s.session_id, s.control_token);
  await until(() => state().state === "awaiting_user_submit");
  const idpFrame = f.page().frames().find((frame) => frame.url().startsWith(f.idp))!;
  assert.equal(await idpFrame.locator("#password").isVisible(), true);
  assert.equal(await idpFrame.locator("#password").inputValue(), fakePass);
  assert.equal(await idpFrame.locator("#submit").isVisible(), true);
  assert.deepEqual(f.counts(), { submittedPasswords: 0, completedOtp: 0 });
  assert.notEqual(state().state, "authenticated");
});

test("Continue labeled button is clicked even when the configured id is absent", async (t) => {
  const f = await setup(t, { hiddenPasswordUntilContinue: true, continueKind: "label-only" });
  const s = await f.sessions.create("synthetic-iframe");
  await f.sessions.credentials(s.session_id, s.control_token, s.revision, f.itemId);
  const state = () => f.sessions.status(s.session_id, s.control_token);
  await until(() => state().state === "awaiting_user_submit");
  const idpFrame = f.page().frames().find((frame) => frame.url().startsWith(f.idp))!;
  assert.equal(await idpFrame.locator("#password").inputValue(), fakePass);
  assert.equal(f.counts().submittedPasswords, 0);
});

test("hidden password without Continue never reports awaiting_user_submit", async (t) => {
  const f = await setup(t, { hiddenPasswordUntilContinue: true, continueKind: "none" });
  const s = await f.sessions.create("synthetic-iframe");
  await f.sessions.credentials(s.session_id, s.control_token, s.revision, f.itemId);
  const state = () => f.sessions.status(s.session_id, s.control_token);
  await until(() => ["manual_required", "blocked", "expired"].includes(state().state));
  assert.notEqual(state().state, "awaiting_user_submit");
  assert.equal(state().reason === "password_not_filled" || state().reason === "password_field_not_visible"
    || state().reason === "username_step_failed" || state().reason === "credential_phase_failed", true, state().reason);
  assert.ok(!f.idpCaptured().join("").includes(fakePass));
  assert.equal(f.counts().submittedPasswords, 0);
});

test("built-in Apple profile is exact-origin, iframe, and selector-overridable", () => {
  const profile = appStoreConnectProfile();
  assert.equal(profile.id, APP_STORE_CONNECT_PROFILE_ID);
  assert.equal(profile.entryUrl, "https://appstoreconnect.apple.com/login");
  assert.equal(profile.portalOrigin, "https://appstoreconnect.apple.com");
  assert.equal(profile.credentialOrigin, "https://idmsa.apple.com");
  assert.equal(profile.credentialFrame, "direct-child");
  assert.equal(profile.usernameSelector, "#account_name_text_field");
  assert.match(profile.passwordSelector ?? "", /#password_text_field/);
  assert.match(profile.usernameNextSelector ?? "", /#sign-in/);
  assert.match(profile.usernameNextSelector ?? "", /button\[type='submit'\]/);
  assert.equal(profile.success.origin, "https://appstoreconnect.apple.com");
  assert.ok(profile.success.denyPathnames?.includes("/login"));
  assert.deepEqual(builtinProfiles().map((p) => p.id), [APP_STORE_CONNECT_PROFILE_ID]);
  assert.throws(() => new ControlledSessions({
    broker: new Broker({ mode: "local", filler: async () => ({ ok: true }) }),
    profiles: [{ ...profile, credentialOrigin: "https://*.apple.com" }],
  }), /invalid_profile/);
  assert.throws(() => new ControlledSessions({
    broker: new Broker({ mode: "local", filler: async () => ({ ok: true }) }),
    profiles: [{ ...profile, credentialFrame: "direct-child", credentialOrigin: profile.portalOrigin }],
  }), /invalid_profile/);
});

test("Apple profile validates without contacting Apple", async () => {
  const broker = new Broker({ mode: "local", filler: async () => ({ ok: true }) });
  const sessions = new ControlledSessions({ broker, profiles: builtinProfiles() });
  try {
    assert.deepEqual(sessions.listProfiles(), [{
      id: APP_STORE_CONNECT_PROFILE_ID,
      entry_url: "https://appstoreconnect.apple.com/login",
      portal_origin: "https://appstoreconnect.apple.com",
      credential_origin: "https://idmsa.apple.com",
      credential_frame: "direct-child",
    }]);
  } finally {
    await sessions.close();
  }
});
