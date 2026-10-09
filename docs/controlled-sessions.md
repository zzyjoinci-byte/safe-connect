# Controlled multi-step credential sessions

`serve` constructs `ControlledSessions` with built-in profiles (currently
`app-store-connect`) unless `SAFE_CONNECT_SESSIONS=0`. The library still extends
the existing broker, vault and companion grant path. It does not provide a remote
browser viewer, tunnel, new listener, or TLS termination. Synthetic coverage is
`test/sessions.test.ts` (same-origin) and `test/iframe-sessions.test.ts`
(portal + cross-origin iframe). No real Apple credentials are used in tests.

## Trusted host integration

Each profile is trusted server-side configuration: an entry URL, an exact
**portal** origin (the top-level page; defaults to `origin(entryUrl)`), one exact
**credential** origin, username/password selectors, an optional username-only Next
button, explicit success origin/path/marker, and optional OTP/CAPTCHA/passkey
markers. Set `credentialFrame: "direct-child"` to fill a unique child iframe at
the credential origin while the top-level page stays on the portal origin.
Profiles and selectors cannot be supplied by the agent or changed by HTTP session
requests. HTTPS is required except for explicit loopback HTTP test origins.
Wildcards, URL userinfo, and origins containing paths are rejected.

Portal and identity-provider origins are different roles. Never infer an Apple
identity origin from an Apple Developer URL, trust every Apple subdomain, or
reuse a portal credential for a different identity origin. Store vault items
against the **credential origin** (for App Store Connect: `https://idmsa.apple.com`).
The browser must reach a permitted credential target before a credential request
is permitted. If a portal needs human navigation before that, it remains
`manual_required`.

## Iframe fill rules (fail-closed)

Writes still run in a document-bound isolated world with a synchronous
`location.origin` check. `grantUniversalAccess` is never set.

| Target | Top-level origin | Fill document |
| --- | --- | --- |
| default (`top`) | Must equal `credentialOrigin` | Main frame only |
| `direct-child` | Must equal `portalOrigin` | Exactly one **direct** child frame whose origin equals `credentialOrigin` |

- Nested frames are never a fill target, even when they share the credential origin.
- Two matching direct children are ambiguous: the session will not fill.
- A child frame whose origin does not exactly match `credentialOrigin` is never written.
- If the top-level origin or the credential-frame origin changes mid-fill, the session aborts.
- Popups and downloads still stop the session.
- Main-frame document navigations to an origin outside the profile allowlist abort the session. Subresources (scripts, XHR, other iframes) are **not** treated as a network sandbox; this is not an egress firewall. No credential write is allowed except in the selected fill document.

## Built-in App Store Connect profile

Id `app-store-connect`. Opt-in by creating a session with that profile id.

| Role | Value |
| --- | --- |
| Entry | `https://appstoreconnect.apple.com/login` |
| Portal origin | `https://appstoreconnect.apple.com` |
| Credential origin | `https://idmsa.apple.com` |
| Frame | `direct-child` (Apple's `#aid-auth-widget-iFrame` widget) |
| Username | `#account_name_text_field` |
| Continue (not final submit) | `#sign-in` when the password field is absent |
| Password | `#password_text_field` |
| Success | Top-level `https://appstoreconnect.apple.com`, not `/login`, marker `a[href='/apps']` or `a[href^='/apps/']` |
| Manual | 2FA/OTP, passkey, and CAPTCHA selectors on `idmsa.apple.com` |

Override selectors with `SAFE_CONNECT_ASC_USERNAME_SELECTOR`,
`SAFE_CONNECT_ASC_PASSWORD_SELECTOR`, `SAFE_CONNECT_ASC_NEXT_SELECTOR`,
`SAFE_CONNECT_ASC_OTP_SELECTOR`, and `SAFE_CONNECT_ASC_SUCCESS_SELECTOR`.

**Not verified against a live Apple account in this repository.** Selectors come
from Apple's long-standing idmsa auth widget (`account_name_text_field` /
`password_text_field` / `#sign-in` inside `iframe#aid-auth-widget-iFrame`). Apple
may change DOM, add interstitial domains, or require passkeys. Unknown Apple
origins are not wildcarded; the session fail-closes rather than filling them.
Final Sign In and the 2FA code stay manual (`awaiting_user_submit` /
`manual_required`).

## Existing credential/grant path

1. Create a session for a known profile. The server creates a fresh,
   non-persistent BrowserContext. Operator APIs also mint a `control_token`;
   agent HTTP/MCP identify the session by `session_id` only and never receive
   `control_token`.
2. `credentials` supplies only a vault item ID and expected session revision.
   The broker checks its origin and consumes L0 synchronously, as in the legacy
   flow. Cloud mode creates the existing unwrap challenge and waits for its
   companion grant. The challenge includes `session_id` for the companion prompt.
   The grant URL is the credential-target document URL (the iframe URL when
   `credentialFrame` is `direct-child`).
3. The cryptographic grant still binds request ID, exact URL and expiry. An
   immutable server-side association ties that request ID to exactly one session
   and credential phase. Changing its request ID to target a different session
   fails authenticated decryption. Sessions never retain a grant for replay.
4. After grant verification, the same broker decrypts and calls the controlled
   filler in that session's existing context. It fills username, optionally clicks
   the configured username-only Next button if no password field exists, and
   fills password. Each write uses the isolated-world origin check in the
   selected frame. The Next action also checks origin and deadline and refuses
   to run when the configured password field is present.
5. The phase deadline is the earliest of the request expiry, signed grant expiry,
   session expiry and 30 seconds after phase entry. Expiry/cancellation closes the
   context and prevents subsequent writes. The phase returns immediately after
   password fill. Broker-side decrypted objects/references are released and key
   buffers are best-effort zeroized by the existing code; immutable JavaScript
   strings cannot be guaranteed erased from memory. Prefilled values necessarily
   remain in the browser's form until the user submits or the context is closed.
6. The state becomes `awaiting_user_submit`, not `authenticated`. No final
   password or OTP submit action is automated by this API. L0 is already consumed;
   denial, timeout or failure does not restore it, and this session cannot start
   a second credential phase. Use a new session and new L0 item for a retry.

A different credential origin requires a separate explicitly configured profile,
matching item and new grant; an existing phase cannot follow credentials across
origins.

## Headed human finish (submit + 2FA)

Set `SAFE_CONNECT_HEADED=1` and a working `DISPLAY` (Linux) so Chromium is
visible. The page stays open after fill until the bounded session deadline
(default 10 minutes when headed, otherwise 5; maximum 10; override with
`SAFE_CONNECT_SESSION_TIMEOUT_MS`). `operator_surface` is `local_headed_browser`
when headed; it is still not a remote-control UI or cookie/session export.
Cancel, expiry, companion loss, or process shutdown destroys the context.

## HTTP, CLI and MCP

Local operator APIs: `/v1/admin/sessions` plus the admin bearer and
`X-Safe-Connect-Session`. Cloud operator APIs: `/v1/companion/sessions` plus the
pairing bearer. Browser-origin operator requests are rejected.

Agent-facing APIs (status/session view only; never secrets, never `control_token`):

| Operation | Request |
| --- | --- |
| List profiles | `GET /v1/session_profiles` |
| Create | `POST /v1/sessions`, `{ "profile_id": "app-store-connect" }` |
| Status | `GET /v1/sessions/:id` |
| Credential phase | `POST /v1/sessions/:id/credentials`, `{ "revision": N, "item_id": "...", "grade": "L1" }` |
| Continue/check | `POST /v1/sessions/:id/continue`, `{ "revision": N }` |
| Cancel | `POST /v1/sessions/:id/cancel`, `{}` |

MCP tools: `list_session_profiles`, `create_login_session`,
`attach_session_credentials`, `get_session_status`, `continue_login_session`,
`cancel_login_session`, plus the existing login request/status tools. There is
no `get_password`.

CLI (broker already serving):

```bash
node dist/cli.js session profiles
node dist/cli.js session create --profile app-store-connect
node dist/cli.js session credentials --session-id ID --item-id ID --revision N
node dist/cli.js session status --session-id ID
node dist/cli.js session continue --session-id ID --revision N
node dist/cli.js session cancel --session-id ID
```

Password, OTP, cookie, passkey, script and arbitrary-navigation fields are not
accepted. There are no value/DOM/screenshot/storage exports. Revisions and a
synchronous per-session operation lock reject concurrent/replayed control
operations. Cancel can preempt an in-flight phase without a revision.

The protocol states are `opening`, `ready_for_credentials`, `awaiting_grant`,
`filling`, `awaiting_user_submit`, `manual_required`, `authenticated`, `blocked`,
`cancelled`, and `expired`. CAPTCHA/passkey/OTP markers stay `manual_required`;
when a challenge cannot be recognized the flow remains manual or stops rather
than claiming success.

## Success, isolation and cleanup

Only `continue` can declare success, after the credential phase, when the
configured success origin matches, the pathname matches `pathname` and/or
`pathnamePrefix`, is not listed in `denyPathnames`, and the profile's success
marker is visible on the **top-level** document. Configured manual challenges
take precedence. A filled password, generic page, HTTP 200, client assertion or
absence of an error is not success. This is profile-defined application
evidence, not a universal proof of authentication.

Default session lifetime is 5 minutes (10 when headed; maximum 10); authenticated
retention is 60 seconds (maximum 5 minutes), never beyond the original session
expiry. Default capacity is 8 sessions, with a configurable maximum of 32 and
bounded terminal metadata. Each has its own cookie/storage context. Cancel,
expiry, unexpected top-level origin, browser closure, shutdown or loss of the
cloud companion closes it. No browser storage is intentionally persisted/exported.

## Connection requirements still unimplemented

The current grant wrapping key derives from the same pairing secret used as the
HTTP bearer. A relay that terminates TLS and sees both bearer and grant can derive
the wrapping key and decrypt the DEK. Real operation therefore needs end-to-end
TLS from the Mac companion to a dedicated companion listener; do not terminate
that connection at an untrusted intermediary or forward the entire agent port.
Keep the 8787 agent interface loopback-only. Separate listeners, TLS, host identity
verification, secure bootstrap and a remote human browser channel are design
requirements, not implemented/deployed capabilities. `init --mode cloud` currently
prints pairing material; no real initialization or cross-machine secret copy was
performed for this work.
