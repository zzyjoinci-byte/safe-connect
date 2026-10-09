# Controlled multi-step credential sessions

This opt-in library integration extends the existing broker, vault and companion
grant path. It does not provide a browser viewer, remote-control UI, tunnel, new
listener, TLS termination, or production login profile. The existing CLI does not
enable it automatically. `test/sessions.test.ts` is the executable integration
example, using only synthetic pages and credentials.

## Trusted host integration

Construct `ControlledSessions({ broker, profiles })` and pass the same instance
as `sessions` to `createHttpServer`. On host shutdown, await `sessions.close()`.
Each profile is trusted server-side configuration: an entry URL, one exact
credential origin, username/password selectors, an optional username-only Next
button, explicit success origin/path/marker, and optional OTP/CAPTCHA/passkey
markers. Profiles and selectors cannot be supplied by the agent or changed by
HTTP session requests. HTTPS is required except for explicit loopback HTTP test
origins. Wildcards, URL userinfo, and origins containing paths are rejected.

Portal and identity-provider origins are different roles. Never infer an Apple
identity origin from an Apple Developer URL, trust every Apple subdomain, or
reuse a portal credential for a different identity origin. No Apple profile or
actual Apple login is implemented/verified here. The browser must reach the
configured credential origin before a credential request is permitted. If a
portal needs human navigation before that, it remains `manual_required`.

## Existing credential/grant path

1. The authenticated operator creates a session for a known profile. The server
   creates a fresh, non-persistent BrowserContext and a random session capability.
2. `credentials` supplies only a vault item ID and expected session revision.
   The broker checks its origin and consumes L0 synchronously, as in the legacy
   flow. Cloud mode creates the existing unwrap challenge and waits for its
   companion grant. The challenge includes `session_id` for the companion prompt.
3. The cryptographic grant still binds request ID, exact URL and expiry. An
   immutable server-side association ties that request ID to exactly one session
   and credential phase. Changing its request ID to target a different session
   fails authenticated decryption. Sessions never retain a grant for replay.
4. After grant verification, the same broker decrypts and calls the controlled
   filler in that session's existing context. It fills username, optionally clicks
   the configured username-only Next button if no password field exists, and
   fills password. Each write uses the same isolated-world origin check as the
   existing filler. The Next action also checks origin and deadline and refuses
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
origins. Frames/popups are not supported as alternate credential targets. Unknown
origins stop the session; new popups and downloads also stop it. Request routing
blocks unknown origins where intercepted, and committed navigation is rechecked.
This is not a network sandbox/SSRF guarantee against every browser transport or
redirect: do not place sensitive unknown-origin data in URLs or rely on this as
an egress firewall. No credential write is allowed on an unknown origin.

## Operator HTTP interface (same existing HTTP server)

Local mode uses `/v1/admin/sessions` and the existing admin bearer. Cloud mode
uses `/v1/companion/sessions` and the existing companion pairing bearer. The wrong
mode's path is absent; unconfigured session integration returns 503. No new
public/agent endpoint or MCP tool is introduced. Browser-origin requests are
rejected; this is an operator control protocol, not an HTML credential relay.

| Operation | Request | Result |
| --- | --- | --- |
| Create | `POST /sessions`, `{ "profile_id": "synthetic" }` | Session view plus one-time-disclosed `control_token` |
| Status | `GET /sessions/:id` | Session view |
| Credential phase | `POST /sessions/:id/credentials`, `{ "revision": N, "item_id": "...", "grade": "L0" }` | Session view; a cloud grant is still required |
| Continue/check | `POST /sessions/:id/continue`, `{ "revision": N }` | Inspect progress/evidence in the same session; never submit a form |
| Cancel | `POST /sessions/:id/cancel`, `{}` | Destroy the context and revoke pending request |

All per-session operations also require `X-Safe-Connect-Session: <control_token>`.
Only its SHA256 is kept server-side. Treat both tokens as secret; do not put them
in URLs or logs. Password, OTP, cookie, passkey, script and arbitrary-navigation
fields are not accepted. There are no value/DOM/screenshot/storage exports.
Revisions and a synchronous per-session operation lock reject concurrent/replayed
control operations. Cancel can preempt an in-flight phase without a revision.

The protocol states are `opening`, `ready_for_credentials`, `awaiting_grant`,
`filling`, `awaiting_user_submit`, `manual_required`, `authenticated`, `blocked`,
`cancelled`, and `expired`. `operator_surface` is always `unavailable`: this code
does not claim a usable human browser handoff. CAPTCHA/passkey/OTP markers stay
`manual_required`; when a challenge cannot be recognized the flow remains manual
or stops rather than claiming success. Tests simulate a human directly in the
same test browser; that test seam is not a production operator channel.

## Success, isolation and cleanup

Only `continue` can declare success, after the credential phase, when the exact
configured success origin and pathname match and the profile's success marker is
visible. Configured manual challenges take precedence. A filled password, generic
page, HTTP 200, client assertion or absence of an error is not success. This is
profile-defined application evidence, not a universal proof of authentication;
production profiles need independent review and a reliable application signal.
Legacy broker `filled` means the credential action completed, not that a controlled
session authenticated; use the session state for that distinction.

Default session lifetime is 5 minutes (maximum 10); authenticated retention is
60 seconds (maximum 5 minutes), never beyond the original session expiry. Default
capacity is 8 sessions, with a configurable maximum of 32 and bounded terminal
metadata. Each has its own cookie/storage context. Cancel, expiry, unexpected
origin, browser closure, shutdown or loss of the cloud companion closes it. No
browser storage is intentionally persisted/exported. Native input/change events
are used; focus/trusted-keyboard-dependent forms remain unverified.

## Connection requirements still unimplemented

The current grant wrapping key derives from the same pairing secret used as the
HTTP bearer. A relay that terminates TLS and sees both bearer and grant can derive
the wrapping key and decrypt the DEK. Real operation therefore needs end-to-end
TLS from the Mac companion to a dedicated dot companion listener; do not terminate
that connection at an untrusted intermediary or forward the entire agent port.
Keep the 8787 agent interface loopback-only. Separate listeners, TLS, host identity
verification, secure bootstrap and a trusted human browser channel are design
requirements, not implemented/deployed capabilities. `init --mode cloud` currently
prints pairing material; no real initialization or cross-machine secret copy was
performed for this work.
