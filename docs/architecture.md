# Architecture (v0.1)

```
Agent (HTTP JSON or MCP)
        │  request_browser_login / get_login_status
        │  (status only — never secrets)
        ▼
┌───────────────────┐     local mode: Playwright fill on this host
│  safe-connect     │
│  broker           │     L1: vault file (Argon2id → XChaCha20-Poly1305)
│  (local | cloud)  │     L0: EphemeralStore (RAM, burn-after-use)
└─────────┬─────────┘
          │ cloud only
          │ heartbeat / challenges / grant (pairing key)
          ▼
┌───────────────────┐
│  companion CLI    │  holds unwrap private key
│  (required)       │  prints challenge; y/code or deny
└───────────────────┘
```

## Processes

One binary (`safe-connect`):

| Command | Role |
| --- | --- |
| `serve --mode local` | Unlocks local vault, HTTP API, example login page, localhost admin add/list |
| `serve --mode cloud` | Encrypted L1 vault on server disk, fail-closed without companion |
| `companion` | Local poll loop + terminal approve/deny + grant minting |
| `mcp` | Stdio MCP proxy to an already-running `serve` |
| `init` / `add` / `list` | Vault or companion identity setup and credential intake |

Cloud brokers **do not** hold the companion private key. They hold the pairing key (control-channel auth + grant wrapping) and the companion X25519 public key (so items can be sealed toward the companion).

## Crypto

- **KDF (local vault):** libsodium `crypto_pwhash` Argon2id. Ops/mem: `MODERATE` by default; `MIN` when `SAFE_CONNECT_KDF=fast` or `NODE_ENV=test`.
- **AEAD:** XChaCha20-Poly1305 IETF (`crypto_aead_xchacha20poly1305_ietf_*`).
- **Sealed DEK (cloud items):** `crypto_box_seal` to the companion public key. Item username/password are AEAD-encrypted under a random 32-byte DEK; the DEK is sealed.
- **Grant:** Companion opens the sealed DEK, then AEAD-encrypts the DEK under `BLAKE2b(pairing_key, "grant\|request_id\|url")` with AAD `request_id|url|expires_at`. TTL capped at 30 seconds. Cloud `openGrant` enforces binding, expiry, and single-use.

Human confirm codes are 6-digit random integers printed next to the challenge. They are not mixed into the grant key.

## Vault file (`SC01`)

Binary header: magic `SC01`, version, kind (`1` local / `2` cloud).

- **Local:** salt + Argon2id params + AEAD blob of `{ entries: L1... }`. L0 entries are omitted.
- **Cloud:** AEAD blob keyed by `BLAKE2b(pairing_key, "safe-connect-cloud-vault")` of `{ companion_public_key, entries: sealed L1... }`. L0 is not written. Opening sealed DEKs still requires the companion.

Files are written `0600` under `SAFE_CONNECT_HOME` (default `~/.safe-connect`), which must not be committed.

## Fill

`playwrightFill` launches Chromium, opens the requested URL, fills `username` / `password` fields, submits. The example page at `/example/login.html` exposes `#login-result[data-status=ok|fail]` for tests.

## Control channel

Companion endpoints (`/v1/companion/*`) require `Authorization: Bearer <pairing_key_hex>`. Prefer wrapping this in SSH/Tailscale/mTLS; the Bearer token is a pre-shared pairing key, not user 2FA.

Local admin endpoints (`/v1/admin/*`) exist only in local mode, bound to the configured loopback address, using a 256-bit token file `admin.token`. They exist so `add --grade L0` can inject RAM-only items into the running broker. They are not agent APIs.

## Fail-closed

`GET /v1/health`:

- local → `200 { companion: "not_required" }`
- cloud paired (heartbeat within 10s) → `200 { companion: "paired" }`
- cloud unpaired → `503 { status: "fail_closed", companion: "missing" }`

`POST /v1/request_browser_login` in cloud without a companion returns `503` / `denied`.
