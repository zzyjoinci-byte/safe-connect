# Safe Connect

Open-source **credential broker for AI agents**. Agents can request a browser login fill and only ever see a status (`pending` | `filled` | `denied` | `expired`). **Passwords never appear in HTTP or MCP responses.**

MIT licensed. Repo: [zzyjoinci-byte/safe-connect](https://github.com/zzyjoinci-byte/safe-connect).

## Choose a mode

| Mode | What you run | Secrets |
| --- | --- | --- |
| **`local`** | One broker on your machine | Plaintext never leaves the machine over the agent/MCP channel. L1 lives in an Argon2id + XChaCha20-Poly1305 vault. L0 is RAM only (burn-after-use). |
| **`cloud`** | Cloud broker **plus a mandatory local companion** | L1 ciphertext may sit on the cloud disk. Every decrypt+fill needs a **≤30s single-use crypto grant** from the companion, bound to `request_id` + URL. L0 is RAM-only on the cloud (never persisted) and still needs local approve. |

**Cloud-only without a paired local companion is unsupported.** Health fails closed (`503`, `companion: missing`) and fill requests are denied.

The 6-digit confirm code printed in the companion CLI is **UX only**. Security is the cryptographic grant, not the code.

## Install

Node 20+.

```bash
git clone https://github.com/zzyjoinci-byte/safe-connect.git
cd safe-connect
npm install
npx playwright install chromium
npm run build
npm test
```

CLI after build:

```bash
node dist/cli.js --help
# or: npx --prefix . safe-connect --help
```

## Local mode

```bash
export SAFE_CONNECT_MODE=local
export SAFE_CONNECT_HOME="$PWD/.safe-connect"   # gitignored
export SAFE_CONNECT_PASSPHRASE='choose-a-strong-passphrase'

node dist/cli.js init --mode local
node dist/cli.js serve --mode local
```

In another terminal, with the same `SAFE_CONNECT_HOME`:

```bash
node dist/cli.js add --grade L1 --label demo --url http://127.0.0.1:8787/example/login.html \
  --username demo --password demo-pass-NOT-SECRET

# L0 (memory only on the running broker — never written to the vault file):
node dist/cli.js add --grade L0 --label demo-once --url http://127.0.0.1:8787/example/login.html \
  --username demo --password demo-pass-NOT-SECRET
```

Agent (HTTP):

```bash
curl -s http://127.0.0.1:8787/v1/request_browser_login \
  -H 'content-type: application/json' \
  -d '{"purpose":"demo","url":"http://127.0.0.1:8787/example/login.html"}'
# -> {"request_id":"...","status":"pending"}

curl -s http://127.0.0.1:8787/v1/requests/<request_id>
# -> {"request_id":"...","status":"filled"}   # never a password
```

MCP stdio proxy (broker must already be serving):

```bash
SAFE_CONNECT_URL=http://127.0.0.1:8787 node dist/cli.js mcp
```

Tools: `request_browser_login`, `get_login_status` only. There is no `get_password`.

Example agent client: `examples/demo-agent.mjs`. Example login page: `examples/login.html` (also served at `/example/login.html`).

## Cloud mode (broker + companion)

On the **local** machine:

```bash
export SAFE_CONNECT_HOME="$HOME/.safe-connect"
node dist/cli.js init --mode cloud
# prints SAFE_CONNECT_PAIRING_KEY and SAFE_CONNECT_COMPANION_PUBLIC_KEY
```

On the **cloud** broker host:

```bash
export SAFE_CONNECT_MODE=cloud
export SAFE_CONNECT_PAIRING_KEY=...          # from init
export SAFE_CONNECT_COMPANION_PUBLIC_KEY=... # from init
export SAFE_CONNECT_HOME=/var/lib/safe-connect
node dist/cli.js serve --mode cloud
```

Tunnel localhost or Tailscale/SSH so the companion can reach the broker. Then on the local machine:

```bash
export SAFE_CONNECT_CLOUD_URL=http://127.0.0.1:8787
node dist/cli.js companion
```

The companion heartbeats, prints each unwrap challenge (`request_id`, URL, purpose, grade, countdown, confirm code), and on approve emits a one-time grant. Type `n` to deny.

Add credentials **from the companion side** (plaintext is sealed to the companion public key before it hits the cloud):

```bash
node dist/cli.js add --grade L1 --label prod --url https://example.com/login --username you
node dist/cli.js add --grade L0 --label once --url https://example.com/login --username you
```

Until the companion is paired, `GET /v1/health` returns **503**.

## Grades

- **L0** — burn-after-use. In-process memory only. Never written to the vault file (local or cloud disk).
- **L1** — long-term. Argon2id KDF (local vault passphrase) or sealed DEK (cloud, unwrapped only with a companion grant) + XChaCha20-Poly1305.

## Agent contract

Responses contain at most:

```json
{ "request_id": "…", "status": "pending|filled|denied|expired", "error": "optional" }
```

## CLI

All human actions for v0.1 are terminal-based (no GUI):

- vault unlock passphrase (`serve` / `init`)
- add L0 / L1 items
- companion approve / deny of unwrap grants

## Security

Read [SECURITY.md](SECURITY.md) and [docs/architecture.md](docs/architecture.md). Residual risk: after a valid grant, plaintext exists briefly in cloud RAM during Playwright fill (≤30s window, then zeroized).

## License

[MIT](LICENSE)
