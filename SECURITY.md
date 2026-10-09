# Security Policy

## Report a vulnerability

Please **do not** open a public GitHub issue for cryptographic or secret-handling bugs.

Email the maintainers via the GitHub profile on [zzyjoinci-byte/safe-connect](https://github.com/zzyjoinci-byte/safe-connect) or open a **private** security advisory on the repository.

## Threat model (v0.1)

Safe Connect is a credential **broker**. AI agents are treated as untrusted for secret exfiltration: they may request a fill, they must never receive passwords.

### Guarantees we aim for

1. **Agent channel** — HTTP JSON and MCP tools return only `pending | filled | denied | expired` (plus a coarse `error` string). No `get_password` / export APIs.
2. **Local mode** — Secret plaintext is not sent over the agent/MCP network. Fill happens in a local Playwright browser. L1 at rest: Argon2id + XChaCha20-Poly1305. L0 never hits disk.
3. **Cloud mode fail-closed** — If the local companion is unpaired or silent, health is `503` and fills are denied. Cloud-only is unsupported.
4. **Cloud L1** — Disk stores ciphertext. Decrypt requires a **single-use ≤30s grant** from the companion, AEAD-bound to `request_id` and target URL. Replay and URL mismatch fail.
5. **Cloud L0** — Sealed blob in cloud process memory only; still needs a local grant before fill; not written to the cloud vault file.
6. **Human 6-digit code** — Display/confirm UX only. It is not an authentication factor. The grant is.
7. **Origin binding** — Explicit item IDs must match the requested normalized origin (scheme, host, and port). The browser checks the destination after navigation and checks the input document's origin synchronously with each credential write, including after redirects.
8. **L0 consumption** — An accepted request atomically removes L0 from the in-memory store before waiting for a companion grant or starting a fill. Concurrent requests cannot reuse it. Denial, timeout, or fill failure still consumes it; add a new L0 item for another attempt. Requests rejected for an origin mismatch do not consume the item.

### Residual risk

- Controlled sessions use the existing broker/grant path and explicit origin profiles. A completed credential fill is not verified login success. Password/OTP submission needs a trusted human browser channel, which is not implemented. See [controlled sessions](docs/controlled-sessions.md).
- The grant-wrapping key derives from the pairing bearer. A TLS-terminating relay that sees the bearer and grant can decrypt the DEK. Real companion traffic requires end-to-end TLS to a dedicated companion listener; the agent port must remain loopback-only. This listener/TLS/bootstrap work is not implemented here.

- After a user-approved grant, the cloud broker holds plaintext in RAM for the Playwright fill, then best-effort `memzero` of key material. JavaScript strings are immutable; treat this as a short trusted-computing-base window on the broker host.
- Pairing key + companion private key are equivalent to “can mint grants”. Store `companion.json` mode `0600` on the local machine only. Prefer an SSH/Tailscale/mTLS tunnel for the companion control channel; Bearer pairing-key auth is v0.1-minimal.
- A compromised local machine (unlocked vault or companion keys) can fill or mint grants. This is out of scope to prevent.
- Playwright submits credentials to the **requested origin** (that is the product). Agents can still phish a user into approving a malicious URL — read the companion prompt (`url` / `purpose`) before approving.
- `SAFE_CONNECT_AUTO_APPROVE=1` and `SAFE_CONNECT_KDF=fast` are **dev/test only**.

### What we do not do (MVP)

- Third-party password managers
- Cookie/session export
- Browser-extension store listing
- Defending a fully compromised cloud host that already received a live grant

## Supported versions

v0.1.x is the initial public preview. Treat it as beta cryptography: review before production secrets.
