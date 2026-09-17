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

### Residual risk

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
