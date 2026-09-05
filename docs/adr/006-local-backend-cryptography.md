# ADR-006: Local backend cryptography

## Status

Accepted

## Context

The MVP needs one working backend end-to-end (see ADR-008 for why it is
the only one and why the trait is shaped the way it is). Its vault file
lives under `$XDG_DATA_HOME/secrets/vault.toml`, and its "lock"/"unlock"
distinction has to be a real security boundary, not merely a UX gate — the
project is explicitly treated as security-sensitive software (see
`AGENTS.md` and `docs/security.md`).

Requirements: a passphrase, not a random key, is what the user supplies
(so nothing else needs to be remembered or stored); the format needs to
distinguish "wrong passphrase" from "corrupted file" only exactly as much
as AES-GCM's authentication tag already does (see below); and vault/item/
field *names* must stay readable while locked, since `ListVaults`/
`ListItems` are available in that state (ADR-005) — only field *values*
are encrypted.

## Decision

- **Key derivation: Argon2id**, via the `argon2` crate's
  `hash_password_into`, at the crate's default parameters (19 MiB, 2
  passes, 1 lane — OWASP's current interactive-use baseline). No home-rolled
  parameter tuning: a maintained crate's default is a better bet than a
  number picked without the benchmarking that produced it.
- **Encryption: AES-256-GCM**, via the `aes-gcm` crate, one random 96-bit
  nonce per field via `rand_core::OsRng`, generated fresh on every write —
  never reused, which is the one hard rule AES-GCM has.
- **Integrity check without decrypting real data**: a fixed plaintext
  (`"secrets-vault-integrity-check"`) is encrypted alongside the vault's
  salt at creation and decrypted on every `unlock` attempt. This exists
  because AES-GCM's authentication tag is what actually distinguishes
  "wrong key" from "corrupted ciphertext" — a freshly-created, still-empty
  vault would otherwise have no ciphertext at all to attempt decrypting,
  and `unlock` would have no way to reject a wrong passphrase before the
  first field is written.
- **Memory hygiene**: the derived key ([`VaultKey`], `crypto.rs`) and every
  resolved [`SecretValue`] (`secrets-core::secret_value`) implement
  `Zeroize`/`ZeroizeOnDrop`. Locking the store is exactly "replace the held
  `Option<VaultKey>` with `None`" — nothing else needs to happen, because
  the vault file itself only ever holds ciphertext.

No algorithm was invented for this project; all three primitives above are
established, audited crates.

## Consequences

- A process that dies by signal (`SIGKILL`, a crash) does not run Rust
  destructors, so `ZeroizeOnDrop` is not a guarantee against every
  scenario — documented as a known limit in `docs/security.md`, not a gap
  hidden by the abstraction.
- The demo vault seeded on first `secrets unlock` (see
  `crates/secretsd/src/backend/local.rs`) is real, working encryption
  under a real, user-chosen passphrase from the very first run — the MVP's
  "definition of done" commands are not backed by a plaintext stand-in.
- A backend with a fundamentally different trust model (an API-based
  backend that authenticates over HTTPS, say) will not reuse this module —
  it is local-backend-specific by design, not a shared "Secrets crypto"
  layer other backends are forced to route through.
