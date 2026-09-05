# Security model

Secrets is treated as security-sensitive software from the start (see
`AGENTS.md`). This document states the MVP's actual security properties
and, just as importantly, its current limitations — plainly, so nobody
relies on a guarantee that does not yet exist.

## Trust boundary

`secretsd` is reachable only from the user's own login session:

- The native API (`org.secrets.Manager`) and the Secret Service
  compatibility layer are served on the **session** D-Bus bus, which is
  per-user and authenticated by the kernel via the connecting process's
  UID — not reachable from another user or another machine.
- The SSH agent socket lives under `$XDG_RUNTIME_DIR`, a tmpfs directory
  private to the user's session, cleared on logout.

Any process running as the same user can reach `secretsd` — there is no
per-application access control in the MVP (see "Not implemented yet"
below).

## What is actually encrypted

The MVP's one backend (a local file, `$XDG_DATA_HOME/secrets/vault.toml`)
encrypts **field values only**, not vault/item/field names:

- **Key derivation:** Argon2id (the `argon2` crate's defaults — 19 MiB, 2
  passes, 1 lane), from the passphrase supplied to `secrets unlock`.
- **Encryption:** AES-256-GCM (the `aes-gcm` crate), one random 96-bit
  nonce per field, generated fresh on every write.
- **Integrity:** AES-GCM's authentication tag detects both a wrong
  passphrase and a corrupted/tampered file; the daemon does not attempt to
  distinguish the two in its error messages (see
  [ADR-006](adr/006-local-backend-cryptography.md)).

Names are readable in the vault file and via `ListVaults`/`ListItems` even
while locked — a deliberate choice (see
[ADR-009](adr/009-session-and-lock-state-machine.md)), not an oversight:
knowing an item named `"GitHub"` exists is not itself sensitive the way
its password is.

## Memory hygiene

- The derived vault key and every value returned by `Backend::get_field`
  (`secrets_core::SecretValue`) are wrapped in types that implement
  `Zeroize`/`ZeroizeOnDrop`. Locking the store is exactly "drop the held
  key" — nothing else needs to happen, because the vault file itself only
  ever holds ciphertext.
- **Limitation:** `ZeroizeOnDrop` only runs on a normal Rust drop. A
  process killed by `SIGKILL`, or one that crashes past a panic boundary
  that aborts rather than unwinds, does not run destructors. This is a
  known limit of the approach, not a guarantee the code claims to provide.

## What is never logged or returned in an error

- `secrets_core::CoreError` and `secrets_core::dbus::ManagerError` are
  constructed only from vault/item/field *names* and static descriptions —
  never a field's value. This is enforced by construction (no code path
  builds one from a `SecretValue`), and exercised by tests (e.g.
  `secrets_core::resolver::tests::resolving_an_unknown_field_reports_not_found_without_the_value`).
- `secrets-cli` prints a secret's value in exactly one place: the output
  of `secrets get`, because the user explicitly asked for it. No other
  command, and no error path, prints one.
- `secretsd`'s `tracing` output logs operation names and identifiers, never
  field values.

## Known MVP limitations

- **No per-application access control.** Any local process running as the
  same user can call `org.secrets.Manager` or read via the Secret Service
  compatibility layer while unlocked. A future prompt-based confirmation
  (via `secrets-gtk`, see
  [`docs/architecture/clients.md`](architecture/clients.md)) is the
  intended fix — not present yet.
- **Daemon-wide locking, not per-vault or per-secret.** Unlocking makes
  every vault readable. See
  [ADR-009](adr/009-session-and-lock-state-machine.md).
- **No encrypted D-Bus session algorithm.** The Secret Service
  compatibility layer only supports `"plain"` — acceptable given the
  session bus's own kernel-enforced trust boundary, but a client that
  insists on encrypted transport will not work. See
  [ADR-004](adr/004-secret-service-compatibility-scope.md).
- **First-run demo seeding.** The very first `secrets unlock` against a
  fresh installation creates the vault file, using the supplied passphrase
  as its new master passphrase, seeded with a small demo vault (a
  `Personal/GitHub` item and a freshly-generated `Infrastructure/Production`
  SSH key) — purely so the MVP's example commands and `ssh-add -L` work
  immediately, not a production provisioning mechanism. There is currently
  no way to opt out of this seeding.
- **RSA agent signature algorithm negotiation is not honoured** — see
  [`docs/dbus/ssh-agent.md`](dbus/ssh-agent.md).
- **The Secret Service compatibility layer's object topology is fixed at
  daemon startup** — see
  [`docs/dbus/secret-service.md`](dbus/secret-service.md).
- **No signal-based graceful shutdown.** `secretsd` relies on the OS to
  reclaim its memory on termination; it does not currently intercept
  `SIGTERM` to zeroize state before exiting (see "Memory hygiene" above).

## Reporting a vulnerability

See [CONTRIBUTING.md](https://github.com/noirbizarre/secrets/blob/main/CONTRIBUTING.md#reporting-a-security-issue)
for how to reach the maintainer privately, rather than filing a public
issue, for anything that looks like a security vulnerability rather than a
bug.
