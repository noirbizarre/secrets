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
- `secrets-cli` prints or otherwise discloses a secret's value in exactly
  one place: `secrets get`, because the user explicitly asked for it —
  as a bare value (default off a terminal, or `--raw`), as
  `{"uri": ..., "value": ...}` (`--json`), or copied to the clipboard
  (`--clipboard`, see [ADR-014](adr/014-cli-secret-disclosure-modes.md)).
  No other command, and no error path, discloses one; `get`'s handler
  wraps the value in `secrets_core::SecretValue` the instant it arrives,
  so nothing else in that command's own code path can print or serialize
  it by accident either.
- `secrets get` with no output flag refuses to print the value at all
  when stdout is a real terminal, rather than relying on the caller to
  remember `--raw`/`--json`/`--clipboard` themselves — see ADR-014.
- `secretsd`'s `tracing` output logs operation names and identifiers, never
  field values.

## Known MVP limitations

- **No per-application access control.** Any local process running as the
  same user can call `org.secrets.Manager` or read via the Secret Service
  compatibility layer while unlocked. A future prompt-based confirmation
  (via a future UI client such as GD Secrets, see
  [`docs/architecture/external-clients.md`](architecture/external-clients.md))
  is the intended fix — not present yet.
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
- **No signal-based graceful shutdown.** `secretsd` relies on the OS to
  reclaim its memory on termination; it does not currently intercept
  `SIGTERM` to zeroize state before exiting (see "Memory hygiene" above).
- **`secrets get --clipboard` does not auto-clear the clipboard.** The
  value stays there with no expiry until something else overwrites it or
  the session ends — unlike e.g. `pass -c`'s timed clear. See
  [ADR-014](adr/014-cli-secret-disclosure-modes.md).
- **The 1Password backend's `list_items` briefly holds decrypted field
  *values* in memory, even though it only reports metadata.** Unlike
  `LocalBackend` (which truly never touches encrypted values to list
  fields), 1Password's `ItemsGetAll` API has no "metadata only" mode —
  fetching field names/types at all means fetching a full, decrypted
  item, values included, in the same response. `OnePasswordBackend`
  never copies a value into anything it holds onto (its own `ItemField`
  type has no `value` field to deserialize into), and the raw response
  buffer is explicitly zeroized immediately after parsing — but the
  underlying `ipc::Response` type this buffer briefly passes through is
  not itself `Zeroize`/`ZeroizeOnDrop` (unlike `SecretValue`/`VaultKey`,
  see "Memory hygiene" above), so a copy of that buffer exists,
  un-zeroized, for the duration of one native call and one parse. See
  `crates/secretsd/src/backend/onepassword/backend.rs`'s `list_items`.

## Reporting a vulnerability

See [CONTRIBUTING.md](https://github.com/noirbizarre/secrets/blob/main/CONTRIBUTING.md#reporting-a-security-issue)
for how to reach the maintainer privately, rather than filing a public
issue, for anything that looks like a security vulnerability rather than a
bug.
