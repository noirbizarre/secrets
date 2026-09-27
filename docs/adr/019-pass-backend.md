# ADR-019: The `pass`/`gopass` backend

## Status

Accepted.

## Context

PLAN.md §7.5/7.6 tracked `pass` and `gopass` as future `Backend`
candidates since ADR-008, which already predicted their general shape:
"a directory tree of GPG-... encrypted files, one file per secret,
decrypted by shelling out to or linking against the relevant tool."
ADR-011 additionally predicted that a filesystem backend like this
"likely" needs no [`BackendSession`](011-backend-session-and-authentication-state.md)
— this ADR confirms that prediction, but for a different reason than
ADR-011 assumed (see "Locking model" below).

Two integration paths exist for reading `pass`-format files:

1. **Shell out to `gpg`/`pass`/`gopass`.** Rejected for exactly the
   reason ADR-012 rejected shelling out to the `op` CLI for 1Password:
   it is a second, informal IPC mechanism — a subprocess and its
   stdout/exit code — alongside D-Bus (ADR-001), and ties this project
   to a specific CLI's argument shape and output format rather than a
   documented protocol.
2. **Decrypt in-process with a pure-Rust OpenPGP implementation.** No
   subprocess, no informal parsing of another tool's text output.

[`ripasso`](https://github.com/cortex/ripasso) is the closest prior art
for reading this exact on-disk format in Rust, and was consulted as
**reference only** for the format's edge cases — it is GPL-3.0 licensed
and cannot be linked into this MIT-licensed project.
[`rPGP`](https://github.com/rpgp/rpgp) (crate `pgp`, MIT OR Apache-2.0)
is the pure-Rust OpenPGP implementation this ADR selects instead.

`gopass` needed no separate investigation: its "multiple mounts" are
just additional `pass`-compatible directories on disk, and its default
crypto backend (`gpgcli`) produces byte-identical `.gpg-id`/`.gpg` files
to plain `pass` — confirmed directly (see "Testing" below), not assumed.

## Decision

`crates/secretsd/src/backend/pass/` implements `Backend` +
[`LockController`](../../crates/secretsd/src/state.rs) (not
`BackendSession`) over rPGP:

- **One vault per store.** `pass` has no native multi-vault concept,
  and multi-store support (ADR-018) already covers "several mounts" as
  separate `[store.<id>]` instances — recovering vault-like grouping
  from top-level directory names within one store would be an invented
  convention, not a `pass` one. A store's one vault name defaults to
  its `store_dir`'s own basename with a leading `.` stripped
  (`~/.password-store` → `password-store`), overridable via `vault =`.
  An item's [`ItemPath`] is the file's full path relative to `store_dir`
  (directories become segments), `.gpg` stripped.
- **Locking model: a real `LockController`, not `BackendSession`.**
  ADR-011 predicted no `BackendSession` for this backend, reasoning
  from "no external session concept." The actual reason turns out
  different: `BackendSession`/`AlwaysUnlocked` (used by the 1Password
  backend) exists for backends whose *external* system (1Password
  Desktop) does its own gating, leaving `secretsd` nothing to hold a
  passphrase for. This backend is the opposite — since decryption
  happens in-process via rPGP, not via `gpg-agent`, **`secretsd` itself
  now owns the passphrase-protected private key material**, which is
  exactly what `LockController` (the local backend's own pattern)
  models: `unlock(passphrase)` verifies the passphrase against the
  configured secret key, `lock()` drops it, `is_unlocked()` reports
  whether one is cached. This is a real revision of the earlier "follow
  `BackendSession`" assumption from before this backend existed, not an
  inconsistency with ADR-011's actual point (which was about *external*
  sessions specifically).
- **Passphrase source: a configured, already-exported secret key file,
  never a live GnuPG keyring.** `secret_key_path` points at an
  ascii-armored OpenPGP secret key (`gpg --export-secret-keys --armor
  <key-id> > key.asc`). `secretsd` never reads GnuPG's own
  `private-keys-v1.d` — that is an S-expression protected by
  `gpg-agent`'s own protocol, not an OpenPGP secret-key packet; rPGP (an
  OpenPGP implementation) has nothing to parse there. This is a real,
  user-visible cost (one manual export step, no live keyring
  integration) accepted deliberately: reading `gpg-agent`'s private
  format would mean re-implementing a second, undocumented, agent-
  specific protocol, the same class of problem ADR-012 already avoided
  once for a different reason.
- **What `unlock()` actually caches: the passphrase, not a decrypted
  key.** rPGP's own API —
  `Message::decrypt(&Password, &SignedSecretKey)` — takes the
  passphrase on *every* call and never exposes a "stays unlocked"
  secret key object; the classic rPGP pattern decrypts key material
  transiently inside a closure's scope and never persists it on the
  struct. `PassBackend::unlock` therefore verifies the passphrase once
  (via the low-level `SecretKey::unlock` checksum/S2K check, so a wrong
  passphrase is reported at unlock time, not deferred to the first
  read) and caches the passphrase itself, in a
  `Zeroize`/`ZeroizeOnDrop` wrapper, until `lock()`/drop — achieving the
  same behavioral contract the issue asked for (one prompt per
  `unlock`, not per read) while arguably improving on a literal
  "cache the decrypted key" reading: the raw, unprotected private key
  scalar never lingers in this process's heap outside the scope of a
  single `decrypt()` call.
- **`.gpg-id` (including nested overrides) is read but never gates
  decryption.** A subdirectory's own `.gpg-id` narrowing/replacing the
  parent's recipient list is a real `pass` feature (not `gopass`-
  specific) — but it only ever changes who a *new* secret gets
  encrypted *for*. This backend never writes, so it only ever walks
  past `.gpg-id` files (never emitting them as items) and always
  attempts decryption with the one configured key regardless of what
  a `.gpg-id` in scope names. A real `gopass` mount scoped to a
  different recipient therefore does not "fail" in any special way —
  it simply does not decrypt with this store's key, handled by the
  next point.
- **Field metadata availability is not decryption-free, unlike
  Local/1Password.** A `pass` entry has no structured field-metadata
  channel — the field names beyond the guaranteed first line are only
  knowable by decrypting the whole file. `list_items`/`list_vaults`
  must stay available regardless of lock state (an existing, daemon-
  wide invariant); for `pass`, when no passphrase is cached, *or* the
  configured key fails to decrypt a specific item (locked, wrong
  recipient, corrupted ciphertext — one fallback for all three), that
  item is reported with exactly one synthetic field: `password`
  (`totp` if the first line is itself an `otpauth://` URI) — a
  heuristic derived from `pass`'s own structural convention about line
  1, never a peek at actual content. One bad item never fails the
  whole listing. `get_field` always requires a real decrypt, even for
  `password`.
- **Field-kind heuristic**, applied only once decrypted, following the
  de-facto convention `browserpass`/`passff`/`pass-otp` already use:
  first line → `password` (or `totp`, for an OTP-only entry); `login`/
  `username`/`user:` → `username`; `totp`/`otp:` or a bare `otpauth://`
  line → `totp`; `url`/`uri`/`website:` → `Custom("url")`; anything
  else recognized as a `key: value` line → `Custom(key)`. Never fails —
  same "unrecognized becomes `Custom`" discipline `LocalBackend`/
  `OnePasswordBackend` already follow.
- **Flat error construction**, directly into `CoreError`/`DaemonError`
  — mirrors `LocalBackend`'s style, not the 1Password backend's two-
  tier `CallError` design. This backend has few enough distinct failure
  modes (locked, not found, corrupted/wrong-recipient) that an
  intermediate enum would add indirection without benefit; the 1Password
  backend's own two-tier design exists to normalize many distinct raw
  IPC error shapes, a problem this backend does not have.
- **No dedicated `gopass` code.** Its stores are disk-compatible with
  `pass`, and its "multiple mounts" are just additional `pass`-
  compatible directories — each is configured as its own `[store.<id>]`
  instance under ADR-018's multi-store abstraction.
- **Path-traversal defense.** Unlike `LocalBackend`'s equivalent join
  (a `BTreeMap` key, never a filesystem path), an `ItemPath`'s segments
  here map directly to real file paths under `store_dir`. Any segment
  containing a path separator or equal to `..` is rejected (reported as
  "not found," not resolved) before it ever reaches `std::fs` — segments
  ultimately come from a `secret://` URI's percent-*decoded* path, which
  `ItemPath::new` does not itself forbid from containing a literal `/`.

## Testing

- Pure, PGP-free unit tests for field parsing (`format.rs`) and
  directory walking (`walk.rs`) against plain strings/a plain
  filesystem tree.
- Backend-level tests (`backend.rs`) against an ephemeral OpenPGP
  keypair generated **in-process with rPGP itself** (`pgp::composed::
  SecretKeyParamsBuilder`) — no `gpg` binary needed for this tier at
  all, confirming the crate's own claim to be usable without any
  external OpenPGP tooling.
- A real `gopass`-initialized store, generated once with the real
  `gpg`/`gopass` binaries in an isolated `GNUPGHOME`/`XDG_*` (never
  touching a real keyring or store), checked into `crates/secretsd/src/
  backend/pass/testdata/gopass-fixture/` (throwaway fixture key and
  values, no real secrets — see that directory's own `README.md` for
  exact provenance and regeneration steps). This is what actually
  confirms the "`gopass`'s default backend is byte-compatible with
  `pass`" claim above, rather than assuming it. No `gpg`/`gopass`
  binary is needed to *run* this test — only to have generated the
  fixture once.
- One end-to-end integration test (`tests/pass_backend.rs`) drives a
  real `secretsd` against that same checked-in fixture over
  `org.secrets.Manager`, proving the acceptance criterion the unit
  tests cannot: this backend is reachable through the real D-Bus wire
  protocol, not just through `PassBackend`'s own Rust API.

## Consequences

- **Every read re-derives key material from the passphrase, and this is
  measurably slow.** Because `unlock()` caches the passphrase rather
  than a decrypted key (see above), `get_field` re-unlocks the relevant
  encryption subkey's S2K-protected secret params on every single call,
  not just once per `unlock()`. Confirmed empirically, not assumed:
  this crate's own test suite flags several `pass`-backend tests
  (including the real-`gopass`-fixture one, whose key uses GnuPG's own
  default, deliberately expensive iterated-and-salted S2K parameters) as
  `SLOW` (rPGP's own S2K implementation takes several seconds *per
  unlock call* against a real-world key, tens of seconds for a test that
  reads several fields). This is the direct, accepted cost of the
  caching decision above; a future revision could cache a decrypted
  session-key-equivalent per subkey instead, if this proves disruptive
  in practice — not done here, since it was not part of this issue's
  scope and the current behavior is correct, just not fast.
- **One manual step to adopt**: exporting a secret key
  (`gpg --export-secret-keys --armor`) before this backend can decrypt
  anything. No live `gpg-agent`/keyring integration, and so no
  smartcard/YubiKey-backed key support either (tracked separately,
  explicitly out of scope for this ADR).
- **Field metadata is not always complete**, unlike every other backend
  today: a locked store, or one specific undecryptable item, reports
  only a guessed `password`/`totp` field until it can actually be
  decrypted. This is a real, user-visible difference from Local/
  1Password's "full metadata always" behavior, not a bug to fix later —
  it is the direct consequence of `pass`'s own file format carrying no
  metadata channel separate from its encrypted content.
- **No write support** (insert/edit/delete), for either `pass` or
  `gopass` — matches every other backend today.
- **`passage`** (age-based) and hardware-backed (YubiKey) key workflows
  remain out of scope, tracked separately (#33/#34 and future work
  respectively).
