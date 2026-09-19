# ADR-008: Backend abstraction and the pluggable-backend roadmap

## Status

Accepted. The "cannot run two backends at once" limitation named in this
ADR's own Consequences is lifted by
[ADR-018](018-multi-store-support.md); the trait design and roadmap
described here are otherwise unchanged. The filesystem-based `pass`/
`gopass` roadmap item is implemented by
[ADR-019](019-pass-backend.md); `passage` remains future work.

## Context

Secrets is meant to outlive any one storage choice — the daemon is the
stable interface, the backend behind it is replaceable (see the README's
opening paragraph). The MVP ships exactly one backend (a local encrypted
file, ADR-006), but the abstraction has to be shaped so that
fundamentally different future backends fit it without redesign:

- **API-based** backends (Vaultwarden, Bitwarden, 1Password): authenticate
  over HTTPS, fetch structured data, no local file format to define.
- **Filesystem-based** backends (`pass`, `gopass`, `passage`): a directory
  tree of GPG- or age-encrypted files, one file per secret, decrypted by
  shelling out to or linking against the relevant tool.

## Decision

`secrets_core::Backend` stays intentionally small: `list_vaults`,
`list_items`, `get_field` — read-only, and nothing about *how* a backend
authenticates, decrypts, or stores. Locking/unlocking is deliberately
**not** part of this trait: it varies too much between backend shapes (a
local passphrase versus an OAuth token versus a GPG agent already running)
to force into one signature now. For the MVP, `secretsd`'s
`DaemonState` holds its one backend concretely as `Arc<LocalBackend>`
rather than `Arc<dyn Backend>` specifically so it can call
`LocalBackend::unlock(passphrase)`/`lock()` directly — see
`crates/secretsd/src/state.rs`.

This is an accepted MVP simplification, not the final shape: the first
backend added after the local one will need either (a) a second
small trait (`Unlockable`, say) that session-capable backends implement,
with `DaemonState` holding `Arc<dyn Backend>` plus an
`Option<Arc<dyn Unlockable>>`, or (b) some other seam discovered once a
second backend's actual constraints are known. Deferred on purpose:
designing that seam against one data point (the local backend) risks
guessing wrong for both API-based and filesystem-based backends at once.

Tracked roadmap, in `PLAN.md` §7: Vaultwarden, Bitwarden, 1Password
(API-shaped), `pass`, `gopass`, `passage` (filesystem-and-GPG/age-shaped).
None implemented in this MVP.

## Consequences

- Today, `secretsd` cannot run two backends at once, or switch backends
  without a restart — acceptable for an MVP with one backend, revisited
  when a second is built.
- The trait's small surface means a future backend author implements three
  methods, not an entire session/auth/config framework — the framework
  gets designed once real requirements from a second backend exist.
- `Resolver` (`secrets_core::resolver`) depends only on `&dyn Backend`, so
  none of the resolution logic changes when a new backend is added; only
  `secretsd`'s own wiring (`state.rs`) needs to grow to accommodate a
  second backend's session shape.
