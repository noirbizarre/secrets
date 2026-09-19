# ADR-009: Session and lock state machine

## Status

Accepted. Superseded in part by
[ADR-018](018-multi-store-support.md): locking is no longer a single
daemon-wide boolean, but N per-store instances of exactly this same
two-state machine, composed by `DaemonState` into the same daemon-wide
operations for backward compatibility — the state machine itself, and its
one-authority principle, stand.

## Context

Every client — the CLI and the SSH agent today; external GUI/TUI/browser
clients (via `secrets-client` or the D-Bus protocol directly) eventually —
needs to agree on whether secrets are currently readable, and that
agreement has to live in exactly one place — `secretsd` — or two clients
could observe contradictory answers (one client's `unlock` should be
visible to every other client immediately, including a
concurrently-running SSH connection attempt).

## Decision

Two states for the MVP: **Locked** and **Unlocked**, daemon-wide (not
per-vault, not per-client). `secrets_core::dbus::{STATUS_LOCKED,
STATUS_UNLOCKED}` name them; `DaemonState` (`crates/secretsd/src/state.rs`)
is the single authority every interface — `org.secrets.Manager`, the
Secret Service compatibility objects, and the SSH agent — reads before
deciding whether to serve a request:

- **Locked**: `Resolve`/`Get` fail with `VaultLocked`; the SSH agent
  reports zero identities and fails every `sign`; `ListVaults`/
  `ListItems` still work (names are not secret material — see ADR-005).
- **Unlocked**: everything above succeeds, subject to the reference
  actually resolving to something that exists.

No intermediate states (no "unlocking", no per-item locks) exist in the
MVP. The transition itself lives in the backend (`LocalBackend::unlock`/
`lock`, ADR-006, ADR-008) — `DaemonState` only asks it "are you unlocked?"
and forwards the answer; it does not duplicate that bookkeeping itself.

## Consequences

- A client cannot be told "half-unlocked" — simplifies every interface's
  error handling, at the cost of coarser granularity (unlocking to read
  one vault's contents makes every vault's contents readable).
- The state machine is trivially auditable: `DaemonState::is_unlocked`
  (one boolean read) is the one function every "am I allowed to do this"
  check in the codebase calls.
- Per-vault locking, if ever wanted, is a breaking change to this ADR, not
  an incremental extension — recorded as a future decision to make
  explicitly (via a superseding ADR) rather than something to grow into
  accidentally.
