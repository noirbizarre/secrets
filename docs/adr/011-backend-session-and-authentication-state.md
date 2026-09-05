# ADR-011: Backend session and authentication state

## Status

Accepted

## Context

ADR-008 kept `secrets_core::Backend` deliberately small and said locking
was excluded on purpose because it "varies too much between backend
shapes... to force into one signature now", forecasting that "the first
backend added after the local one will need either (a) a second small
trait... or (b) some other seam discovered once a second backend's actual
constraints are known."

The next backend on the roadmap (PLAN.md §7), 1Password Desktop, is that
second data point. It has its own authentication and session lifecycle,
entirely external to `secretsd`: the user unlocks 1Password Desktop
itself (biometrics, its own master password), and the Desktop app grants
or denies IPC requests based on a session `secretsd` does not create,
store, or renew on the user's behalf (see
`docs/architecture/1password-integration.md`). That session can expire
independently of whatever the daemon's own lock state is — the daemon can
be unlocked while 1Password Desktop's session has lapsed, or vice versa.
ADR-009's daemon-wide Locked/Unlocked state machine has no room for this;
conflating the two would either force every backend into a 1Password-
shaped auth model, or force 1Password's session into a two-state lock it
does not fit.

## Decision

Keep ADR-009's daemon lock exactly as it is: two states, one authority
(`DaemonState`), unchanged by this ADR. Add a second, optional, orthogonal
concept for a backend's *own* session, in `secrets_core::backend`:

```rust
pub enum BackendStatus {
    Available,
    Unavailable,
    RequiresAuthentication,
    Authenticated,
    SessionExpired,
}

pub trait BackendSession: Send + Sync {
    fn backend_status(&self) -> BackendStatus;
}
```

`DaemonState` gains `session: Option<Arc<dyn BackendSession>>`, checked in
addition to (never instead of) the existing `is_unlocked()` check inside
`get`/`resolve`. The local backend never implements `BackendSession` and
`open_default_state` passes `None` — its "unlock" already *is* the
daemon-wide lock, so there is nothing separate to report. A future
`OnePasswordBackend` implements `BackendSession`, reporting
`RequiresAuthentication`/`SessionExpired` when its native IPC session
needs (re-)establishing.

Two new, narrowly-scoped errors carry this distinction over the wire
without leaking why a session is missing: `CoreError::
BackendRequiresAuthentication` (mirrored as `org.secrets.Error.
BackendRequiresAuthentication`) for `RequiresAuthentication`/
`SessionExpired`, and the existing `CoreError::BackendUnavailable` reused
for `BackendStatus::Unavailable` rather than inventing a duplicate.

## Consequences

- A client can now tell "the daemon itself is locked, run `secrets
  unlock`" apart from "the daemon is unlocked, but the active backend
  needs its own re-authentication" — two different problems that used to
  have no way to be distinguished, since only `VaultLocked` existed.
- `secrets_core::Backend` itself is untouched: `BackendSession` is a
  second, optional trait, exactly the "(a)" option ADR-008 forecast.
  Backends with no external session (the local file, and likely `pass`/
  `gopass`/`passage`) never implement it and pay no cost.
- `DaemonState` grows a third constructor parameter; every existing call
  site (`open_default_state`, and now every test) has to say `None`
  explicitly for backends without a session — a small, deliberate
  verbosity cost in exchange for no implicit "no session" default a
  future backend author could silently rely on by mistake.
- This ADR does not decide anything about *renewal* (single-flight
  refresh, timeouts) — that is `secretsd`'s own session-management logic
  for a specific backend (1Password Desktop's, when implemented), not a
  concern of this shared, generic enum.
</content>
