# ADR-005: The `org.secrets.Manager` native API

## Status

Accepted

## Context

The Secret Service compatibility layer (ADR-004) exists so *existing*
tools keep working; it is not shaped the way a Secrets-aware client would
choose to talk to `secretsd` if it did not need to imitate another
specification. `secrets-cli` — and, via `secrets-client`, eventual
external clients such as GD Secrets and a browser native messaging host —
need an interface that speaks `secret://` references directly,
distinguishes "the store is locked" from "this does not exist" with named
errors, and can grow new capabilities (TOTP generation, SSH key metadata,
...) without breaking existing callers.

## Decision

A second, Secrets-owned interface: `org.secrets.Manager`, defined once in
`secrets-core::dbus` via a plain (non-`async`) trait under
`#[zbus::proxy]` — which generates both an async and a blocking proxy from
the same declaration, so `secrets-client` (and `secrets-cli` through it)
never needs an async runtime just to make a method call (see ADR-010).

Seven methods for the MVP:

- `Status` / `Unlock` / `Lock` — the session/lock state machine (ADR-009).
- `ListVaults` / `ListItems` — metadata only, available regardless of lock
  state, since names are not secret material.
- `Resolve` — validates a `secret://` reference (vault, item and field all
  exist) without returning its value; requires the store to be unlocked,
  since confirming a field exists is itself information about unlocked
  contents.
- `Get` — the one method that returns a secret's plaintext value. The only
  place secret material crosses the bus on this interface.

Errors are named, not just described: `secrets-core::dbus::ManagerError`
(`#[derive(zbus::DBusError)]`, prefix `org.secrets.Error`) gives every
`CoreError` variant — `InvalidUri`, `VaultLocked`, `NotFound`,
`PermissionDenied`, `InvalidOperation`, `BackendUnavailable` — its own
D-Bus error name, so a client matches on the failure instead of parsing a
message string.

Forward compatibility is additive by convention: new methods or properties
can be appended to the interface without breaking existing clients (D-Bus
dispatches by name); an existing method's signature is never changed after
the fact.

## Consequences

- `secrets-cli` holds no vault or session state of its own — every command
  is a direct call into this interface (ADR-010).
- Adding `Inject`/`Run`/`Totp`-shaped daemon support later (the CLI
  commands already have a surface — see `crates/secrets-cli/src/cli.rs` —
  but no daemon-side implementation yet) means adding new
  `org.secrets.Manager` methods, not a new interface.
- A future second backend with different authentication (Vaultwarden's
  OAuth, say) will need `Unlock`'s single-passphrase-string signature
  reconsidered — deferred rather than over-generalised now (see ADR-008).
