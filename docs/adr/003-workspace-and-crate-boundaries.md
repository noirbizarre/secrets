# ADR-003: Workspace and crate boundaries

## Status

Accepted

## Context

The daemon (`secretsd`) and the CLI (`secrets-cli`) both need the
`secret://` parser, the data model, the backend contract and the shared
D-Bus interface/error definitions — none of that is CLI-specific or
daemon-specific. Duplicating it in two binaries would let the two drift
apart on exactly the things that must stay identical (URI parsing rules,
D-Bus error names).

At the time this project started, `rust.tpl` (the project template — see
`AGENTS.md`) only rendered a single package at the repository root, with no
concept of a Cargo workspace. That gap was raised upstream
([rust.tpl#8](https://github.com/noirbizarre/rust.tpl/issues/8)) and
resolved before this ADR was written: the template now renders a
`workspace` boolean question that produces a virtual-manifest root, so this
project could adopt native workspace support directly rather than through
an interim, hand-maintained `[workspace]` table.

## Decision

Three crates, three responsibilities, one workspace:

- **`crates/secrets-core`** — the shared library. `secret://` parsing
  (`uri`), the vault/item/field model (`model`), the `Backend` trait
  (`backend`), the resolver (`resolver`), and the shared D-Bus interface
  definitions and error mapping (`dbus`). Depends on nothing daemon- or
  CLI-specific; knows neither a D-Bus connection nor a terminal exists.
- **`crates/secretsd`** — the daemon binary. Implements `Backend` (the
  local encrypted-file store), owns session/lock state, serves
  `org.secrets.Manager` and the Secret Service compatibility interfaces,
  and runs the SSH agent.
- **`crates/secrets-cli`** — the CLI binary (`secrets`). A thin D-Bus
  client with no vault or session state of its own; every operation is a
  call into `secretsd`.

Dependencies point one way only: `secretsd` and `secrets-cli` both depend
on `secrets-core`; neither depends on the other.

## Consequences

- URI parsing, the data model and D-Bus error names can only be changed in
  one place, and a test there is a test for every consumer at once.
- Adding a future client (`secrets-gtk`) means adding a fourth workspace
  member that depends on `secrets-core`, not touching `secretsd` or
  `secrets-cli`.
- The daemon's business logic (`secrets-core` + `secretsd`'s own modules)
  can be exercised in tests without a D-Bus connection at all, since
  `secretsd`'s D-Bus interface implementations are thin wrappers over
  plain Rust types.
