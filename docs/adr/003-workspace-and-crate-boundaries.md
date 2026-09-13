# ADR-003: Workspace and crate boundaries

## Status

Accepted

## Context

The daemon (`secretsd`) and every client both need the `secret://` parser,
the data model, the backend contract and the shared D-Bus interface/error
definitions — none of that is client-specific or daemon-specific.
Duplicating it in every binary would let them drift apart on exactly the
things that must stay identical (URI parsing rules, D-Bus error names).

At the time this project started, `rust.tpl` (the project template — see
`AGENTS.md`) only rendered a single package at the repository root, with no
concept of a Cargo workspace. That gap was raised upstream
([rust.tpl#8](https://github.com/noirbizarre/rust.tpl/issues/8)) and
resolved before this ADR was written: the template now renders a
`workspace` boolean question that produces a virtual-manifest root, so this
project could adopt native workspace support directly rather than through
an interim, hand-maintained `[workspace]` table.

Since this ADR was first accepted, the project grew a second backend
(1Password Desktop, see [ADR-012](012-1password-desktop-backend.md)) and a
concrete need external Rust applications share with `secrets-cli`: talking
to `secretsd` without re-learning `zbus`, D-Bus object paths, interface
names, error mapping, or connection setup. `secrets-cli`'s own thin D-Bus
client (ADR-010) was exactly that logic, just not reusable outside the CLI
binary. This revision extracts it as `secrets-client`, the workspace's
public Rust client library, so a Rust application (a future GTK client, an
`Over` integration, third-party tooling) can depend on one crate instead of
reimplementing `secrets-cli`'s own D-Bus plumbing.

## Decision

Four crates and one protocol boundary, one workspace:

- **`crates/secrets-core`** — the domain/core library. `secret://` parsing
  (`uri`), the vault/item/field model (`model`), the `Backend` trait
  (`backend`), the resolver (`resolver`), and the shared D-Bus interface
  definitions and error mapping (`dbus`). Depends on nothing daemon-,
  client-, or CLI-specific; knows neither a D-Bus connection nor a
  terminal exists.
- **`crates/secrets-client`** — the public Rust client library. A thin,
  blocking wrapper over the `Manager` proxy `secrets-core` defines,
  translating it into an ergonomic API (`SecretsClient::connect`,
  `.get(...)`, ...) for any Rust application that wants to consume
  `secretsd` without its own D-Bus plumbing. Depends only on
  `secrets-core`; **never on `secretsd`** — it is a client of the
  protocol, not an abstraction over the daemon's implementation.
- **`crates/secretsd`** — the daemon binary. Implements `Backend` (the
  local encrypted-file store and the 1Password Desktop backend), owns
  session/lock state, serves `org.secrets.Manager` and the Secret Service
  compatibility interfaces, and runs the SSH agent. Depends on
  `secrets-core` only.
- **`crates/secrets-cli`** — the CLI binary (`secrets`). A thin client
  with no vault or session state of its own; every operation is a call
  through `secrets-client` into `secretsd`. It depends on `secrets-client`
  for that call path (see ADR-010); [ADR-014](014-cli-secret-disclosure-modes.md)
  later added a direct `secrets-core` dependency too, used only for the
  shared `SecretValue` type, not to resolve secrets directly.
- **The D-Bus protocol** (`org.secrets.Manager` plus the Secret Service
  compatibility interfaces) — the stable IPC contract between `secretsd`
  and every client, documented as a first-class boundary in
  [`docs/dbus/`](../dbus/README.md), not merely an implementation detail
  of `secretsd`. Rust applications should normally use `secrets-client`;
  non-Rust clients may consume this protocol directly with any D-Bus
  library. `secrets-client` does not replace or redefine it — it is an
  ergonomic Rust binding for it.

Dependency direction:

```text
secrets-core
    ^
    |
    +-- secretsd
    |
    +-- secrets-client
    |       ^
    |       |
    |       +-- secrets CLI
    |       +-- (future) external Rust applications
    |
    +-- secrets CLI (direct, for SecretValue only — see ADR-014)
```

No cross-dependency: `secretsd` never depends on `secrets-client` or
`secrets-cli`; `secrets-client` never depends on `secretsd`.

## Consequences

- URI parsing, the data model and D-Bus error names can only be changed in
  one place, and a test there is a test for every consumer at once.
- A future Rust client (a GTK application, an `Over` integration) means
  depending on `secrets-client` — a **published-in-this-workspace
  library**, not a new workspace member of its own. GTK, TUI and browser
  *applications* themselves (GD Secrets, `secrets-tui`,
  `secrets-firefox`/`secrets-chrome`) are separate repositories entirely —
  see [`docs/architecture/external-clients.md`](../architecture/external-clients.md)
  — this repository never grows a UI/browser crate to host them.
- The daemon's business logic (`secrets-core` + `secretsd`'s own modules)
  can be exercised in tests without a D-Bus connection at all, since
  `secretsd`'s D-Bus interface implementations are thin wrappers over
  plain Rust types.
- `secrets-cli`'s own D-Bus client code (`client.rs`) was removed in favour
  of `secrets-client`: the CLI now has exactly the same D-Bus plumbing
  every other Rust consumer of `secrets-client` has, not a parallel
  implementation of it.
</content>
