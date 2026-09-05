# ADR-010: The CLI as a thin D-Bus client only

## Status

Accepted

## Context

`secrets-cli` could, in principle, open the vault file itself and
duplicate `secretsd`'s resolution logic — it links `secrets-core`, which
has everything needed to do so. That would make simple commands faster
(no D-Bus round trip) but would create two independent implementations of
locking, resolution and backend access that could drift, and would defeat
the entire premise of a *daemon* as the secret broker: a second process
that also reads the vault file is a second place secret material can leak
from, and a second place lock state can be wrong.

## Decision

`secrets-cli` holds no vault or session state of its own. Every command in
`crates/secrets-cli/src/lib.rs::run` does exactly one thing: parse
arguments (`cli.rs`), call one or more methods on
`client::Client` (a thin wrapper over the generated
`ManagerProxyBlocking` — see ADR-005 on why no async runtime is needed
here), and format the result. `crates/secrets-core` is used only for
shared types (`SecretUri`, the D-Bus interface/error definitions) — never
for resolving a secret directly.

The one deliberate exception, `secrets-cli/src/config.rs`, loads a local
TOML file (`~/.config/secrets/config.toml`) for CLI-only preferences (a
default vault, in the future) — configuration, not secret data, and it
never touches the vault file or bypasses the daemon.

## Consequences

- `secretsd` down means every `secrets` command fails with a clear
  "could not reach secretsd" error (`CliError::DaemonUnreachable`) rather
  than silently falling back to reading the vault file directly.
- Every lock-state and resolution bug has exactly one place to be fixed:
  `secretsd`. The CLI cannot have its own, different bug in the same
  logic, because it does not have its own copy of that logic.
- Future clients (`secrets-gtk`, the browser native messaging host) follow
  the same rule by construction: they will use the same
  `org.secrets.Manager` proxy `secrets-core` already generates, not a
  parallel implementation — see `docs/architecture/clients.md`.
