# Architecture overview

Secrets is a local secret broker: one daemon owns the secret store and
access control, and a stable local interface — D-Bus — is how everything
else reaches it. `secret://` is the *resource reference* (see
[secret-uri.md](../secret-uri.md)); D-Bus is the *transport*. The
underlying storage backend is replaceable and never assumed by clients.

```mermaid
flowchart TB
    subgraph Today
        cli[secrets CLI]
        ssh[ssh / ssh-add]
        st[secret-tool / libsecret clients]
    end

    subgraph ext["External repositories"]
        gtk["GD Secrets"]
        tui[secrets-tui]
        browser[browser extensions]
    end

    client[[secrets-client]]

    subgraph secretsd
        direction TB
        ss["org.freedesktop.Secret.*\n(standard contract)"]
        manager["org.secrets.Manager\n(extensions)"]
        agent[SSH agent socket]
        state[DaemonState\nlock/session]
        resolver["Resolver<br/>(secrets-core)"]
        backend[Backend trait]
    end

    local[(Local encrypted file)]
    onepassword[(1Password Desktop<br/>native IPC)]
    future[(Vaultwarden / Bitwarden /<br/>pass / gopass / passage)]

    cli --> client
    gtk -. secrets-client or D-Bus .-> client
    tui -. secrets-client or D-Bus .-> client
    browser -. Native Messaging .-> gtk
    client -- D-Bus --> manager
    ssh -- SSH agent protocol --> agent
    st -- D-Bus --> ss

    manager --> state
    ss --> state
    agent --> state
    state --> resolver
    resolver --> backend
    backend --> local
    backend --> onepassword
    backend -. not yet .-> future
```

## Layers

1. **`secret://` URI** (`secrets-core::uri`) — parses and validates a
   reference into `vault`, `item` (one or more path segments) and `field`.
   Reused by every crate; never reimplemented per client.
2. **Resolver** (`secrets-core::resolver`) — turns a parsed `SecretUri`
   into a value via a `Backend`. Knows nothing about D-Bus, locking, or
   sessions.
3. **Backend** (`secrets-core::backend`) — the contract a storage
   implementation satisfies: `list_vaults`, `list_items`, `get_field`.
   Deliberately small and read-only; see
   [ADR-008](../adr/008-backend-abstraction-and-roadmap.md). A second,
   optional trait, `BackendSession`, lets a backend report its own
   authentication/session state, distinct from `DaemonState`'s daemon-wide
   lock — see [ADR-011](../adr/011-backend-session-and-authentication-state.md).
   Two implementations exist: the local encrypted file, and 1Password
   Desktop's native IPC channel (not the `op` CLI) — see
   [ADR-012](../adr/012-1password-desktop-backend.md),
   [1password-integration.md](1password-integration.md) and
   [1password-poc-results.md](1password-poc-results.md) for the
   investigation and validation behind it.
4. **`secretsd`** — the daemon. Owns `DaemonState` (session/lock — see
   [ADR-009](../adr/009-session-and-lock-state-machine.md)),
   configuration-selected backend (`[backend] type = "local" |
   "1password"` — see [config.rs](../../crates/secretsd/src/config.rs)),
   and three protocol surfaces: the standard Secret Service interfaces
   ([ADR-004](../adr/004-secret-service-compatibility-scope.md)), the
   `org.secrets.*` extension namespace
   ([ADR-005](../adr/005-native-manager-api-design.md)), and the SSH agent
   ([ADR-007](../adr/007-ssh-agent-implementation.md)). See
   [ADR-013](../adr/013-standard-secret-service-and-extension-namespace.md)
   for how the first two relate.
5. **Clients** — `secrets-cli` today, via `secrets-client`
   ([ADR-010](../adr/010-cli-as-thin-dbus-client.md)); GD Secrets,
   `secrets-tui` and browser native messaging hosts in the future, each a
   separate repository (see [external-clients.md](external-clients.md));
   any Secret-Service-speaking application (`secret-tool`, `libsecret`
   consumers) today, read-only.

## Crates

See [ADR-003](../adr/003-workspace-and-crate-boundaries.md) for the
reasoning; in short:

| Crate                   | Role                                             |
| ------------------------ | ------------------------------------------------ |
| `crates/secrets-core`   | Domain/core library: URI parsing, model, backend trait, D-Bus definitions |
| `crates/secrets-client` | The public Rust client library for the D-Bus protocol |
| `crates/secretsd`       | The daemon binary                                |
| `crates/secrets-cli`    | The `secrets` CLI binary                         |

Dependencies point one way: `secretsd` depends on `secrets-core` directly;
`secrets-cli` depends on `secrets-client`, which itself depends on
`secrets-core`. `secrets-client` never depends on `secretsd`, and
`secretsd` never depends on either client crate.
