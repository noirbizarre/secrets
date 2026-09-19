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
        provider["prompt provider<br/>(e.g. secrets-prompt-gtk)"]
    end

    client[[secrets-client]]

    subgraph secretsd
        direction TB
        ss["org.freedesktop.Secret.*\n(standard contract)"]
        manager["org.secrets.Manager\n(extensions)"]
        broker["PromptBroker\n(org.secrets.PromptBroker1)"]
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
    ss -. Prompt() .-> broker
    agent --> state
    state --> resolver
    resolver --> backend
    backend --> local
    backend --> onepassword
    backend -. not yet .-> future
    broker <-. org.secrets.PromptProvider1 .-> provider
```

## Layers

1. **`secret://` URI** (`secrets-core::uri`) — parses and validates a
   reference into an optional `store` qualifier, `vault`, `item` (one or
   more path segments) and `field` — see
   [ADR-018](../adr/018-multi-store-support.md). Reused by every crate;
   never reimplemented per client.
2. **Resolver** (`secrets-core::resolver`) — turns a parsed `SecretUri`
   into a value via a `Backend`. Knows nothing about D-Bus, locking,
   sessions, or store identity — a `Backend` implementation never learns
   which store it was configured as (ADR-018).
3. **Backend** (`secrets-core::backend`) — the contract a storage
   implementation satisfies: `list_vaults`, `list_items`, `get_field`.
   Deliberately small and read-only; see
   [ADR-008](../adr/008-backend-abstraction-and-roadmap.md). A second,
   optional trait, `BackendSession`, lets a backend report its own
   authentication/session state, distinct from `DaemonState`'s per-store
   lock — see [ADR-011](../adr/011-backend-session-and-authentication-state.md).
   Two implementations exist: the local encrypted file, and 1Password
   Desktop's native IPC channel (not the `op` CLI) — see
   [ADR-012](../adr/012-1password-desktop-backend.md),
   [1password-integration.md](1password-integration.md) and
   [1password-poc-results.md](1password-poc-results.md) for the
   investigation and validation behind it. Either can be configured more
   than once, as separate named *stores* (ADR-018) — a store is one
   configured backend instance, which may itself expose several named
   vaults.
4. **`secretsd`** — the daemon. Owns `DaemonState`, a registry of every
   configured store, each with its own session/lock (ADR-009, extended by
   [ADR-018](../adr/018-multi-store-support.md) to per-store); a keyed
   collection of backend instances (`[store.<id>] type = "local" |
   "1password"` — see [config.rs](../../crates/secretsd/src/config.rs));
   and three protocol surfaces: the standard Secret Service interfaces
   ([ADR-004](../adr/004-secret-service-compatibility-scope.md)), the
   `org.secrets.*` extension namespace
   ([ADR-005](../adr/005-native-manager-api-design.md)), and the SSH agent
   ([ADR-007](../adr/007-ssh-agent-implementation.md)). See
   [ADR-013](../adr/013-standard-secret-service-and-extension-namespace.md)
   for how the first two relate. A toolkit-independent `PromptBroker`
   (`org.secrets.PromptBroker1`/`PromptProvider1`/`PromptRequest1`) lets an
   external, desktop-specific prompt provider answer interactive prompts
   (today: the Secret Service `Prompt` interface's unlock flow) without
   `secretsd` depending on any UI toolkit itself — see
   [ADR-017](../adr/017-prompt-broker-and-provider-protocol.md) and
   [`docs/dbus/prompt-broker.md`](../dbus/prompt-broker.md).
5. **Clients** — `secrets-cli` today, via `secrets-client`
   ([ADR-010](../adr/010-cli-as-thin-dbus-client.md)); GD Secrets,
   `secrets-tui` and browser native messaging hosts in the future, each a
   separate repository (see [external-clients.md](external-clients.md));
   any Secret-Service-speaking application (`secret-tool`, `libsecret`
   consumers) today, read-only. A **prompt provider** (e.g. a future
   `secrets-prompt-gtk`) is a different kind of external peer — it answers
   `secretsd`'s own prompts rather than requesting secrets — see
   [`docs/dbus/prompt-broker.md`](../dbus/prompt-broker.md).

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
