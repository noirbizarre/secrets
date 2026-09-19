<p align="center">
  <img src="docs/images/logo.svg" alt="secrets">
</p>

<h1 align="center">secrets</h1>

<p align="center"><strong>Local-first secret broker and secret manager for Linux desktops</strong></p>

<p align="center">
  <a href="https://github.com/noirbizarre/secrets/actions/workflows/ci.yaml">
    <img src="https://github.com/noirbizarre/secrets/actions/workflows/ci.yaml/badge.svg" alt="CI">
  </a>
  <a href="https://codecov.io/gh/noirbizarre/secrets">
    <img src="https://codecov.io/gh/noirbizarre/secrets/graph/badge.svg" alt="Codecov">
  </a>
  <img src="https://img.shields.io/github/v/release/noirbizarre/secrets" alt="Release">
  <a href="https://noirbizarre.github.io/secrets/">
    <img src="https://img.shields.io/badge/docs-noirbizarre.github.io-blue" alt="Documentation">
  </a>
  <img src="https://img.shields.io/github/license/noirbizarre/secrets" alt="License">
</p>

---

Every Linux desktop ends up with secrets scattered across a dozen
incompatible places: a password manager's own vault, `~/.ssh/`, a browser's
built-in store, environment variables exported from a shell profile,
plaintext files nobody remembers to `.gitignore`. Each tool that wants a
secret invents its own way to ask for one. **Secrets** is a local-first
secret broker: one user-session daemon (`secretsd`) that owns the actual
secret store and the access control, and a stable local interface —
D-Bus — that any client speaks. The storage backend behind it is
replaceable; the interface is not. Secrets is not another password-manager
UI — it is the plumbing other tools use to reach one.

```mermaid
flowchart TB
    subgraph apps["Applications"]
        over[Over]
        gtk["GD Secrets"]
        tui[secrets-tui]
    end
    cli[secrets CLI]
    client[[secrets-client]]
    dbus{{D-Bus}}
    ssh[OpenSSH ssh / ssh-add]
    stclients[secret-tool / libsecret clients]

    subgraph secretsd
        secretservice["org.freedesktop.Secret.*\n(standard contract)"]
        manager["org.secrets.Manager\n(extensions)"]
        agent[SSH agent socket]
        backend[(Backend)]
    end

    over --> client
    gtk --> client
    tui --> client
    cli --> client
    client --> dbus --> manager
    ssh -- SSH agent protocol --> agent
    stclients -- D-Bus --> secretservice

    manager --> backend
    secretservice --> backend
    agent --> backend
```

## The Secrets ecosystem

Secrets is not one binary — it is a small ecosystem, all in this
repository except the applications on top:

| Crate                          | Role                                                    |
| ------------------------------- | -------------------------------------------------------- |
| `secretsd`                      | The daemon/service: owns the secret store and session/lock state |
| `secrets-cli` (binary: `secrets`) | The CLI: a thin client, no vault or session state of its own |
| `secrets-core`                  | The domain library: `secret://` parsing, model, backend contract |
| `secrets-client`                | The public Rust client library for the D-Bus protocol   |
| D-Bus (`org.freedesktop.Secret.*` + `org.secrets.*`) | The protocol — the standard Secret Service contract plus the `org.secrets.*` extension namespace, both stable, between `secretsd` and every client |

`GD Secrets` (a GTK application), `secrets-tui`, and browser extensions are
**separate repositories** that consume `secrets-client` or the D-Bus
protocol directly — not workspace members of this one. See
[`docs/architecture/external-clients.md`](docs/architecture/external-clients.md).
A non-Rust application does not need `secrets-client` either: it can speak
the standard Secret Service interfaces (for interoperability with
existing tooling) or `org.secrets.Manager` (for `secret://`-specific
operations) over D-Bus directly, with any D-Bus library — see
[`docs/dbus/README.md`](docs/dbus/README.md).

`secrets` (the CLI) is itself just one more client, no more privileged
than any other:

```text
secrets CLI
    |
    v
secrets-client
    |
    v
  D-Bus
    |
    v
 secretsd
```

Secrets are addressed by a `secret://<vault>/<item>/<field>` URI — see
[`docs/secret-uri.md`](docs/secret-uri.md). That scheme is the *resource
reference*; D-Bus is the *transport*. The two answer different questions,
and the documentation treats them as such.

## Installation

Or download a binary for your platform from the
[latest release](https://github.com/noirbizarre/secrets/releases/latest).

## Usage

```bash
secretsd &                        # or: systemctl --user enable --now secretsd
secrets status                    # locked
secrets unlock                    # prompts for a passphrase
secrets list                      # default@Personal, default@Infrastructure, ...
secrets list Personal             # GitHub
secrets get secret://Personal/GitHub/password
secrets lock

SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/secrets/ssh-agent.sock ssh-add -L
```

With more than one configured store (see [Configuration](#configuration-storeid) below),
qualify a reference with `store@` whenever a bare vault name would be
ambiguous, and target one store's own lock with `--store`:

```bash
secrets stores                    # personal: unlocked
                                   # work: locked
secrets unlock --store work
secrets get secret://work@Personal/GitHub/password
```

## Current MVP scope

- One or more configured *stores* (ADR-018), each one backend instance —
  a local, AES-256-GCM-encrypted file by default
  (see [`docs/security.md`](docs/security.md)), or 1Password Desktop.
- Two states per store: locked and unlocked (no per-vault locking within
  a store). `secrets lock`/`unlock`/`status` with no `--store` compose
  over every configured store; pass `--store <id>` to target one.
- Secret Service compatibility covers the "plain" session algorithm only.
- `secrets inject`, `secrets run` and `secrets totp` exist as a CLI surface
  (see `secrets --help`) but are not implemented yet.
- No GTK, TUI or browser client yet — those are separate repositories, not
  workspace members of this one. See
  [`docs/architecture/external-clients.md`](docs/architecture/external-clients.md)
  for the boundary they will attach behind once they exist.

Full roadmap, tracked by category with checkboxes: [`PLAN.md`](PLAN.md).
Design rationale for every non-obvious decision: [`docs/adr/`](docs/adr/).

## Backends

The `Backend` trait (`crates/secrets-core/src/backend.rs`) is deliberately
small so more implementations can be added without touching `secretsd`'s
D-Bus surface. Two exist today: the local encrypted file (the default),
and 1Password Desktop, via its native IPC library rather than the `op`
CLI (`crates/secretsd/src/backend/onepassword/` — see
[ADR-012](docs/adr/012-1password-desktop-backend.md) and the
[setup guide](docs/backends/1password.md)). Vaultwarden and
Bitwarden (API-based) and `pass`/`gopass`/`passage` (GPG- or
age-encrypted files on disk) are the remaining tracked candidates — see
`PLAN.md` §7.

### Configuration: `[store.<id>]`

`secretsd` reads `~/.config/secrets/secretsd.toml`. With no file (or a
file with no `[store.*]` table at all), it runs exactly one implicit
store, id `default`, backed by the local encrypted file — the zero-config
case above. More than one store (ADR-018) can be configured at once —
each `[store.<id>]` table shaped the same way, `<id>` becoming that
store's name in `secret://` references (`store@vault`) and `secrets
--store <id>`:

```toml
[store.personal]
type = "local"

[store.work]
type = "1password"
account_name = "Work"
```

**Migrating from `[backend]`**: the pre-ADR-018 single `[backend]` table
is no longer accepted. Rename it to `[store.default]`, keeping every
other field the same — `default` maps to the same fixed vault file
(`vault.toml`) the implicit zero-config case already uses, so this rename
alone changes nothing observable.

## Documentation

<https://noirbizarre.github.io/secrets/>

- [1Password Desktop backend setup](docs/backends/1password.md)
- [`secret://` URI scheme](docs/secret-uri.md)
- [Architecture overview](docs/architecture/overview.md)
- [External clients (GTK, TUI, browser)](docs/architecture/external-clients.md)
- [The D-Bus protocol](docs/dbus/README.md)
- [`org.secrets.Manager` D-Bus API](docs/dbus/secrets-manager.md)
- [Secret Service compatibility](docs/dbus/secret-service.md)
- [SSH agent](docs/dbus/ssh-agent.md)
- [Security model](docs/security.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE](LICENSE).
