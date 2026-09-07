<p align="center">
  <img src="docs/images/icon.svg" alt="secrets" width="160">
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
        manager["org.secrets.Manager"]
        secretservice["org.freedesktop.Secret.*\n(compatibility)"]
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
| `secrets`                       | The CLI: a thin client, no vault or session state of its own |
| `secrets-core`                  | The domain library: `secret://` parsing, model, backend contract |
| `secrets-client`                | The public Rust client library for the D-Bus protocol   |
| D-Bus (`org.secrets.*`)         | The protocol — the stable contract between `secretsd` and every client |

`GD Secrets` (a GTK application), `secrets-tui`, and browser extensions are
**separate repositories** that consume `secrets-client` or the D-Bus
protocol directly — not workspace members of this one. See
[`docs/architecture/external-clients.md`](docs/architecture/external-clients.md).
A non-Rust application does not need `secrets-client` either: it can speak
`org.secrets.Manager` over D-Bus directly, with any D-Bus library — see
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
secrets list                      # Personal, Infrastructure, ...
secrets list Personal             # GitHub
secrets get secret://Personal/GitHub/password
secrets lock

SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/secrets/ssh-agent.sock ssh-add -L
```

## Current MVP scope

- One backend: a local, AES-256-GCM-encrypted file
  (see [`docs/security.md`](docs/security.md)).
- Two states: locked and unlocked, daemon-wide (no per-vault locking yet).
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
D-Bus surface. Two exist today: the local encrypted file (the MVP
default), and 1Password Desktop, via its native IPC library rather than
the `op` CLI (`crates/secretsd/src/backend/onepassword/`, selected with
`[backend] type = "1password"` — see
[ADR-012](docs/adr/012-1password-desktop-backend.md)). Vaultwarden and
Bitwarden (API-based) and `pass`/`gopass`/`passage` (GPG- or
age-encrypted files on disk) are the remaining tracked candidates — see
`PLAN.md` §7.

## Documentation

<https://noirbizarre.github.io/secrets/>

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
