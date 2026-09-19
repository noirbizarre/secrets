# The Secrets protocol

D-Bus is not an implementation detail of `secretsd` — it is the
**inter-process protocol of the Secrets ecosystem**: the stable contract
every client, present or future, Rust or not, relies on to talk to
`secretsd`. This directory is that protocol's specification.

- [`secret-service.md`](secret-service.md) — the standard freedesktop
  [Secret Service](https://specifications.freedesktop.org/secret-service/latest/)
  interfaces, the **primary, interoperable contract**: any client
  written against the specification (`secret-tool`, `libsecret`, GNOME
  Keyring/KWallet-compatible consumers) works against `secretsd`
  unmodified, no Secrets-specific code required.
- [`secrets-manager.md`](secrets-manager.md) — `org.secrets.Manager`, the
  `org.secrets.*` **extension namespace** layered on top, for
  `secret://`-shaped operations the standard interfaces have no way to
  express (`Resolve`/`Get` a `secret://` reference directly,
  single-passphrase `Unlock`/`Status`).
- [`ssh-agent.md`](ssh-agent.md) — the standard SSH agent wire protocol
  over its own Unix socket, documented here for completeness even though
  it is deliberately **not** D-Bus (see [ADR-001](../adr/001-dbus-as-the-ipc-mechanism.md)
  for why that one exception exists).

See [ADR-013](../adr/013-standard-secret-service-and-extension-namespace.md)
for why the two D-Bus surfaces are framed this way, and for the bus-name
detail that makes the standard contract actually reachable (`secretsd`
requests `org.freedesktop.secrets` best-effort, in addition to its own
`org.secrets.Daemon`).

## Which interface each `secrets` command uses

A reader who only runs `secrets --help` and never opens the pages above:
every `secrets` subcommand today goes through the `org.secrets.*`
extension namespace, because every one of them is a `secret://`-shaped
operation the standard interfaces have no way to express (a
single-passphrase unlock model, or resolving/fetching a `secret://`
reference directly rather than a Secret Service object path). Nothing in
the CLI talks to the standard Secret Service interfaces — those exist for
*other* clients (`secret-tool`, `libsecret`-based applications) to keep
working unmodified, not for `secrets` itself to use.

| Command                         | Interface             | Method                        |
| -------------------------------- | ---------------------- | ------------------------------ |
| `secrets status`                 | `org.secrets.Manager`  | `Status`                       |
| `secrets unlock`                 | `org.secrets.Manager`  | `Unlock`                       |
| `secrets lock`                   | `org.secrets.Manager`  | `Lock`                         |
| `secrets list`                   | `org.secrets.Manager`  | `ListVaults` / `ListItems`     |
| `secrets resolve`                | `org.secrets.Manager`  | `Resolve`                      |
| `secrets get`                    | `org.secrets.Manager`  | `Get`                          |
| `secrets show`                   | `org.secrets.Manager`  | `ShowItem`                     |

See [ADR-014](../adr/014-cli-secret-disclosure-modes.md) for what `secrets
get` does with the value once it has it (default/`--raw`/`--json`/
`--clipboard`) — a CLI-side decision, not a protocol one; the wire method
called is `Get` in every case. See
[ADR-016](../adr/016-show-command-and-field-value-obfuscation.md) for
`secrets show`'s different disclosure model: `ShowItem` never sends a
secret-shaped field's real value over the wire at all, so there is
nothing for the CLI to redact on that command's behalf.

## Source of truth and bindings

`org.secrets.Manager`'s definition lives once, in Rust, at
`crates/secrets-core/src/dbus.rs` (`#[zbus::proxy]` generates both a
blocking and an async proxy from a single trait; `#[derive(zbus::DBusError)]`
generates the named `org.secrets.Error.*` mapping). `secretsd` implements
the same trait as a `#[zbus::interface]`, so server and client can never
drift apart on method or error names.

- **`secrets-client`** is the ergonomic Rust binding for this protocol —
  the recommended way for a Rust application to talk to `secretsd` (see
  [ADR-003](../adr/003-workspace-and-crate-boundaries.md)). It does not
  replace or redefine this protocol; it wraps the same generated proxy.
- **Non-Rust clients** (a GTK application in another language, a browser
  native messaging host, a third-party tool) consume this protocol
  directly with any D-Bus library, using the method and error tables in
  the pages above as the specification. Nothing here requires Rust.

No `.xml` introspection files exist in this repository today: the
`#[zbus::proxy]`/`#[zbus::interface]` declarations and these Markdown pages
are the specification. Generating standalone introspection XML from those
declarations is plausible future work (useful for non-Rust tooling that
expects it) but is not needed for any consumer this project has today, so
it is not done here.

## Compatibility and versioning

`org.secrets.Manager` grows **additively only**: new methods or properties
can be appended without breaking existing clients, since D-Bus dispatches
by name. An existing method's signature is never changed after the fact —
a genuinely incompatible change is a new method, not a modification of an
existing one (see each page's own "Compatibility" section for specifics).
The standard Secret Service interfaces follow the specification's own
shape instead, by definition, and are versioned by that specification, not
by this project.
