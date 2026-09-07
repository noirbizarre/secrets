# The Secrets protocol

D-Bus is not an implementation detail of `secretsd` — it is the
**inter-process protocol of the Secrets ecosystem**: the stable contract
every client, present or future, Rust or not, relies on to talk to
`secretsd`. This directory is that protocol's specification.

- [`secrets-manager.md`](secrets-manager.md) — `org.secrets.Manager`, the
  native Secrets-aware API (`Status`/`Unlock`/`Lock`/`ListVaults`/
  `ListItems`/`Resolve`/`Get`).
- [`secret-service.md`](secret-service.md) — the freedesktop
  [Secret Service](https://specifications.freedesktop.org/secret-service/)
  compatibility interfaces, for tools that predate this project
  (`secret-tool`, `libsecret`, GNOME Keyring clients).
- [`ssh-agent.md`](ssh-agent.md) — the standard SSH agent wire protocol
  over its own Unix socket, documented here for completeness even though
  it is deliberately **not** D-Bus (see [ADR-001](../adr/001-dbus-as-the-ipc-mechanism.md)
  for why that one exception exists).

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
The Secret Service compatibility interfaces follow the specification's own
shape instead, by definition, and are versioned by that specification, not
by this project.
