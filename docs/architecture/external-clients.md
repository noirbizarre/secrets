# External clients: GD Secrets, `secrets-tui`, and browser extensions

None of these are implemented yet, and **none of them live in this
repository**. `secrets` (this repository) is the service, protocol,
daemon, CLI and library ecosystem; a GTK application, a TUI, and browser
integrations are clients of it, each its own separate project. This
document exists so the boundary they sit behind is decided now, rather
than guessed at when they are built.

## The boundary

Every client — present or future, in this repository or not — talks to
`secretsd` the same way `secrets-cli` does: over D-Bus, through
`org.secrets.Manager` (see [ADR-005](../adr/005-native-manager-api-design.md)
and [ADR-010](../adr/010-cli-as-thin-dbus-client.md)). A Rust client would
normally do so through [`secrets-client`](../dbus/README.md) rather than
`zbus` directly; a client written in another language speaks the D-Bus
protocol itself, using the same specification. Either way, a client:

- **owns no vault or session state.** It does not cache a decrypted
  secret past the operation that needed it, does not track lock state
  independently of what `Status` reports, and does not read the vault
  file (there may not even be one, depending on the active backend).
- **is a presentation layer over the daemon**, not a second
  implementation of resolution or locking. If a client needs behaviour
  `org.secrets.Manager` does not yet expose, the fix is a new method on
  that interface (additive — see ADR-005), not a client-side workaround.

This is the same rule `secrets-cli` already follows; a GUI, TUI or browser
client is not a special case of it.

## GD Secrets

A GTK application (separate repository), intended to provide:

- a real interactive unlock prompt, filling the gap the Secret Service
  compatibility layer's `Prompt` interface currently cannot (see
  [ADR-004](../adr/004-secret-service-compatibility-scope.md) — the MVP's
  shared `Prompt` object always reports itself dismissed immediately,
  because no UI agent exists yet)
- browsing vaults/items and reading fields, through `org.secrets.Manager`
  (via `secrets-client`)
- acting as the D-Bus-side counterpart for a browser extension's native
  messaging host, if that ends up being a separate process from the
  browser extension itself

It is a pure client of `secretsd`: no vault state, no independent lock
state, no direct backend access, and no code in this repository.

## `secrets-tui`

A terminal-UI client (separate repository), for the same reasons a GTK
application exists but without a graphical environment: browsing
vaults/items and reading fields through `secrets-client`/D-Bus, subject to
the exact same boundary as every other client. Not designed in detail
here — this document exists to fix the boundary, not the UI.

## Browser extensions (`secrets-firefox`, `secrets-chrome`)

A browser extension plus a
[native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
host process, one pair of separate repositories per browser family. The
extension itself cannot speak D-Bus directly (browser extension sandboxes
do not allow it), so the native messaging host is the piece that actually
holds the connection to `secretsd` (through `secrets-client`) and relays
requests from the browser extension over the native messaging protocol
(length-prefixed JSON over stdio). Whether that host is its own small
binary or reuses GD Secrets' process is an open question, deferred until
there is a concrete reason to choose one over the other. The exact
implementation is future work and is not designed further here.

## What will not change when these are built

- `secretsd`'s D-Bus interfaces grow additively; they do not get
  restructured to suit a GUI's needs at the expense of the CLI's.
- The backend abstraction (`secrets-core::Backend`) is not visible to
  clients at all — a GTK window never knows or cares whether the active
  backend is the local file, Vaultwarden, or `pass`.
- `secrets-client` remains the recommended Rust integration point; adding
  a new client never means adding a workspace member to this repository.
- Locking stays daemon-wide (see
  [ADR-009](../adr/009-session-and-lock-state-machine.md)) unless a future
  ADR explicitly supersedes that decision — a GUI unlock prompt changes
  *who* triggers `Unlock`, not the state machine `Unlock` operates on.
</content>
