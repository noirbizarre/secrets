# External clients: GD Secrets, `secrets-tui`, browser extensions, and prompt providers

None of these are implemented yet, and **none of them live in this
repository**. `secrets` (this repository) is the service, protocol,
daemon, CLI and library ecosystem; a GTK application, a TUI, and browser
integrations are clients of it, each its own separate project. This
document exists so the boundary they sit behind is decided now, rather
than guessed at when they are built.

## The boundary

Every client — present or future, in this repository or not — talks to
`secretsd` the same way `secrets-cli` does: over D-Bus, through the
standard Secret Service interfaces for anything they already express
(enumerating and reading secrets), and `org.secrets.Manager` for
`secret://`-shaped operations they cannot (see
[ADR-005](../adr/005-native-manager-api-design.md),
[ADR-010](../adr/010-cli-as-thin-dbus-client.md) and
[ADR-013](../adr/013-standard-secret-service-and-extension-namespace.md)).
A Rust client would normally do so through
[`secrets-client`](../dbus/README.md) rather than `zbus` directly; a
client written in another language speaks the D-Bus protocol itself,
using the same specification. Either way, a client:

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

- browsing vaults/items and reading fields, through the standard
  interfaces and `org.secrets.Manager` (via `secrets-client`)
- acting as the D-Bus-side counterpart for a browser extension's native
  messaging host, if that ends up being a separate process from the
  browser extension itself
- optionally, also registering as a prompt provider (see "Prompt
  providers" below) — the same GTK process could plausibly do both,
  though nothing requires it to.

It is a pure client of `secretsd`: no vault state, no independent lock
state, no direct backend access, and no code in this repository.

## Prompt providers

A different kind of external peer from every client above: instead of
*requesting* secrets, a prompt provider *answers* `secretsd`'s own
interactive prompts (an unlock passphrase, a confirmation, a choice, a
security-key approval) — see
[ADR-017](../adr/017-prompt-broker-and-provider-protocol.md) and
[`docs/dbus/prompt-broker.md`](../dbus/prompt-broker.md) for the full
protocol. This is the mechanism that fills the gap the standard Secret
Service `Prompt` object could not on its own (see
[ADR-004](../adr/004-secret-service-compatibility-scope.md) — with no
provider registered, that object still always reports itself dismissed
immediately, exactly as in the original MVP).

The first external provider will be a separate GTK project (for example
`secrets-prompt-gtk`), suitable for lightweight Wayland compositors
(Hyprland, and similar) that do not run GNOME Keyring. Future providers
may target Qt/KDE, GNOME Shell integration, or a TUI. Like every other
client, none of this lives in this repository, and multiple providers may
coexist — `secretsd` selects one per request by declared capability and
priority (see `docs/dbus/prompt-broker.md`).

A prompt provider is not bound by the "owns no vault or session state"
rule above in quite the same way as a reading client: it necessarily
handles a passphrase in-process, on its way from the user to `secretsd`.
It must never persist it, log it, or use it for anything but the one
`Respond` call the prompt broker protocol expects.

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
