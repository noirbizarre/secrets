# ADR-001: D-Bus as the IPC mechanism

## Status

Accepted

## Context

`secretsd` needs to talk to clients that do not share its process:
`secrets-cli` today, and — via `secrets-client` or the D-Bus protocol
directly — separately maintained clients such as GD Secrets, `secrets-tui`
and browser extensions eventually, possibly third-party tools later.
Something has to carry method calls and errors between them.

Options considered:

- **A proprietary Unix-socket protocol.** Full control over the wire
  format, but every client (including third parties who want to integrate
  with Secrets) has to implement it from scratch, and it buys nothing that
  an existing IPC mechanism does not already provide on Linux.
- **D-Bus**, the session bus every desktop Linux environment already runs.
  Every mainstream language has bindings; `zbus` gives Rust a pure-Rust
  implementation (no `libdbus` needed); and the desktop's *existing*
  secret-management convention — the freedesktop Secret Service
  specification — is itself a D-Bus interface, so compatibility with
  `libsecret`/`secret-tool`/GNOME Keyring clients falls out of the same
  choice for free.

## Decision

Use the D-Bus session bus as the sole IPC mechanism. `secretsd` exposes two
D-Bus surfaces: the native `org.secrets.Manager` interface (see ADR-005)
and the `org.freedesktop.Secret.*` compatibility interfaces (see ADR-004).
No custom socket protocol is introduced for talking to `secretsd` itself —
the SSH agent socket (ADR-007) is a separate, deliberate exception, because
`ssh-add`/`ssh` speak a *standard* protocol that is not D-Bus and cannot be
made to.

`secret://` remains the resource-reference scheme (ADR-002); D-Bus is only
the transport. The two must never be confused with each other in
documentation or code.

## Consequences

- Every client needs a D-Bus library, not a bespoke one — cheaper for the
  ecosystem this project hopes to grow (GD Secrets, `secrets-tui`, browser
  extensions, third-party tools).
- `secretsd` is unreachable from outside the user's own login session,
  which is exactly the trust boundary a secret broker wants — D-Bus session
  bus peers are authenticated by the kernel via the connecting process's
  UID.
- The daemon's core logic must not assume synchronous, in-process calls:
  every operation is now a message round-trip that can fail independently
  of the caller's own state.
