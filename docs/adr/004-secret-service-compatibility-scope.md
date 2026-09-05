# ADR-004: Secret Service compatibility scope

## Status

Accepted

## Context

The freedesktop Secret Service specification defines, among other things,
a session-negotiation handshake (`Service.OpenSession`) that supports two
algorithms: `"plain"` (no encryption — the session bus itself is the only
protection) and `"dh-ietf1024-sha256-aes128-cbc-pkcs7"` (a Diffie-Hellman
key exchange followed by AES-encrypted secret transport). The latter
exists because D-Bus implementations historically included a TCP transport
where messages could be sniffed; it adds real cryptographic surface
(DH parameter validation, a second symmetric cipher, padding handling) for
a threat that does not apply to a local, kernel-authenticated Unix-socket
session bus.

The specification's `Prompt` interface exists so a service can ask a
*separate, trusted UI agent* to show a real interactive prompt (an unlock
dialog, a "may this application read this secret?" confirmation) without
the requesting client ever seeing the passphrase. This project has no such
UI agent yet — that is `secrets-gtk`'s eventual job (see
`docs/architecture/clients.md`).

## Decision

Implement `Service`, `Collection`, `Item` and `Session` for the `"plain"`
algorithm only; `Service.OpenSession` returns
`org.freedesktop.DBus.Error.NotSupported` for any other algorithm.
Implement the `Prompt` interface's shape (so the specification's
discoverable pattern still works for a well-behaved client), but back it
with a single shared, always-immediately-dismissed instance — see
`crates/secretsd/src/secret_service/prompt.rs`. `CreateCollection`,
`CreateItem`, `SetSecret` and `Delete` all return `NotSupported`: the local
backend's vault set is read-only through this compatibility layer for the
MVP (see ADR-008 for the backend contract itself).

The compatibility layer's object topology (which `Collection`/`Item`
objects exist) is fixed at `secretsd` startup, computed once from whatever
the backend reports then — not recomputed per call. This is the layer's
most significant MVP limitation: creating the vault file for the first
time (via `secrets unlock`) while `secretsd` is already running does not
retroactively register its collections; the daemon must be restarted. The
native `org.secrets.Manager` API (ADR-005) has no such limitation, since it
reads live state on every call — this compatibility layer is secondary by
design (see ADR-001).

## Consequences

- `secret-tool`, `libsecret`-based applications and similar can list and
  read secrets against `secretsd` today, but cannot create, modify, or
  delete them, and cannot negotiate the encrypted session algorithm.
- No GUI-agent-dependent interactive unlock exists through this layer;
  `Service.Unlock` only reflects the state `secrets unlock` already set.
- Encrypted-session support and dynamic collection/item registration are
  both explicitly deferred, not accidentally missing — tracked in
  `PLAN.md` §2 and §3 rather than silently absent.
