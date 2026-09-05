# ADR-007: SSH agent implementation

## Status

Accepted

## Context

`secretsd` needs to act as a drop-in `ssh-agent`: `ssh`, `ssh-add -L`, and
anything else that reads `$SSH_AUTH_SOCK` must work unmodified. That means
implementing the SSH agent wire protocol (`draft-miller-ssh-agent`) exactly
— there is no "close enough" for a binary framing protocol — and signing
with whatever key algorithm a stored `SshKey` field happens to use
(Ed25519, RSA, ECDSA), without OpenSSH itself ever seeing the private key
bytes.

## Decision

Use `ssh-agent-lib` (the protocol/socket framework: request/response
framing, the `Session` trait, listening on a Unix socket) and `ssh-key`
(RustCrypto: parsing OpenSSH-formatted private keys, and signing via its
`signature::Signer<Signature>` implementation for `PrivateKey`). No
hand-rolled protocol parsing and no hand-rolled cryptography.

`ssh-agent-lib` requires an async runtime (`tokio`); the rest of
`secretsd` deliberately does not (see ADR-001 and ADR-005 on keeping the
D-Bus surface blocking). Rather than pulling `tokio` into the whole
daemon, the SSH agent runs on its own thread with its own single-threaded
runtime (`ssh_agent.rs::spawn`) — the one place this project accepts async
complexity, confined to exactly the component that requires it.

Identities are derived live from the backend on every `request_identities`
and `sign` call — enumerating every `SshKey`-kind field across every
vault, parsing each with `ssh_key::PrivateKey::from_openssh` — rather than
cached at unlock time. When the store is locked, this enumeration returns
nothing: `request_identities` reports zero identities and `sign` fails,
both from the same one check (`SecretsAgent::private_keys`), so the two
paths cannot disagree about whether the daemon is locked.

## Consequences

- Identities are unavailable exactly when the daemon is locked, with no
  separate flag to keep in sync — `private_keys()` is the single source of
  truth both agent operations read.
- `ssh-add -d` (remove identity) and `ssh-add -D` (remove all) both report
  success without doing anything: identities come from the backend, not an
  in-memory add-list, so there is nothing in-process to remove without
  deleting the underlying field, which this surface does not do. A
  well-behaved `ssh-add` does not treat this as an error.
- Signing does not yet honour the RSA `SSH_AGENT_RSA_SHA2_256`/`_512` flag
  negotiation in `SignRequest.flags` — `ssh_key`'s generic `Signer` trait
  produces its default signature scheme regardless. Documented as an MVP
  gap in `docs/security.md`; Ed25519 keys (the demo vault's default) are
  unaffected, since that scheme has no such negotiation.
