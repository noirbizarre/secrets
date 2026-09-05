# SSH agent

`secretsd` acts as a standard `ssh-agent`: the SSH agent wire protocol
(`draft-miller-ssh-agent`) over a Unix socket, so `ssh`, `ssh-add`, and
anything else that honours `$SSH_AUTH_SOCK` work unmodified. See
[ADR-007](../adr/007-ssh-agent-implementation.md) for the implementation
approach (`ssh-agent-lib` + `ssh-key`, no hand-rolled protocol or crypto).

This is **not** a D-Bus interface — the SSH agent protocol predates and is
independent of D-Bus, so `secretsd` speaks it exactly as OpenSSH expects,
over its own socket.

## Socket

```text
$XDG_RUNTIME_DIR/secrets/ssh-agent.sock
```

Under `XDG_RUNTIME_DIR` deliberately: that directory is tmpfs-backed,
private to the user, and cleared on logout — private key material's
signing capability should not outlive the login session, and nothing here
is ever written to persistent disk.

Point OpenSSH at it:

```bash
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/secrets/ssh-agent.sock"
ssh-add -L
```

## Identities

Every field of kind `SshKey`, across every vault, is offered as an
identity — parsed fresh from the backend on every request, not cached.
Concretely: `secret://Infrastructure/Production/ssh-key` (an OpenSSH
private key stored as that field's value) becomes one identity whose
comment is the key's own OpenSSH comment.

## Behaviour by lock state

| Operation                | Locked                          | Unlocked                        |
| ------------------------- | -------------------------------- | -------------------------------- |
| List identities (`ssh-add -L`) | Zero identities returned    | Every `SshKey` field's public key |
| Sign (`ssh`, `ssh-add -T`)      | Fails: no matching identity  | Succeeds for a known key         |
| Remove identity (`ssh-add -d`) | Succeeds, does nothing       | Succeeds, does nothing           |

"Remove" is a no-op regardless of lock state: identities come from the
backend, not an in-memory list `ssh-add -d` could meaningfully shrink —
removing a key means deleting the underlying `secret://` field, which this
surface does not do. A well-behaved `ssh-add` does not treat that as an
error.

## Signing

Signing happens entirely inside `secretsd`; the private key bytes never
cross the socket, only the resulting signature. Supports Ed25519, RSA and
ECDSA (whatever `ssh-key::PrivateKey::from_openssh` parses and its
`Signer` implementation supports).

**Known limitation:** RSA's `SSH_AGENT_RSA_SHA2_256`/`_512` flag
negotiation (`SignRequest.flags`) is not honoured yet — `ssh_key`'s generic
signing API always produces its default scheme. Ed25519 keys (the seeded
demo identity's algorithm) are unaffected, since that scheme has no such
negotiation. Tracked as a known gap, not a silent one — see
[`docs/security.md`](../security.md).
