# 1Password Desktop backend

`secretsd` can read vaults, items and fields directly from a running
**1Password Desktop** application, over its native IPC library — not the
`op` CLI, and not 1Password's cloud API (see
[ADR-012](../adr/012-1password-desktop-backend.md) for why). This page is
the operator-facing setup guide; for the wire protocol and reverse-
engineering notes, see
[1Password Desktop integration](../architecture/1password-integration.md).

## Prerequisites

- **1Password Desktop installed, running, and signed in** to the account
  whose vaults you want `secretsd` to read.
- **Settings → Developer → "Integrate with other apps"** (also shown as
  "Integrate with 1Password CLI/SDKs" depending on version) enabled in the
  Desktop app. Without this, the IPC channel `secretsd` needs stays
  closed, and every call to it fails or times out.
- Your **account name or UUID**, exactly as shown in the Desktop app's
  sidebar — this backend needs it to open a client session.
- Linux is the only platform confirmed today (this backend has been
  validated against 1Password Desktop 8.11.x on Arch Linux). macOS is not
  yet tested; there is no known reason it wouldn't work, but treat it as
  unverified until someone confirms it.

## Configuration

Add a `[backend]` table to `~/.config/secrets/secretsd.toml` (create the
file if it does not exist yet):

```toml
[backend]
type = "1password"
account_name = "my-account"
```

`account_name` is required — omitting it is rejected at startup with an
actionable error (`secrets::daemon::invalid_backend_config`), not a raw
TOML parse failure. Restart `secretsd` after changing this file: the
config is only read at startup.

## What you get

Once configured, this backend behaves like any other through every
surface `secretsd` exposes — the standard
[Secret Service interfaces](../dbus/secret-service.md) (`secret-tool`,
`libsecret`-based apps), [`org.secrets.Manager`](../dbus/secrets-manager.md)
(what `secrets-cli` uses), and the [SSH agent](../dbus/ssh-agent.md) for any
field 1Password reports as an SSH key. All three commands the acceptance
criteria for this backend care about work unmodified:

```console
secrets status
secrets list <vault>
secrets get secret://<vault>/<item>/<field>
secrets resolve secret://<vault>/<item>/<field>
```

This backend is **read-only** and has no daemon-wide passphrase lock of
its own (`secrets unlock`/`secrets lock` are no-ops for it) — 1Password
Desktop's own approval/session flow is the real gate, described next.

## Failure modes

| Situation | What happens | What to do |
| --- | --- | --- |
| 1Password Desktop is not installed, or its native IPC library cannot be found/loaded | `secretsd` fails to start: `backend unavailable at startup: ...` | Install/reinstall 1Password Desktop; confirm the library ships at its usual location on your platform. |
| "Integrate with other apps" is disabled, or the approval prompt is denied or left unanswered (~30s timeout) during `secretsd` startup | `secretsd` fails to start the same way (`backend unavailable at startup: ...`) — startup discovery is the first call this backend makes | Enable the setting, or approve the prompt in the Desktop app, then restart `secretsd`. |
| `account_name` is missing from `secretsd.toml` | `secretsd` fails to start with an actionable `invalid backend configuration` error | Add `account_name`, as shown above. |
| The 1Password session expires or is revoked *after* `secretsd` is already running | Subsequent `secrets get`/`resolve` fail with a "needs authentication" error (`org.secrets.Error.BackendRequiresAuthentication`); Secret Service clients (`secret-tool`, libsecret apps) and the SSH agent see the same field/item as **locked**, not just `org.secrets.Manager` | Reauthorize in the Desktop app, then retry. There is no `secrets unlock` equivalent for this backend, and no interactive prompt over D-Bus yet (see [ADR-004](../adr/004-secret-service-compatibility-scope.md)) — the daemon itself does not need restarting once the session is valid again. |
| A vault or item is created in 1Password *after* `secretsd` started | Not visible over Secret Service until restart; `org.secrets.Manager` (`secrets list`/`get`/`resolve`) sees it immediately | Restart `secretsd` if you need the new vault/item visible over Secret Service too — see [`docs/dbus/secret-service.md`](../dbus/secret-service.md)'s "Dynamic topology" note. |

## Known limitations

- **`CONFIRMED_SDK_VERSION`** (in `protocol.rs`) is a specific build
  string discovered by reverse-engineering, not a documented API contract
  — if 1Password changes what it accepts, this backend may need updating.
  See ADR-012's consequences section.
- **`list_items`** briefly holds decrypted field values in an
  un-zeroized buffer before the rest of the pipeline zeroizes its own
  copies — see [`docs/security.md`](../security.md)'s "Known MVP
  limitations".
- **SSH key field format.** `secretsd`'s SSH agent expects `SshKey`-typed
  fields to resolve as OpenSSH-formatted private key text. This has been
  exercised against a real 1Password SSH item by the opt-in smoke test
  below (if you ran it with `SECRETS_OP_TEST_SSH_ITEM`/
  `SECRETS_OP_TEST_SSH_FIELD` set) — if it doesn't hold for your item, the
  SSH agent logs a warning (never the value) and skips that identity
  rather than failing silently.
- **No write support.** Creating, editing or deleting vaults/items through
  `secretsd` is out of scope for this backend, same as every other one
  today.

## Validating your own setup end to end

An opt-in, `#[ignore]`d test drives the real `secrets` CLI against a real
`secretsd` configured for this backend — the same commands listed above.
**Use a dedicated development vault/item you control, never a real
personal or work vault or item** (see `AGENTS.md`'s testing invariants):

```console
$ SECRETS_OP_ACCOUNT_NAME="my-account" \
  SECRETS_OP_TEST_VAULT="Development" \
  SECRETS_OP_TEST_ITEM="secrets-smoke-test" \
  SECRETS_OP_TEST_FIELD="password" \
  cargo test -p secrets-cli --test onepassword_smoke -- --ignored --nocapture
```

Optionally, also set `SECRETS_OP_TEST_SSH_ITEM`/`SECRETS_OP_TEST_SSH_FIELD`
to additionally confirm the SSH-key format assumption above against a real
SSH item. The first call may take up to a minute if 1Password Desktop
needs you to approve its integration prompt.

## Further reading

- [ADR-008: backend abstraction and roadmap](../adr/008-backend-abstraction-and-roadmap.md)
- [ADR-011: backend session and authentication state](../adr/011-backend-session-and-authentication-state.md)
- [ADR-012: 1Password Desktop backend](../adr/012-1password-desktop-backend.md)
- [ADR-013: standard Secret Service and extension namespace](../adr/013-standard-secret-service-and-extension-namespace.md)
- [1Password Desktop integration (wire protocol, reverse-engineering notes)](../architecture/1password-integration.md)
- [1Password Desktop POC results](../architecture/1password-poc-results.md)
- [Security model](../security.md)
