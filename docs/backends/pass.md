# `pass`/`gopass` backend

`secretsd` can read vaults, items and fields directly from a
[`pass`](https://www.passwordstore.org/)-compatible store directory —
including a [`gopass`](https://www.gopass.pw/)-initialized one, since
`gopass`'s default crypto backend writes the exact same on-disk format —
by decrypting `.gpg` files itself with a pure-Rust OpenPGP implementation
([rPGP](https://github.com/rpgp/rpgp)), not by shelling out to `gpg`/
`pass`/`gopass` and not through a running `gpg-agent`. See
[ADR-019](../adr/019-pass-backend.md) for why.

## Prerequisites

- An existing `pass` or `gopass` store directory (default
  `~/.password-store`) — `secretsd` never creates or initializes one.
- Your OpenPGP secret key, exported as an ascii-armored file:

```console
gpg --list-secret-keys --keyid-format long   # find your key id
gpg --export-secret-keys --armor <key-id> > ~/.config/secrets/pass-key.asc
chmod 600 ~/.config/secrets/pass-key.asc
```

`secretsd` never reads GnuPG's own keyring (`~/.gnupg/private-keys-v1.d`)
directly — that is `gpg-agent`'s own protocol-protected format, not an
OpenPGP secret-key packet an OpenPGP library can parse. This is a
one-time manual step, not a limitation you work around per-store.

## Configuration

Add a `[store.<id>]` table to `~/.config/secrets/secretsd.toml` (create
the file if it does not exist yet) — `<id>` becomes this store's name in
`secret://` references and `secrets --store` (see
[ADR-018](../adr/018-multi-store-support.md)):

```toml
[store.default]
type = "pass"
secret_key_path = "/home/you/.config/secrets/pass-key.asc"
# store_dir defaults to ~/.password-store; set it to point elsewhere,
# e.g. a gopass mount:
# store_dir = "/home/you/.local/share/gopass/stores/root"
# vault defaults to store_dir's own basename with a leading "." stripped
# (so ~/.password-store -> "password-store"); set it for a friendlier name:
# vault = "Personal"
```

`secret_key_path` is required — omitting it is rejected at startup with
an actionable error (`secrets::daemon::invalid_backend_config`), naming
the specific `[store.<id>]` it is missing from. Restart `secretsd` after
changing this file: the config is only read at startup.

**Multiple `gopass` mounts** are just additional stores of this same
type, each pointed at that mount's own directory — there is no dedicated
`gopass` backend or mount-aware configuration:

```toml
[store.default]
type = "pass"
secret_key_path = "/home/you/.config/secrets/pass-key.asc"

[store.work]
type = "pass"
secret_key_path = "/home/you/.config/secrets/pass-key.asc"
store_dir = "/home/you/.local/share/gopass/stores/work"
vault = "Work"
```

## What you get

Once configured, this backend behaves like any other through every
surface `secretsd` exposes — the standard
[Secret Service interfaces](../dbus/secret-service.md) (`secret-tool`,
`libsecret`-based apps), [`org.secrets.Manager`](../dbus/secrets-manager.md)
(what `secrets-cli` uses), and the [SSH agent](../dbus/ssh-agent.md) for
any field this backend reports as an `ssh-key`-kind field:

```console
secrets status
secrets unlock                       # prompts for your key's passphrase
secrets list <vault>
secrets get secret://<vault>/<item>/<field>
secrets resolve secret://<vault>/<item>/<field>
```

Unlike the local and 1Password backends, this one exposes **exactly one
vault per configured store** — `pass` has no native multi-vault concept
of its own; an item's name is its full path within the store (e.g.
`Personal/Email/gmail`), directories included.

`secrets unlock` verifies your key's passphrase once and caches it (never
the passphrase itself past the process's lifetime, never written to
disk) until `secrets lock` or the daemon restarts — one prompt per
unlock, not one per secret read.

### Field mapping

A `pass` entry has no structured fields of its own — just lines of text.
`secretsd` follows the same convention `browserpass`/`passff`/`pass-otp`
already use:

| Line | Field name | Kind |
| --- | --- | --- |
| First line (unless an `otpauth://` URI) | `password` | Password |
| First line, if an `otpauth://` URI (OTP-only entry) | `totp` | Totp |
| `login:`/`username:`/`user:` | `username` | Username |
| `totp:`/`otp:`, or a bare `otpauth://` line | `totp` | Totp |
| `url:`/`uri:`/`website:` | `url` | Custom |
| any other `key: value` line | the key, lowercased | Custom |

Lines that match none of these (blank lines, free-form notes) are
skipped, never reported as a field.

## Failure modes

| Situation | What happens | What to do |
| --- | --- | --- |
| `store_dir` does not exist, or `secret_key_path` cannot be parsed as an OpenPGP secret key | `secretsd` fails to start: `backend unavailable at startup: ...` / `could not read secret key at ...` | Fix the path, or export your key as shown above. |
| `secret_key_path` is missing from `secretsd.toml` | `secretsd` fails to start with an actionable `invalid backend configuration` error | Add `secret_key_path`, as shown above. |
| A wrong passphrase is given to `secrets unlock` | Rejected immediately (`org.secrets.Error.PermissionDenied`); the store stays locked | Retry with the correct passphrase. |
| The store is locked | `list`/`status` still work (item and vault *names* are visible without decrypting anything); `get`/`resolve` fail with `org.secrets.Error.VaultLocked`; `list` reports every item with only a single guessed `password` field, since field names beyond that require decrypting the entry | `secrets unlock`. |
| One specific `.gpg` file cannot be decrypted with the configured key (e.g. a `gopass` mount scoped to a different recipient than the one you configured) | That one item degrades the same way a locked item does (a guessed `password` field only); `get`/`resolve` on it fail with `org.secrets.Error.BackendUnavailable` — every other item in the store is unaffected | Configure that mount as its own `[store.<id>]` with the matching secret key, if you need to read it too. |

## Known limitations

- **No live `gpg-agent`/keyring integration.** You export your key once;
  `secretsd` never queries a running `gpg-agent`, so revoking or rotating
  a key in GnuPG has no effect here until you re-export and update
  `secret_key_path`.
- **No hardware-backed keys** (smartcards, YubiKeys) — out of scope for
  this backend; rPGP decrypts entirely in-process from the exported key
  file.
- **Field metadata is incomplete while locked, or for an item this
  store's key cannot decrypt** — see the table above. This is a direct
  consequence of `pass`'s file format carrying no metadata separate from
  its encrypted content, not a bug.
- **A nested `.gpg-id` override is read but never enforced** — this
  backend never writes, so a subdirectory's own recipient scoping (a
  real `pass`/`gopass` feature) has nothing to gate; only whether your
  configured key can actually decrypt a given file matters.
- **No write support.** Creating, editing or deleting entries through
  `secretsd` is out of scope for this backend, same as every other one
  today.
- **Every read re-derives key material from your passphrase, which can
  be noticeably slow against a real GnuPG key.** `secretsd` never
  caches a decrypted key (see [ADR-019](../adr/019-pass-backend.md)'s
  "Decision"/"Consequences"), only the passphrase — so `secrets get`
  can take several seconds per call against a key protected with
  GnuPG's own default (deliberately expensive) key-derivation
  parameters. This is a real, measured cost, not a hypothetical one.

## Validating your own setup end to end

```console
secrets status
secrets unlock
secrets list <vault>
secrets get secret://<vault>/<item>/password
```

Use a dedicated test entry you control if you want to confirm this
before pointing `secretsd` at your real store.

## Further reading

- [ADR-008: backend abstraction and roadmap](../adr/008-backend-abstraction-and-roadmap.md)
- [ADR-011: backend session and authentication state](../adr/011-backend-session-and-authentication-state.md)
- [ADR-012: 1Password Desktop backend](../adr/012-1password-desktop-backend.md)
  (the precedent this backend's "never shell out" decision follows)
- [ADR-018: multi-store support](../adr/018-multi-store-support.md)
- [ADR-019: the `pass`/`gopass` backend](../adr/019-pass-backend.md)
- [Security model](../security.md)
