# Secret Service compatibility

`secretsd` implements a read-only subset of the
[freedesktop Secret Service specification](https://specifications.freedesktop.org/secret-service/latest/)
so existing tools — `secret-tool`, GNOME Keyring/`libsecret`-based
applications — can list and read secrets without knowing Secrets exists.
This is a **compatibility API**: prefer
[`org.secrets.Manager`](secrets-manager.md) for anything Secrets-aware. See
[ADR-004](../adr/004-secret-service-compatibility-scope.md) for the full
design rationale.

## Interfaces implemented

| Interface                             | Object path(s)                                          |
| -------------------------------------- | -------------------------------------------------------- |
| `org.freedesktop.Secret.Service`       | `/org/freedesktop/secrets`                                |
| `org.freedesktop.Secret.Collection`    | `/org/freedesktop/secrets/collection/<vault-slug>`        |
| `org.freedesktop.Secret.Item`          | `/org/freedesktop/secrets/collection/<vault-slug>/<slug>` |
| `org.freedesktop.Secret.Session`       | `/org/freedesktop/secrets/session/shared` (one, shared)   |
| `org.freedesktop.Secret.Prompt`        | `/org/freedesktop/secrets/prompt/unsupported` (one, shared) |

`<vault-slug>`/`<slug>` are lossy, ASCII-safe encodings of the vault/item/
field names (see `secretsd::secret_service::slug`) — used only for object
path stability; a client should read `Label`/`Attributes`, not the path,
for the actual names.

Each `Item` object represents one **(vault, item, field) triple**, not a
whole `secrets-core` item — the Secret Service spec's "item" holds exactly
one secret value, while a `secrets-core` item can hold several fields
(`username`, `password`, `totp`, ...). An item with three fields therefore
appears as three `Item` objects, labelled `"<item> (<field>)"`.

## What works

- `Service.Collections`, `Collection.Items` — enumerate vaults and items.
- `Service.SearchItems`, `Collection.SearchItems` — match by `vault`,
  `item` or `field` attribute (see `Item.Attributes` below).
- `Item.GetSecret`, `Service.GetSecrets` — read a field's value, subject to
  lock state.
- `Item.Locked`, `Collection.Locked` — reflect the daemon-wide lock state
  live, on every property read.
- `Item.Attributes` — a synthetic `{"vault": ..., "item": ..., "field":
  ...}` map (there is no Secret-Service-native concept of a
  vault/item/field triple to draw richer attributes from).
- `Service.ReadAlias("default")` — resolves to the first known vault, if
  any.

## What does not work (by design, in this MVP)

- **Writing.** `CreateCollection`, `CreateItem`, `Item.SetSecret`,
  `Collection.Delete`, `Item.Delete`, `Service.SetAlias` all return
  `org.freedesktop.DBus.Error.NotSupported`. The local backend is
  read-only through this compatibility layer.
- **The encrypted session algorithm.** `OpenSession` only accepts
  `"plain"`; `"dh-ietf1024-sha256-aes128-cbc-pkcs7"` is rejected with
  `NotSupported`. See ADR-004 for why.
- **Interactive prompting.** The shared `Prompt` object immediately
  reports itself dismissed when `Prompt()` is called — there is no GUI
  agent yet (that is a future UI client's job, e.g. GD Secrets; see
  [`docs/architecture/external-clients.md`](../architecture/external-clients.md)).
  `Service.Unlock` therefore only reflects state `secrets unlock` already
  set; it cannot itself trigger a passphrase prompt.
- **Dynamic topology.** Collections and items are registered once, at
  `secretsd` startup, from whatever the backend reports at that moment.
  Creating the vault file for the first time (via `secrets unlock`) while
  `secretsd` is already running does not retroactively add its
  collections — restart the daemon. `org.secrets.Manager` has no such
  limitation.

## Errors

Unlike `org.secrets.Manager`, this layer does not define custom D-Bus
error names — clients written against the Secret Service specification
expect ordinary `org.freedesktop.DBus.Error.*` errors (`Failed`,
`NotSupported`), and that is what they get.
