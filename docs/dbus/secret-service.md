# Secret Service (the standard contract)

`secretsd` implements a read-only subset of the
[freedesktop Secret Service specification](https://specifications.freedesktop.org/secret-service/latest/)
— the **standard, primary contract**: `secret-tool`, GNOME Keyring/
`libsecret`-based applications and any other conforming client can list
and read secrets against `secretsd` without knowing Secrets exists, or
containing a single line of Secrets-specific code.
[`org.secrets.Manager`](secrets-manager.md) exists alongside it, purely as
an extension namespace for `secret://`-shaped operations this standard has
no way to express. See
[ADR-004](../adr/004-secret-service-compatibility-scope.md) and
[ADR-013](../adr/013-standard-secret-service-and-extension-namespace.md)
for the full design rationale.

## Bus name

`secretsd` always owns `org.secrets.Daemon`
(`secrets_core::dbus::SERVICE_NAME`) — that name is exclusively its own.
It additionally requests the well-known name every standard Secret
Service client hardcodes, `org.freedesktop.secrets`
(`secretsd::secret_service::BUS_NAME`), **best-effort**: a desktop session
may already run GNOME Keyring or KWallet's `ksecretsd` owning that name,
in which case `secretsd` logs a warning and keeps running under
`org.secrets.Daemon` only — it never fails to start, and never takes the
name away from an already-running provider. If a standard client isn't
reaching `secretsd`, check `secretsd`'s log for that warning; either stop
the other provider, or point the client at `org.secrets.Daemon` as the
D-Bus destination explicitly. See
[ADR-013](../adr/013-standard-secret-service-and-extension-namespace.md).

## Interfaces implemented

| Interface                             | Object path(s)                                          |
| -------------------------------------- | -------------------------------------------------------- |
| `org.freedesktop.Secret.Service`       | `/org/freedesktop/secrets`                                |
| `org.freedesktop.Secret.Collection`    | `/org/freedesktop/secrets/collection/<vault-slug>`        |
| `org.freedesktop.Secret.Item`          | `/org/freedesktop/secrets/collection/<vault-slug>/<slug>` |
| `org.freedesktop.Secret.Session`       | `/org/freedesktop/secrets/session/shared` (one, shared)   |
| `org.freedesktop.Secret.Prompt`        | `/org/freedesktop/secrets/prompt/unsupported` (one, shared) |
| `org.freedesktop.Secret.Collection`    | `/org/freedesktop/secrets/aliases/default` (the `"default"` alias's collection, also reachable at its real path above) |

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
  any; the same collection is also reachable directly at the literal
  `/org/freedesktop/secrets/aliases/default` object path (see the
  interfaces table above).

## What does not work (by design, in this MVP)

- **Writing.** `CreateCollection`, `CreateItem`, `Item.SetSecret`,
  `Collection.Delete`, `Item.Delete`, `Service.SetAlias` all return
  `org.freedesktop.DBus.Error.NotSupported`. The local backend is
  read-only through this layer for now — tracked as follow-up work by
  [#8](https://github.com/noirbizarre/secrets/issues/8) and `PLAN.md`,
  not silently missing.
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
