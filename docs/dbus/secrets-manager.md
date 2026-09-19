# `org.secrets.Manager`

The `org.secrets.*` **extension namespace**, layered on top of the
[standard Secret Service interfaces](secret-service.md) — not a
replacement for them. It exists only for what that standard cannot
express: resolving or fetching a `secret://` reference directly, and a
single-passphrase unlock/status model. Prefer the standard interfaces for
anything they already cover (enumerating and reading secrets); reach for
this interface when a client needs to speak `secret://` references
directly. See [ADR-005](../adr/005-native-manager-api-design.md) for the
interface's own design rationale and
[ADR-013](../adr/013-standard-secret-service-and-extension-namespace.md)
for how it relates to the standard contract.

- **Bus name:** `org.secrets.Daemon`
- **Object path:** `/org/secrets/Manager`
- **Interface:** `org.secrets.Manager`

Defined once in `secrets_core::dbus` (via `#[zbus::proxy]`, generating both
`ManagerProxy` and `ManagerProxyBlocking`) and implemented by
`secretsd::manager::ManagerIface` — client and server share the exact same
declaration, so they cannot drift apart.

Every method below that names a store (`Status`/`Unlock`/`Lock`) is a
daemon-wide **composite** over every configured store (ADR-018) — a
client that only ever configures one store observes no behavior change
at all. The `*Store` methods target exactly one store explicitly.

## Methods

### `Status() -> String`

Returns `"locked"` or `"unlocked"`
(`secrets_core::dbus::{STATUS_LOCKED, STATUS_UNLOCKED}`) — `"unlocked"`
iff every configured store with a real passphrase lock reports unlocked
(vacuously true if none has one). Never fails. See `StatusStore` for one
store's own status.

### `Unlock(passphrase: String)`

Unlocks the store with a real passphrase lock. A no-op if none is
configured; unlocks it directly if exactly one is; fails with
`StoreSelectionRequired`, naming every candidate, if more than one is —
this never guesses which store `passphrase` belongs to. On the very first
call ever made against a fresh installation (no vault file exists yet for
that store), this call *creates* the vault, using `passphrase` as its new
master passphrase, seeded with a small demo vault — see
[`docs/security.md`](../security.md) for why and its limits.

Fails with `PermissionDenied` if a vault already exists and the passphrase
does not match it. See `UnlockStore` to target one store explicitly.

### `Lock()`

Locks every configured store, dropping any derived key from memory. Never
fails. See `LockStore` to target one store explicitly.

### `ListVaults() -> Vec<String>`

Every configured store's vault names, as `"<store>@<vault>"` strings
(ADR-018) — always store-qualified, even with a single configured store,
so this method's own output is always ready to paste into a `secret://`
reference or `ListItems`. Available regardless of lock state — vault
names are not secret material.

### `ListItems(vault: String) -> Vec<String>`

Item paths within `vault` (e.g. `"GitHub"`, `"Production/database"`),
formatted the same way they appear in a `secret://` URI's item segment.
`vault` accepts the same optional `"<store>@"` prefix as a `secret://`
URI's vault segment (see [`docs/secret-uri.md`](../secret-uri.md#store-qualification));
unqualified, it resolves via the same rule: a name found in exactly one
store still resolves silently, in more than one fails with
`AmbiguousVault`. Available regardless of lock state. Fails with
`NotFound` if `vault` does not exist in any configured store.

### `ListStores() -> Vec<String>`

Every configured store's id (ADR-018).

### `StatusStore(store: String) -> String`

One store's own `"locked"`/`"unlocked"` status — unlike `Status`, never a
composite. Fails with `StoreNotFound` if `store` is not configured, or
`InvalidUri` if it does not parse as a valid store id.

### `UnlockStore(store: String, passphrase: String)`

Unlocks exactly `store` with its own master passphrase. Same first-run
seeding and `PermissionDenied` behavior as `Unlock`, scoped to that one
store. Fails with `StoreNotFound`/`InvalidUri` as above.

### `LockStore(store: String)`

Locks exactly `store`. Fails with `StoreNotFound`/`InvalidUri` as above.

### `Resolve(uri: String) -> String`

Validates that `uri` (a `secret://` reference) names an existing vault,
item and field, and returns its canonical form — without returning the
field's *value*. Requires the store to be unlocked (confirming a field
exists is itself information about unlocked contents). Fails with
`InvalidUri` if `uri` does not parse, `VaultLocked` if the store is
locked, `BackendRequiresAuthentication` if the active backend has its own
unmet session requirement (see ADR-011), or `NotFound` if it does not
resolve.

Implemented internally by `DaemonState::validate_reference` — named
differently from `secrets_core::Resolver::resolve` (which *does* return a
value) on purpose, to keep "validate a reference exists" and "fetch a
value" from being confused in the code, even though this method's own
wire name (`Resolve`) does not change. Whatever a backend's own native
reference format is internally (a future 1Password backend's `op://...`
encoding, for instance) never appears in this method's output or in any
error it returns — only the `secret://` form the caller supplied.

### `Get(uri: String) -> String`

Fetches a field's value. The **only** method on this interface that
returns secret material — the plaintext crosses the bus here and nowhere
else. Same failure modes as `Resolve`, plus whatever the backend itself
reports (`BackendUnavailable`).

### `ShowItem(item_uri: String) -> Vec<FieldDisplay>`

Shows every field of one item: its name, kind, and either its real value
(kinds `Username`/`Certificate`, per `FieldKind::is_secret`) or the fixed
string `OBFUSCATED_FIELD_PLACEHOLDER` (`"••••••••"`, every other kind).
See [ADR-016](../adr/016-show-command-and-field-value-obfuscation.md).

`item_uri` is a `secret://<vault>/<item...>` reference with **no field
segment** — distinct from every other method here, which take a full
`secret://<vault>/<item>/<field>` reference. Requires the store to be
unlocked. Fails with `InvalidUri` if `item_uri` does not parse,
`VaultLocked` if the store is locked, `BackendRequiresAuthentication` if
the active backend has its own unmet session requirement, or
`ItemNotFound` if no item exists at that path.

A secret-shaped field's real value is never fetched from the backend at
all for this method — the obfuscation happens before a value is ever
requested, not as a display-time mask over one that was. `FieldDisplay`
is a struct of three strings (`name`, `kind`, `value`); `kind` is
`FieldKind`'s canonical string form (`"username"`, `"password"`,
`"totp"`, `"ssh-key"`, `"certificate"`, `"private-key"`, `"note"`, or
`"custom:<name>"`).

## Errors

`secrets_core::dbus::ManagerError` (`org.secrets.Error.*`), one variant per
failure kind, so a client matches on the specific error rather than
parsing a message string:

| D-Bus error name                        | Meaning                                  |
| ---------------------------------------- | ----------------------------------------- |
| `org.secrets.Error.InvalidUri`           | The `secret://` reference did not parse   |
| `org.secrets.Error.VaultLocked`          | The store is locked                       |
| `org.secrets.Error.NotFound`             | The vault, item or field does not exist   |
| `org.secrets.Error.ItemNotFound`         | The vault exists but no item at this path does (`ShowItem` only) |
| `org.secrets.Error.PermissionDenied`     | Not allowed (includes a wrong passphrase) |
| `org.secrets.Error.InvalidOperation`     | The operation does not make sense here    |
| `org.secrets.Error.BackendUnavailable`   | The backend could not be reached          |
| `org.secrets.Error.BackendRequiresAuthentication` | The backend has its own unmet session/auth requirement (see ADR-011) |
| `org.secrets.Error.AmbiguousVault`       | An unqualified vault name exists in more than one configured store (ADR-018) |
| `org.secrets.Error.StoreNotFound`        | A `store@` qualifier or `store` argument named a store that is not configured (ADR-018) |
| `org.secrets.Error.StoreSelectionRequired` | A daemon-wide `Unlock` has more than one candidate store and cannot guess which (ADR-018) |

None of these ever include a secret's value in their message — see
[`docs/security.md`](../security.md).

## Compatibility

Additions are additive: new methods or properties can be appended without
breaking existing clients, since D-Bus dispatches by name. An existing
method's signature is never changed after the fact; a genuinely
incompatible change would be a new method, not a modification of `Get` or
`Resolve`.
