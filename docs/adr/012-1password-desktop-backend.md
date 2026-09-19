# ADR-012: 1Password Desktop backend

## Status

Accepted. The "exactly one backend active per daemon instance, no
routing" constraint this ADR cites from ADR-008 is lifted by
[ADR-018](018-multi-store-support.md): a 1Password store can now be
configured alongside other stores (another 1Password account, or a local
vault). Everything else here — the IPC transport choice, field-kind
heuristic, session/lock design — is unchanged.

## Context

PLAN.md §7 tracked 1Password as a future `Backend` candidate since
ADR-008. The obvious integration path — shelling out to the `op` CLI —
was ruled out from the start: it would mean a second, informal IPC
mechanism (a subprocess and its stdout) alongside D-Bus (ADR-001),
duplicate session/lock bookkeeping `op` already does its own way, and
tie this project to a specific CLI's argument shape rather than to
1Password's own supported integration surface.

1Password Desktop exposes a native, local IPC channel specifically for
this kind of integration (`libop_sdk_ipc_client.so`, dynamically
loaded, never bundled) — the same one 1Password's own official SDKs
use for "Desktop app integration." The protocol behind it is
undocumented publicly; investigating and validating it against a real
account was itself a multi-step effort — see
`docs/architecture/1password-integration.md` (the investigation) and
`docs/architecture/1password-poc-results.md` (the validation, including
a real root-cause correction found via an independent cross-check
against 1Password's own official Go SDK).

## Decision

`crates/secretsd/src/backend/onepassword/` implements `Backend` +
`BackendSession` over that native channel:

- `list_vaults`/`list_items`/`get_field` map to 1Password's own
  `VaultsList`/`ItemsList`+`ItemsGetAll`/`SecretsResolve` operations.
  `get_field` builds `op://{vault}/{item}/{field}` directly from the
  `secret://` reference's own parts — 1Password's `op://` addressing
  accepts human-readable vault/item names directly, so no separate
  ID-lookup round trip is needed for this path (unlike
  `list_items`, which does need one — `ItemsList`/`ItemsGetAll` require
  a vault *ID*, not its name).
- The `op://...` representation is constructed and consumed entirely
  inside this module; it never appears on the public `secret://`/D-Bus
  surface, matching every other backend.
- TOTP generation and SSH-specific signing logic are **not**
  implemented here, on purpose: those stay Secrets-level semantics
  (`secretsd::ssh_agent` already consumes `FieldKind::SshKey` metadata
  from any backend generically) — this backend only reports the field
  *kind*, the same way `LocalBackend` does.
- Field kind (`Username`/`Password`/`Totp`/`SshKey`/`Custom`) is a
  documented heuristic over 1Password's own `(fieldType, title)` pair,
  not a clean 1:1 mapping — 1Password's `ItemFieldType` does not itself
  distinguish "username" from generic text, or "password" from a
  generic concealed value. An unrecognized combination becomes
  `FieldKind::Custom`, never a failure.
- Authentication is 1Password Desktop's own responsibility end to end:
  `secretsd` never stores a master password, session token, or
  equivalent credential. `SessionManager` (see ADR-011) tracks only
  *that* a session exists and *when* it was last established, single-
  flight, bounded by a timeout on every path.
- Selected via `[backend] type = "1password"` in `secretsd.toml`
  (`account_name` required) — exactly one backend active per daemon
  instance, no routing (ADR-008's own constraint, unchanged).
- 1Password Desktop has no daemon-wide passphrase lock of its own to
  plug into ADR-009's lock state machine — `AlwaysUnlocked` (a trivial
  `LockController`) is used instead, deferring all real gating to
  `BackendSession` (ADR-011). This is correct, not a bypass: the daemon
  lock and a backend's session answer different questions, and
  `DaemonState` already checks both independently.

## Consequences

- **A specific, confirmed-working value (`CONFIRMED_SDK_VERSION` in
  `protocol.rs`) is load-bearing and compatibility-fragile.** It was
  found only by capturing what one specific official Go SDK release
  actually sends on the wire — 1Password Desktop's server-side session
  validation rejects any value it does not recognize, with an opaque
  error naming no specific field. If this integration ever starts
  failing with the same "delegated session" shape again, this is the
  first thing to re-verify, the same way it was found (see
  `docs/architecture/1password-integration.md`'s "Compatibility risk").
- **`list_items` briefly holds 1Password's own decrypted field values
  in memory**, even though it only reports metadata — 1Password's
  `ItemsGetAll` API has no metadata-only mode. Mitigated (never copied
  into anything this backend holds onto; the raw response buffer is
  zeroized immediately after parsing) but not eliminated (the
  `ipc::Response` type this buffer passes through is not itself
  `Zeroize`/`ZeroizeOnDrop`) — documented as a known limitation in
  `docs/security.md`, the same way other MVP limitations already are.
- **SSH key field values' exact format is not confirmed against a real
  1Password SSH item** — the POC's test item was a password field. A
  1Password-backed `secretsd::ssh_agent` identity is architecturally
  supported (the same `FieldKind::SshKey`-driven code path `LocalBackend`
  already uses) but not validated end-to-end.
- **No live, full end-to-end success through the real daemon (as
  opposed to the standalone probe or fixture tests) was obtained this
  session** — a real 1Password Desktop authorization-state issue at the
  time (see `docs/architecture/1password-poc-results.md`), not a defect
  in this backend's own logic, which is otherwise confirmed two ways:
  the standalone probe (Step 8/9, a different integration name) and
  `OnePasswordBackend`'s own fixture-driven test suite (13 tests
  covering vault/item/field listing, mapping, and every confirmed error
  shape).
- Two 1Password-specific error strings this backend matches against
  (`"no vault matched"`/`"no item matched"`/`"cannot be found within the
  item"`) are 1Password's own, undocumented, human-readable text, not a
  structured error code — a future 1Password Desktop release could
  reword them without notice, silently turning a `NotFound` into a
  generic `BackendUnavailable`. Acceptable degradation (still an error,
  just a less specific one), not a silent failure.
- **`ItemsGetAll` rejects more than 50 item IDs per call** — another
  undocumented, empirically-discovered constraint (found against a real
  account whose vault exceeded it; see
  `docs/architecture/1password-integration.md`'s own subsection on this).
  `list_items` chunks around it transparently, so this is invisible to
  every caller of this backend, but it is the same class of risk as
  `CONFIRMED_SDK_VERSION` above: an unversioned behavior this backend
  depends on staying stable.
</content>
