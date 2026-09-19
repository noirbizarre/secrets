# ADR-018: Multi-store support

## Status

Accepted. Supersedes ADR-009's "daemon-wide, not per-vault" lock
granularity — locking becomes per-store, composed by `DaemonState` into
the same daemon-wide operations for backward compatibility — and
ADR-013's "the first vault" (singular) `"default"`-alias framing,
redefined to "the first `(store, vault)` pair" over a now-necessary
ordering; every other decision in both ADRs stands unchanged. Extends
ADR-002's URI grammar (an additive, optional qualifier) and ADR-008's/
ADR-011's single-backend-count assumption (lifting the "cannot run two
backends at once" limitation ADR-008's own Consequences named) without
reversing either's actual decisions.

## Context

ADR-008 shaped `secrets_core::Backend` deliberately small and explicitly
named its own limitation: "today, `secretsd` cannot run two backends at
once, or switch backends without a restart — acceptable for an MVP with
one backend, revisited when a second is built." ADR-011 then built the
seam that limitation's own text forecast (a second, optional
`BackendSession` trait) — but for exactly one backend, still describing
`DaemonState` as holding "the active backend" (singular) throughout.
ADR-009 fixed the lock state machine at exactly two daemon-wide values,
but pre-registered its own escape hatch: "per-vault locking, if ever
wanted, is a breaking change to this ADR... recorded as a future decision
to make explicitly (via a superseding ADR)."

The real trigger is not a new backend *kind* — `pass`/`gopass`/`passage`
remain out of scope, tracked separately — but wanting more than one
*instance* of a kind active at once: a personal local vault file and a
work local vault file; a local vault alongside a 1Password account; two
separate 1Password accounts. Every one of these needs its own lock/session
state, its own vault namespace, and its own place in the `secret://`
grammar and the Secret Service object tree — none of which the current
single-backend design has room for. In particular, two backend instances
each happening to expose a vault of the same name (a real scenario, not a
hypothetical: two personal/work `local` vault files might both have a
"Personal" vault, or a personal and work 1Password account might each
have one too) was structurally impossible to address unambiguously: vault
names live in one flat namespace throughout `secrets-core`, `secretsd`'s
config, and the Secret Service object-path scheme.

## Decision

### `StoreId`: a config-assigned instance identifier, distinct from a vault

`secrets_core::store_id::StoreId` names one configured backend instance —
a "store." A store is not a vault: one store can expose several named
vaults (confirmed by the existing code this ADR builds on — `LocalBackend`
already holds `vaults: BTreeMap<String, VaultData>` in one file, and
`OnePasswordBackend::list_vaults()` already maps a whole account's vault
list). The hierarchy is `store → vault → item → field`, four distinct
levels, not three.

Its charset is deliberately narrow — ASCII letters, digits, `-`, `_`,
never `@` — so a valid `StoreId` never needs percent-encoding anywhere it
appears: a `secret://` URI's `store@` segment (below), a `[store.<id>]`
TOML table key, or a Secret Service object path segment. One
guaranteed-safe representation replaces three encodings that would
otherwise need to be kept in sync by hand.

### URI grammar: an optional, userinfo-style `store@` qualifier

`secret://[<store>@]<vault>/<item...>/<field>` — extending, not replacing,
ADR-002's grammar. The qualifier mirrors real URI userinfo@host syntax
(`ssh://user@host`), detected as an unescaped `@` in the *first* `/`-
bounded segment, before percent-decoding — the same precedent ADR-002
already set for treating `/` specially before decoding. Omitting `store@`
parses **identically to every `secret://` reference written before this
ADR** — the entire backward-compatibility guarantee rests on this being
detection, not a new required field. A literal `@` in a vault name must be
percent-encoded (`%40`) to avoid being read as the separator — the same
escaping tradeoff ADR-002 already accepted for a literal `/`.

### Ambiguous unqualified vault names: an explicit error, never a guess

A vault name given without `store@` is resolved by `secretsd::state::
DaemonState`: with exactly one configured store, it always resolves
there, without even checking whether that store currently lists a vault
by that name — a single-store deployment has nothing to disambiguate,
and skipping that check is what preserves ADR-009's "report locked before
checking existence" behavior byte-for-byte for a never-yet-unlocked
store. With two or more configured stores, every one is asked; a name
found in exactly one still resolves silently (this is what keeps a
multi-store deployment working unqualified whenever names simply don't
collide); a name found in more than one fails with a new,
name-only `CoreError::AmbiguousVault { vault, candidates }`, naming every
matching store — store ids are configuration identifiers, not secrets, so
listing them is strictly more actionable than a bare "ambiguous" message.
A name found in none fails with the existing `CoreError::NotFound`.

### Config: `[backend]` is replaced by `[store.<id>]`

`secretsd.toml`'s single `[backend]` table (`BackendKind`, `type = "local"
| "1password"`) is **replaced**, not kept, by a `[store.<id>]` table per
configured instance, each shaped exactly like `[backend]` used to be. A
config file with no `[store.*]` table at all — including no file — still
yields exactly one implicit store, id `"default"`, type `local`: today's
zero-config behavior is unaffected in observable effect. A `[store.
default]` written explicitly, still `type = "local"`, behaves identically
(its vault file is the same fixed `vault.toml`, not `default.toml`) — so
making a zero-config setup's shape explicit is always a safe,
behavior-preserving edit. A leftover `[backend]` table is detected
specifically (not left to a generic `deny_unknown_fields` error) and
rejected with the exact `[store.<id>]` rewrite needed.

### `DaemonState` becomes a store registry

`secrets_core::Backend`, `Vault`, `Item` and `Resolver` are **entirely
unchanged** by this ADR — this is the single biggest simplification the
design makes possible. Store identity is a registry-level routing
concern: a `Backend` implementation is handed a file path or an account
name and nothing else, and never learns which `StoreId` it was registered
under. `secretsd::state::DaemonState` moves from one `Arc<dyn Backend>` +
one `Arc<dyn LockController>` + one `Option<Arc<dyn BackendSession>>` to a
`BTreeMap<StoreId, StoreEntry>`, each entry holding that same triple for
one store. Every read/lock/session operation is now either store-mandatory
(a `StoreId` argument, or one already carried by a `secret://` URI) or
store-optional with the ambiguity rule above.

Locking (ADR-009) becomes genuinely per-store: two local stores may have
different passphrases and independent lock states, since each is backed
by its own `LocalBackend` instance. `Manager.Unlock`/`Lock`/`Status`'s
existing zero-argument wire methods are kept — additive-only, per
ADR-005 — but redefined as `DaemonState`'s own explicit composition over
every configured store: `Status` reports `"unlocked"` iff every store
with a real passphrase lock is unlocked (vacuously true with none);
`Unlock` is a no-op with zero real locks, unlocks directly with exactly
one, and fails with a new `StoreSelectionRequired` naming every candidate
with more than one — it never guesses, since applying one passphrase to
an arbitrary store would be actively wrong the moment two stores'
passphrases differ; `Lock` locks every store unconditionally (locking
carries no per-store secret to misapply, so there is nothing to
disambiguate). New `UnlockStore`/`LockStore`/`StatusStore`/`ListStores`
methods target one store explicitly.

### Secret Service object paths nest by store

`/org/freedesktop/secrets/collection/<store_slug>/<vault_slug>` — real,
distinct path segments, not a concatenated single one
(`slug(store)+slug(vault)` cannot guarantee uniqueness: `"ab"`+`"c"` and
`"a"`+`"bc"` collide as strings; distinct path segments cannot). This
reshapes today's single-store path too, which ADR-013/ADR-015 already
document as dynamically discovered, never persisted, by well-behaved
clients — safe to change. `Item` objects gain a `"store"` search
attribute alongside `vault`/`item`/`field`. The `"default"` alias (ADR-013
item 2) now names the first `(store, vault)` pair by `(StoreId, vault
name)` lexicographic order — a documented, deterministic reinterpretation
of "the first vault," since a flat vault-name order alone no longer
determines a single answer once two stores exist.

### What this ADR does not decide

The `pass`/`gopass`/`passage` backends themselves (tracked separately).
Any UI/UX for choosing which store a new secret is written to (this
project remains read-only against every backend today). Cross-store
search or aggregation beyond simple name-collision detection. Whether a
future backend might itself expose multiple *accounts* as a single
configured store (today, one `[store.<id>]` entry is always exactly one
backend instance).

## Consequences

- **Breaking**: a `secretsd.toml` with a `[backend]` table stops parsing.
  `deny_unknown_fields` alone would report this as an opaque "unknown
  field," so it is detected specifically and rejected with the exact
  `[store.<id>]` rewrite needed instead — see README's Configuration
  section, updated in the same change.
- **Not breaking**: every `secret://<vault>/<item>/<field>` reference ever
  written keeps meaning exactly what it meant before, in a single-store
  deployment or in a multi-store deployment where the name happens to be
  unique. A pre-existing zero-config, single local-vault install observes
  no behavior change at all.
- `Manager.ListVaults`/`ListItems` results change shape (fully
  store-qualified `store@vault` strings) — a breaking change to
  `secretsd`'s own extension namespace, contained entirely to
  `secrets-client`/`secrets-cli` in this same change, per ADR-010's
  one-crate blast radius.
- `secrets_core::Backend`/`Vault`/`Item`/`Resolver` are untouched — no
  existing or future `Backend` implementation (including `pass`/`gopass`/
  `passage`, when built) ever needs to know about `StoreId` at all.
- A `CoreError` may now optionally carry a `StoreId` (`VaultLocked`,
  `NotFound`, `ItemNotFound`, `PermissionDenied`) or require one
  (`StoreNotFound`, `AmbiguousVault`, `StoreSelectionRequired`) — never a
  value, preserving invariant #1; the enforcing test suite is extended,
  not weakened.
- AGENTS.md invariant #3 ("locking is daemon-wide... one place") is
  reworded, not dropped: locking is still authoritative in exactly one
  place (`DaemonState`), but that place now composes N per-store lock
  states rather than owning one boolean.
- Unqualified `secrets unlock`/`Manager.Unlock` degrades gracefully to an
  explicit "use `--store`/`UnlockStore`" error the moment a second store
  with its own real lock exists, rather than silently applying one
  passphrase to every store (which would be actively wrong when their
  passphrases differ).
- This does not decide anything about a future backend exposing multiple
  accounts as one store, or about write support gaining a
  store-selection UI — both remain open, to be decided when a concrete
  need for either exists.
