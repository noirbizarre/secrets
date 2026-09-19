# ADR-016: `secrets show` and field-value obfuscation by kind

## Status

Accepted

## Context

`secrets list <vault>` returns an item's path; `secrets get <uri>` reads
one named field's value. Neither answers "what fields does this item
even have?" — the only way to find out was already knowing a field's
name (from a UI the daemon does not provide, or a backend's own app),
then guessing at `get`'s field segment until one resolved. Every
`Backend::list_items` implementation already computes exactly this
metadata per item — `Item { path, fields: Vec<FieldMeta { name, kind }>
}` — but `Manager.ListItems` collapses it to a bare path string
(`secretsd::manager::ManagerIface::list_items`), discarding the field
list before it ever crosses the bus.

`FieldKind`'s own doc comments (`secrets_core::model`) already draw a
line between kinds: `Username` is "not itself secret, but part of the
pair with a password"; `Certificate` is "frequently not secret at all,"
often stored next to its private key only for convenience. Nothing
before this ADR acted on that distinction — every value, from every
kind, required the same full `get`.

This is a different problem from the one ADR-014 solved. ADR-014 is
entirely about *whether* `secrets get` may print the one value it always
fetches; it has no concept of fetching some fields' values and not
others based on their kind. Folding partial, kind-based disclosure into
that ADR would conflate two different questions, so it gets its own
record instead.

## Decision

1. **New D-Bus method, `Manager.ShowItem(item_uri: String) ->
   Vec<FieldDisplay>`** (`secrets_core::dbus`), additive per ADR-005/
   ADR-013's compatibility rule. `item_uri` is a `secret://<vault>/<item...>`
   reference with **no field segment** — the existing `SecretUri` parser
   requires one and must not change (ADR-002), so this is a new type,
   `ItemUri`, parsed by a helper (`decode_segments`) shared with
   `SecretUri::parse` so the two can never decode the same string two
   different ways.
2. **`FieldKind::is_secret(&self) -> bool`** (`secrets_core::model`) is
   the one classification this feature introduces: `false` for
   `Username` and `Certificate` (matching their existing doc comments
   verbatim), `true` for everything else — including `Note` and
   `Custom`, whose actual content this type cannot predict. Fail closed:
   an unknown shape is obfuscated, never assumed safe.
3. **Obfuscation happens server-side, before a value is ever fetched —
   not as a display-time mask over one that was.**
   `DaemonState::show_item` checks each field's kind *first*; for a
   secret-shaped field it never calls `Backend::get_field` at all,
   substituting the fixed constant `OBFUSCATED_FIELD_PLACEHOLDER`
   (`"••••••••"`, `secrets_core::dbus`) instead. The placeholder is
   never derived from the real value in any way — constant content and
   length — so a client (even a buggy or malicious one downstream of the
   daemon) cannot learn anything about the value from it, not even how
   long it is. This is deliberately stronger than "the CLI decides not
   to print it": there is structurally nothing secret in the wire
   payload for those fields to begin with.
4. **`FieldDisplay { name, kind, value }`** (`secrets_core::dbus`) is the
   wire type — a struct, not a bare tuple, matching `Item`/`FieldMeta`'s
   own precedent of named fields on both ends. `kind` is `FieldKind`'s
   canonical string form (its new `Display` impl — the same scheme
   `secretsd::backend::local`'s TOML (de)serialization already used
   privately, now shared via one `Display`/`FromStr` implementation
   instead of two independently-maintained string tables).
5. **Requires the store to be unlocked**, same as `get`. Checked
   explicitly at the top of `DaemonState::show_item`, not left to happen
   incidentally via `read_field`'s own gate: an item made entirely of
   secret-shaped fields would otherwise never call `read_field` at all,
   and so would answer with placeholders even while locked. New error
   variant `CoreError::ItemNotFound { vault, item }` /
   `ManagerError::ItemNotFound` for an unknown item — distinct from
   `NotFound`, which always names a specific field that an item-level
   lookup has none of.
6. **`secrets show <item-ref>`** (`secrets-cli`) is the new subcommand.
   Unlike `get`, it has **no terminal-disclosure refusal** (ADR-014's
   `resolve_get_mode`): no real secret material ever reaches this
   command, so there is nothing for that rule to guard. It only gains a
   `--json` flag, following the `list`/`status`/`resolve` precedent —
   `ShowPayload { uri, fields: Vec<FieldDisplay> }`, built directly from
   the client's response with no further redaction logic in the CLI
   (there being nothing left to redact).

## Consequences

- `Note` and `Custom` fields are always obfuscated by this command, even
  though many real-world uses of both (an expiry date in a note, a
  non-sensitive custom field a backend or user added) are not actually
  sensitive. There is no per-field override in this iteration — a future
  ADR could add one (e.g. a backend- or user-supplied sensitivity
  annotation), but the safe, fail-closed default ships first.
- `ItemUri` and `SecretUri` can parse the *same string* into two
  different shapes: `secret://Personal/GitHub/password` is a one-segment
  item (`GitHub`) plus a field (`password`) to `SecretUri`, but a
  two-segment item (`["GitHub", "password"]`) to `ItemUri`. This is a
  documented ambiguity, not a bug — a caller must already know which
  reference shape it means (exactly as it must already know whether a
  bare `foo/bar` is one nested item path or an item plus a field), and
  `secrets show`'s own `--help` documents its argument as an item
  reference specifically.
- `secretsd::backend::local`'s `kind_to_str`/`kind_from_str` now delegate
  to `FieldKind`'s shared `Display`/`FromStr` rather than maintaining
  their own copy of the same string table — a small refactor bundled
  into this change since both now need to agree on the same strings.
- `Manager.ShowItem` is a second method (besides `Get`) that can read
  backend data, so it is covered by the same lock/session gating tests
  `get`/`resolve` already have, plus new tests specific to the
  obfuscation guarantee (`secretsd::state::tests::show_item_*`,
  `secrets-cli`'s end-to-end suite) that assert the real secret values
  never appear anywhere in the response — not merely that they are equal
  to the placeholder.
</content>
