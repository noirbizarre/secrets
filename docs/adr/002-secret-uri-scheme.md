# ADR-002: The `secret://` URI scheme

## Status

Accepted

## Context

Every client needs a single, unambiguous way to name one field of one item
in one vault — in CLI arguments, in D-Bus method parameters, and
eventually in injected environment variables and templates. The format
needs to:

- distinguish vault, item and field unambiguously
- support items organised in nested folders (`Infrastructure/Production`
  containing a `database` item, not just flat item names)
- allow any of those names to contain a literal `/`, without that breaking
  parsing
- reject malformed references with a specific, actionable error rather
  than silently misinterpreting them

## Decision

`secret://<vault>/<item...>/<field>`, where `<item...>` is one or more
`/`-separated segments and the *last* segment is always the field. A
literal `/`, `%`, or non-ASCII byte inside any single segment must be
percent-encoded (RFC 3986 `pct-encoded`) by whatever produces the
reference — parsing splits on unescaped `/` first, then percent-decodes
each resulting segment, so an encoded slash can never be mistaken for a
path separator.

Consequences of this shape, worked through against the examples in
`docs/secret-uri.md`:

- `secret://Personal/GitHub/password` → vault `Personal`, item `GitHub`,
  field `password`.
- `secret://Infrastructure/Production/database/password` → vault
  `Infrastructure`, item `Production/database` (two segments), field
  `password` — the same URI shape supports both flat and nested items
  without a separate syntax for either.

Implemented once, in `secrets-core::uri`, and reused by every crate — the
parser is not reimplemented per client.

## Consequences

- A three-part mental model ("vault / item path / field") replaces a naive
  fixed three-segment split, at the cost of requiring callers to
  percent-encode names containing `/` themselves — accepted, since that
  case is rare and the alternative (guessing where the item ends) is worse.
- Escaping and validation are exercised by `secrets-core`'s own test suite
  once, rather than by each client independently — a client cannot get URI
  parsing "slightly wrong" in a way `secrets-core`'s tests would not catch.
- The scheme purely names a *resource*; it says nothing about how a client
  reaches `secretsd` to resolve it — that is D-Bus's job (ADR-001), kept
  deliberately separate so the URI format could, in principle, outlive any
  particular transport.
