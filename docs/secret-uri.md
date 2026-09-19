# The `secret://` URI scheme

`secret://` is the canonical way to name one field of one item in one
vault, wherever a client needs to refer to a specific secret: CLI
arguments, `org.secrets.Manager` method parameters, and eventually
templates and injected environment variables.

**`secret://` is a resource reference, not an IPC protocol.** Resolving one
happens over D-Bus (see [`docs/dbus/secrets-manager.md`](dbus/secrets-manager.md));
the URI itself says nothing about transport. See
[ADR-001](adr/001-dbus-as-the-ipc-mechanism.md) and
[ADR-002](adr/002-secret-uri-scheme.md) for the reasoning behind keeping
those two concerns apart.

## Shape

```text
secret://[<store>@]<vault>/<item...>/<field>
```

- **`<store>@`** — optional. Names which configured *store* (backend
  instance) the vault lives in — see
  [ADR-018](adr/018-multi-store-support.md). Omit it and the reference
  parses exactly as it always has: with one configured store, it always
  resolves there; with more than one, it resolves wherever the vault name
  is found, as long as that is unambiguous (see "Store qualification"
  below).
- **`<vault>`** — one segment, the vault's name.
- **`<item...>`** — one or more segments. Most items are a single segment
  (`GitHub`); a vault that organises items in folders uses more
  (`Production/database`). The model does not distinguish "folder" from
  "item" — it is simply a path.
- **`<field>`** — one segment, always the *last* one. The field's kind
  (password, username, TOTP seed, SSH key, certificate, ...) is metadata
  the backend reports, not part of the URI.

## Examples

```text
secret://Personal/GitHub/username
secret://Personal/GitHub/password
secret://Personal/GitHub/totp

secret://Infrastructure/Production/database/password
secret://Infrastructure/Production/ssh-key

secret://PKI/example.com/certificate
secret://PKI/example.com/private-key
secret://PKI/example.com/chain
```

`secret://Infrastructure/Production/database/password` parses as vault
`Infrastructure`, item `Production/database` (two segments), field
`password`. `secret://Infrastructure/Production/ssh-key` parses as vault
`Infrastructure`, item `Production` (one segment), field `ssh-key` — the
same grammar handles both without a separate syntax for nested versus flat
items; the rule is simply "the last segment is the field, everything
between the vault and it is the item path."

## Escaping

A literal `/`, `%`, or non-ASCII byte inside a single segment's *name*
must be percent-encoded (RFC 3986 `pct-encoded`) by whatever produces the
reference. Parsing splits the string on unescaped `/` characters first,
then percent-decodes each resulting segment — so an encoded slash
(`%2F`) can never be mistaken for a path separator, and a segment
containing one round-trips correctly:

```text
secret://Personal/My%2FFolder/password
```

parses as vault `Personal`, item `My/Folder` (one segment, containing a
literal slash), field `password`.

## Invalid references

The parser (`secrets_core::uri::SecretUri::parse`) rejects, with a specific
error rather than a generic failure:

- a string not starting with `secret://` (case-sensitive)
- fewer than three `/`-separated components after the scheme and any
  `store@` qualifier (missing item or field)
- any component that decodes to the empty string (e.g. a trailing slash,
  or two adjacent slashes)
- invalid percent-encoding within a component
- a bare `@` with nothing before it (`secret://@Personal/...`)
- a store qualifier that decodes but is not a valid store id (ADR-018) —
  e.g. contains a space

Every error variant is listed in `secrets_core::uri::UriError`, and is
safe to log or display: a malformed reference cannot itself be a secret's
*value*, only its name.

## Store qualification

With more than one configured store, an unqualified `<vault>` is resolved
by asking every store whether it has a vault by that name:

```text
secret://Personal/GitHub/password           # unqualified
secret://work@Personal/GitHub/password      # qualified: store "work"
```

- Found in exactly **one** store: resolves there, exactly as if only that
  store were configured — the reason a multi-store deployment does not
  need every reference qualified, only the ones that actually collide.
- Found in **more than one** store: rejected with
  `org.secrets.Error.AmbiguousVault`, naming every matching store — never
  a silent guess. Qualify the reference to pick one:
  `secret://<store>@Personal/...`.
- Found in **no** store: the usual `NotFound`.

A literal `@` in a vault name must be percent-encoded (`%40`) so it is not
read as the store separator — the same escaping rule this page's
"Escaping" section already applies to a literal `/`. The `<store>@`
detection only ever looks at the *first* segment, so an `@` inside an
item or field name is never affected:
`secret://Personal/user@host/password` is vault `Personal`, item
`user@host`, with no store qualifier at all.

`org.secrets.Manager.ListVaults` always returns fully `store@vault`-
qualified names (even with a single configured store), so its output is
always ready to use as a qualifier or paste into a `secret://` reference.
`Manager.ListItems`'s `vault` argument, and `secrets list`'s own, accept
the same optional `store@` prefix.

## Item-level references

`secrets_core::uri::ItemUri` parses `secret://<vault>/<item...>` — the
same grammar with **no field segment** — for the one operation that
addresses a whole item rather than one of its fields:
`Manager.ShowItem`/`secrets show` (see
[ADR-016](adr/016-show-command-and-field-value-obfuscation.md)). It has
no way to tell "a two-segment item path" apart from "a one-segment item
plus a field" for the same string — `secret://Personal/GitHub/password`
is item `GitHub` field `password` to `SecretUri`, but item
`["GitHub", "password"]` to `ItemUri` — so a caller must already know
which shape it means, the same way it must already know whether a bare
`foo/bar` is a nested item path or an item plus a field. Every other
operation on this page's grammar (`Resolve`, `Get`, and `secrets`'
`resolve`/`get`/`totp` commands) still uses `SecretUri`, unchanged.

## Implementation

Parsing, validation and canonical formatting all live in
`crates/secrets-core/src/uri.rs`, reused by `secretsd`, `secrets-client`
and `secrets-cli` — and, by extension, any application built on
`secrets-client`, or any non-Rust client speaking the D-Bus protocol
directly — rather than reimplemented per client. See its module
documentation and test suite for the exhaustive set of cases covered.
