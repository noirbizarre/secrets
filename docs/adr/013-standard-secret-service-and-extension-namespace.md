# ADR-013: Standard Secret Service as the primary contract, `org.secrets.*` as extensions

## Status

Accepted

## Context

ADR-004 scoped the Secret Service compatibility layer and ADR-005 designed
`org.secrets.Manager`, but together the documentation ended up presenting
them backwards from how a client author actually needs to read them:
`docs/dbus/secrets-manager.md` called `org.secrets.Manager` "the native
Secrets D-Bus API" and Secret Service "the compatibility layer that exists
for tools that predate this project" — implying `org.secrets.Manager` is
what a new client should reach for first. That framing also hid a real
gap: `secretsd` requested only its own well-known bus name,
`org.secrets.Daemon` (`secrets_core::dbus::SERVICE_NAME`), and never
`org.freedesktop.secrets` — the name standard Secret Service clients
(`secret-tool`, `libsecret`'s `SECRET_SERVICE_BUS_NAME`, GNOME
Keyring/KWallet-compatible consumers) address directly. An unmodified
standard client could not reach `secretsd` at all, regardless of which
object paths it served.

`secretsd` also did not serve the specification's literal well-known
alias object, `/org/freedesktop/secrets/aliases/default` (spec chapters
4 "Aliases" and 12 "Object Paths") — only the `ReadAlias("default")`
method — leaving a documented discovery path some clients rely on
unreachable.

## Decision

1. `secretsd` requests `org.freedesktop.secrets` **best-effort**, after
   the connection is already serving `org.secrets.Daemon` and every
   object path: a desktop session may already run GNOME Keyring or
   KWallet's `ksecretsd` owning that name first, and startup must not
   fail because of that, nor may `secretsd` request
   `AllowReplacement`/`ReplaceExisting` and risk stealing the name from a
   legitimate provider. `DoNotQueue` is used so the outcome (own it, or
   don't) is immediate; anything other than becoming the primary owner is
   logged as a warning naming the likely conflicting provider and telling
   the operator to address `org.secrets.Daemon` explicitly instead. See
   `crates/secretsd/src/main.rs` and
   `crates/secretsd/src/secret_service/mod.rs::BUS_NAME`.
2. `secretsd` also serves the `"default"` alias's collection at its
   literal object path, `secret_service::ALIAS_DEFAULT_PATH`, in addition
   to its real `collection_path()` — same read-only, static-topology
   shape as everything else the compatibility layer already serves.
3. Documentation is **reframed in place, not restructured**: the standard
   `org.freedesktop.Secret.*` interfaces
   (`docs/dbus/secret-service.md`) are the primary, interoperable
   contract a client author should reach for first; `org.secrets.Manager`
   (`docs/dbus/secrets-manager.md`) is documented as the `org.secrets.*`
   **extension namespace** — for `secret://`-shaped operations the
   standard cannot express (resolving/fetching a `secret://` reference
   directly, single-passphrase unlock/status) — not a replacement API.
   No files are renamed; `docs/dbus/README.md`,
   `docs/architecture/overview.md`, `docs/architecture/external-clients.md`
   and the root `README.md` are updated to match.
4. Write support against the standard interfaces
   (`CreateCollection`/`CreateItem`/`SetSecret`/`Delete`/`SetAlias`), the
   `dh-ietf1024-sha256-aes128-cbc-pkcs7` session algorithm, and a real
   `Prompt` remain exactly as scoped by ADR-004 — out of scope here,
   tracked by
   [#8](https://github.com/noirbizarre/secrets/issues/8) and `PLAN.md`.

## Consequences

- `secret-tool`/`libsecret`-based applications reach `secretsd` and list/
  read secrets without any client-side configuration, on a machine where
  no other Secret Service provider is already running.
- On a machine where GNOME Keyring or KWallet already owns
  `org.freedesktop.secrets`, standard clients keep reaching that provider
  instead — `secretsd` logs a warning naming the conflict rather than
  failing silently or fighting over the name; the operator chooses which
  provider is authoritative (stop the other one, or address
  `org.secrets.Daemon` directly for Secrets-specific tooling).
- `org.secrets.Manager`'s own contract (methods, errors, compatibility
  policy) is unchanged by this ADR — only its documented *relationship*
  to the standard interfaces changes. ADR-004 and ADR-005 are not
  superseded; this ADR records how they fit together and closes the one
  concrete gap (the missing bus name and alias object) between what they
  described and what `secretsd` actually did.
