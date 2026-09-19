# ADR-017: The prompt broker and provider protocol

## Status

Accepted. Extends ADR-001 (D-Bus as the IPC mechanism) and ADR-005's
naming/versioning conventions to a new kind of D-Bus peer; adapts
ADR-004's `Prompt` stub without reversing its "plain algorithm only, no
write support" decisions.

## Context

ADR-004 implemented `org.freedesktop.Secret.Prompt`'s shape but backed it
with a single, shared, always-immediately-dismissed instance, because "this
project has no such UI agent yet." `docs/security.md`'s own "Known MVP
limitations" section already named the consequence: no per-application
access control, with "a future prompt-based confirmation... via a future UI
client" recorded as the intended fix, not yet built.

`secretsd` must stay a headless-capable daemon (ADR-003: GTK/Qt/TUI/browser
applications are explicitly out-of-repo, separate projects; this repo never
grows a UI crate to host them). At the same time, several real needs
require asking a human something and waiting for an answer: unlocking the
daemon's own passphrase lock from a standard Secret Service client (not
just `secrets unlock`), and — eventually — per-application confirmation and
backend-specific interactive flows. None of this can depend on GTK, Qt, or
any specific toolkit living inside `secretsd`.

The first external provider will be a separate GTK project (e.g.
`secrets-prompt-gtk`, for lightweight Wayland compositors that don't run
GNOME Keyring); future providers may target Qt/KDE, GNOME Shell, or a TUI.
Multiple provider *implementations* must be able to exist without any of
them becoming a workspace member — the daemon needs a protocol, not a
dependency.

## Decision

Introduce a toolkit-independent `PromptBroker` (`secretsd::prompt`) plus a
versioned, D-Bus-based provider protocol defined once in `secrets-core`
(`secrets_core::prompt` for the wire-level vocabulary, `secrets_core::dbus`
for the transport), following ADR-002's "define shared syntax once, reuse
everywhere" house style.

### Wire protocol: three interfaces, not one

Three D-Bus interfaces, mirroring this codebase's own existing precedent
for dynamic object registration (`secret_service::refresh`'s `Collection`/
`Item` objects, ADR-015) rather than inventing a new IPC shape:

- **`org.secrets.PromptBroker1`** (`secretsd`-owned, fixed path
  `/org/secrets/PromptBroker`) — a provider calls `RegisterProvider(path,
  capabilities, priority)`/`UnregisterProvider()` here. The registering
  identity is always the D-Bus message's own sender (its unique connection
  name, read via `#[zbus(header)]`), **never** a self-reported argument —
  a provider cannot register or unregister on another connection's behalf,
  and `secretsd` never has to trust an unauthenticated claim of identity.
- **`org.secrets.PromptProvider1`** (provider-owned, at the path it
  registered) — `secretsd` calls `HandleRequest(request_path)` here to
  hand off a new prompt. This call is expected to return quickly (e.g.
  once a window is scheduled); it is not a place a provider blocks until
  the user answers.
- **`org.secrets.PromptRequest1`** (`secretsd`-owned, one object per
  pending prompt, at `/org/secrets/PromptBroker/Request/<id>`) — read-only
  `Kind`/`Title`/`Description`/`Options` properties describe what is being
  asked (never a secret value); `Respond`/`Decline`/`Cancel` let the
  provider answer. A per-request object, not a flat `Respond(id, ...)`
  method on the broker, so a provider can only answer a request it was
  actually handed — no request id to spoof.

Capabilities (`secrets_core::prompt::kind`: `"unlock"`, `"confirmation"`,
`"choice"`, `"security-key"`) are plain strings, not a D-Bus enum, so a
future kind is additive. Interface names carry an explicit version suffix
(`PromptBroker1`, not `PromptBroker`) — unlike `org.secrets.Manager`
(ADR-005), which assumes "additive forever" because `secretsd` and its own
clients release together, a prompt provider is a **separate process this
project does not release in lockstep with**. A breaking change gets a new,
distinctly named interface (`PromptBroker2`) instead of silently breaking
old providers that only know `PromptBroker1`.

### Nothing blocks the D-Bus dispatch thread

`main.rs`'s own doc comment establishes that the blocking `Connection`
dispatches every method call on a single background thread. A prompt can
legitimately stay open for minutes; a handler that blocked in-line on a
human (or a hung provider process) would stall every other client of
`secretsd` for as long as the prompt stayed open. Concretely:

- `PromptBroker::submit` never waits for an answer. With no provider
  registered for the requested capability, it resolves immediately
  (`PromptOutcome::NoProviderAvailable`) and returns — the path that keeps
  a headless `secretsd` functional, per this issue's own acceptance
  criteria. With one, it returns immediately too; the eventual answer
  arrives later.
- The outbound `HandleRequest` call and each request's timeout each run on
  their own short-lived thread — the same bounded-worker-thread pattern
  `backend::onepassword::session::SessionManager` already uses so a hung
  external process cannot block the daemon forever (ADR-012's own
  precedent for calling into an external process carefully).
- The eventual outcome is delivered as the standard `Completed` signal via
  `Connection::emit_signal`, called from whichever thread learns it — the
  same technique `secret_service::refresh` already uses to emit topology
  signals from outside a live method call (ADR-015), not a
  `#[zbus(signal)]` codegen'd method (which needs an async `SignalEmitter`
  only available inside a call).

### Provider selection and disappearance

Among providers registered for a requested capability, the
highest-`priority` one is selected; ties favour whichever registered
first. Only the selected provider is notified per request — this project's
MVP does not race multiple providers against each other.

A provider's connection closing (crash, or any exit without calling
`UnregisterProvider`) is detected via `org.freedesktop.DBus`'s own
`NameOwnerChanged` signal, watched on its own background thread
(`secretsd::prompt::watcher`, same "plain OS thread, no second executor"
shape as the topology refresher). Every request routed to a vanished
provider resolves deterministically as `PromptOutcome::ProviderVanished`
— never left pending forever.

### What is actually wired up by this ADR

`org.freedesktop.Secret.Prompt` is adapted to the broker for exactly one
real flow: `Service.Unlock`, when the daemon's own passphrase lock (not a
backend session) is why access is denied, now starts a genuine `"unlock"`
request through `secret_service::prompt::UnlockPrompt`. A correct answer
actually calls `DaemonState::unlock`; any other outcome reports the prompt
as dismissed, exactly like the pre-ADR-017 behaviour. With no provider
registered, behaviour is unchanged, byte-for-byte, from the ADR-004 stub.

**Not** wired up by this ADR, deliberately: a backend session's own
authentication requirement (1Password Desktop's `RequiresAuthentication`/
`SessionExpired`, ADR-011) is not something this broker can resolve —
1Password Desktop's own app owns that UI, entirely outside `secretsd`'s
control. Per-application access control (`docs/security.md`'s "no
per-application access control" limitation) is also not implemented here
— only the mechanism a future confirmation policy would need. Both remain
explicitly open, tracked as follow-up work, not silently missing.

### Trust boundary

Every existing D-Bus interface `secretsd` serves treats the daemon as the
trusted authority and the caller as merely unprivileged-but-harmless. A
prompt provider inverts that for exactly the data it returns: `secretsd`
acts on what a provider says a human did — "the user typed this
passphrase," "the user approved this" — without any way to verify it
independently. Any process running as the same user can register as a
provider in this MVP; there is no additional authentication beyond the
session bus's own kernel-UID authentication (ADR-001), the same boundary
every other interface already relies on. A malicious local process could
therefore register as a `"unlock"` provider and answer a real user's
unlock prompt with an attacker-supplied passphrase — but that process
could already call `org.secrets.Manager.Unlock` directly with any
passphrase it likes; registering as a provider grants no capability an
unprivileged same-user process didn't already have. `docs/security.md` is
updated alongside this ADR to document this explicitly as a known MVP
limitation, in the same style as its existing ones.

Request/response payloads are held to the same discipline as
[`CoreError`]/[`SecretValue`]: a [`PromptKind`] only ever carries names and
descriptions; only [`PromptAnswer::Password`] can carry a secret, and only
for as long as it takes `DaemonState::unlock` to consume it.

## Consequences

- `secretsd` gains no GTK/Qt/UI dependency — the broker and protocol types
  live in `secrets-core`/`secretsd`, exactly where ADR-003 already
  confines domain/daemon logic; any real provider is an out-of-tree,
  protocol-speaking peer, never a workspace member.
- A headless `secretsd` (no provider ever registered) is unaffected:
  `Service.Unlock`/`Prompt.Prompt` behave exactly as the ADR-004 stub did.
- The existing `prompting_immediately_reports_itself_dismissed` test needed
  no changes — it never registers a provider, so it continues to exercise
  the unchanged "no provider" path.
- A new in-repo, D-Bus-speaking mock provider
  (`crates/secretsd/tests/support/mock_provider.rs`) exists purely to test
  this protocol end to end; it is not a template for a real provider's UX,
  only its wire behaviour.
- `PROMPT_TIMEOUT`/`PROMPT_NOTIFY_TIMEOUT` are hardcoded, not
  `secretsd.toml` knobs — same status as `REFRESH_INTERVAL` (ADR-015) —
  but overridable via an environment variable for tests only
  (`PROMPT_TIMEOUT_OVERRIDE_ENV`), the same pattern
  `backend::onepassword::ffi::LIBRARY_PATH_OVERRIDE_ENV` already
  established for pointing a test at a fixture instead of a real
  external dependency.
- Backend-session authentication and per-application confirmation remain
  unimplemented; a future issue can build on this broker's existing public
  API (`PromptBroker::submit`) without a protocol change to do either.
- `docs/security.md` gains a new trust-boundary paragraph for prompt
  providers as an inbound-trusted peer — the first D-Bus interface in this
  project where that direction of trust exists at all.
