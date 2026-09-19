# The prompt broker and provider protocol

The `org.secrets.*` extension namespace's third surface, alongside
[`org.secrets.Manager`](secrets-manager.md) and the standard
[Secret Service](secret-service.md) compatibility layer: how an external,
desktop-specific **prompt provider** registers with `secretsd` and answers
interactive prompts (unlock passphrases, confirmations, choices,
security-key approvals) without `secretsd` itself depending on any UI
toolkit. See [ADR-017](../adr/017-prompt-broker-and-provider-protocol.md)
for the full design rationale, and
[`docs/architecture/external-clients.md`](../architecture/external-clients.md)
for where a real provider (e.g. a future `secrets-prompt-gtk`) lives
relative to this repository.

**No provider is implemented in this repository.** This page documents the
protocol a separate, out-of-tree process implements; `secretsd`'s own
integration tests exercise it against a minimal, test-only mock
(`crates/secretsd/tests/support/mock_provider.rs`), not a real UI.

## Three interfaces

| Interface                     | Implemented by | Object path                                    |
| ------------------------------ | --------------- | ------------------------------------------------ |
| `org.secrets.PromptBroker1`    | `secretsd`      | `/org/secrets/PromptBroker`                       |
| `org.secrets.PromptProvider1`  | the provider    | wherever the provider registered                  |
| `org.secrets.PromptRequest1`   | `secretsd`      | `/org/secrets/PromptBroker/Request/<id>`, one per pending request |

All three are defined once in `secrets_core::dbus` (`#[zbus::proxy]`,
generating both blocking and async proxies), the same source-of-truth
pattern `org.secrets.Manager` uses.

### `org.secrets.PromptBroker1` — registration

#### `RegisterProvider(object_path: ObjectPath, capabilities: Vec<String>, priority: i32) -> u32`

Registers the calling connection as a prompt provider. `capabilities` is a
subset of the tags below; `object_path` is where `secretsd` will call
`PromptProvider1.HandleRequest` **on the calling connection**. Returns the
protocol version (`1` today) so a provider can verify compatibility before
relying on any capability.

The registering identity is always the D-Bus message's own sender (its
unique connection name) — never a caller-supplied argument. Fails with
`org.secrets.Prompt.Error.AlreadyRegistered` if the same connection already
has a registration; call `UnregisterProvider` first to replace it.

#### `UnregisterProvider()`

Unregisters the calling connection. A no-op if it was never registered.
Does not resolve any requests already routed to it — a well-behaved
provider answers or cancels its own in-flight requests first.

### Capability tags

| Tag              | [`PromptKind`] variant | Meaning                                  |
| ----------------- | ------------------------ | ------------------------------------------ |
| `"unlock"`        | `Unlock`                 | A passphrase is needed                     |
| `"confirmation"`  | `Confirmation`           | A yes/no confirmation for an action        |
| `"choice"`        | `Choice`                 | A choice among a fixed set of options      |
| `"security-key"`  | `SecurityKey`            | Hardware/security-key approval             |

Plain strings, not a D-Bus enum, so a future kind is additive.

### `org.secrets.PromptProvider1` — implemented by the provider

#### `HandleRequest(request: ObjectPath)`

Called by `secretsd` when a new request needs this provider's attention.
`request` is a `PromptRequest1` object on `secretsd`'s own connection — the
provider reads its properties, shows UI, and eventually calls exactly one
of `Respond`/`Decline`/`Cancel` on it. This method is expected to return
quickly (e.g. once a window is scheduled to open); it is **not** a place to
block until the user answers — see ADR-017 for why nothing in this
protocol blocks a caller waiting on human interaction.

### `org.secrets.PromptRequest1` — one object per pending request

#### Properties (read-only)

| Property       | Type          | Meaning                                                    |
| --------------- | ------------- | ------------------------------------------------------------ |
| `Kind`          | `String`      | One of the capability tags above                              |
| `Title`         | `String`      | A short, human-readable title                                 |
| `Description`   | `String`      | A longer, human-readable description                          |
| `Options`       | `Vec<String>` | The offered options — non-empty only for `"choice"`           |

Never a secret value: a request only ever carries names and descriptions
(e.g. "Unlock the Secrets vault"), never vault contents.

#### `Respond(answer: Variant)`

Answers the request. `answer`'s shape depends on `Kind`:

- `"unlock"` — a string passphrase.
- `"choice"` — one of `Options`, verbatim.
- `"confirmation"` / `"security-key"` — ignored; calling `Respond` at all
  (rather than `Decline`) already means "approved".

Fails with `org.secrets.Prompt.Error.KindMismatch` if the answer's shape
does not match `Kind`, or `org.secrets.Prompt.Error.RequestNotFound` if the
request already concluded (answered, declined, cancelled, timed out, or
`secretsd` otherwise resolved it — e.g. this provider was detected as
vanished on another connection).

#### `Decline()`

Explicitly declines (e.g. "No" on a confirmation). Same
`RequestNotFound` failure mode as `Respond`.

#### `Cancel()`

Dismisses without answering. Same `RequestNotFound` failure mode.

## What happens with no provider available

Every capability degrades gracefully to "as if this protocol did not
exist": with no provider registered for a requested kind (or the selected
one fails to acknowledge `HandleRequest` within a short, internal timeout),
the request resolves immediately as `NoProviderAvailable` — a headless
`secretsd` is fully functional regardless. Concretely, for the one flow
this repository wires up today (`org.freedesktop.Secret.Prompt`, see
below): `Prompt.Prompt()` dismisses immediately, exactly as it did before
this protocol existed.

## Provider disappearance, cancellation, and timeouts

- **Timeout:** an unanswered request resolves as `TimedOut` after a fixed
  interval (`secretsd::prompt::broker::PROMPT_TIMEOUT`) — not a
  `secretsd.toml` setting, same status as the Secret Service topology
  refresher's own interval (ADR-015).
- **Provider vanishing:** `secretsd` watches `org.freedesktop.DBus`'s
  `NameOwnerChanged` signal for every registered provider's unique name.
  If a provider's connection closes without calling `UnregisterProvider`
  first, every request routed to it resolves as `ProviderVanished`.
- **Cancellation:** the Secret Service `Prompt.Dismiss()` call (see below)
  cancels the corresponding outstanding request, if any.

Every one of these leaves `secretsd`'s own state deterministic: a request
never stays pending forever, and locking/session state never depends on a
provider that has disappeared.

## How `org.freedesktop.Secret.Prompt` uses this

`Service.Unlock`, when the daemon's own passphrase lock (not a backend
session — see ADR-011) is why access is denied, starts a real `"unlock"`
request through this broker. If a `"unlock"`-capable provider answers with
the correct passphrase, `secretsd` actually unlocks — `Prompt.Completed`
reports `dismissed = false`. Any other outcome (declined, cancelled, timed
out, no provider, provider vanished, or a wrong passphrase) reports
`dismissed = true`, the same shape the pre-ADR-017 stub always reported.
See [`secret-service.md`](secret-service.md) for the interface's full
scope.

A backend session's own authentication requirement (1Password Desktop) is
**not** resolved through this broker — that backend's own app owns its
UI, entirely outside `secretsd`'s control.

## Security

See [`docs/security.md`](../security.md)'s "Prompt providers" section for
the trust boundary a provider represents: unlike every other D-Bus
interface `secretsd` serves, `secretsd` acts on what a provider *tells it*
a human did, without independent verification. Any process running as the
same user can register as a provider today — the same boundary every other
interface already relies on (the session bus's kernel-UID authentication),
not a new, weaker one.

## Compatibility

Interface names carry an explicit version suffix (`PromptBroker1`, not
`PromptBroker`) — unlike `org.secrets.Manager`, which assumes additions are
forever backward compatible because `secretsd` and its own clients release
together, a prompt provider is a **separate project this repository does
not release in lockstep with**. A breaking change to this protocol
introduces a new, distinctly named interface (`PromptBroker2`, and so on)
rather than silently breaking a provider that only knows `PromptBroker1`.
