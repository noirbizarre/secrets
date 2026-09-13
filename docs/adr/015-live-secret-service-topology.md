# ADR-015: Live Secret Service topology

## Status

Accepted. Supersedes only ADR-004's "fixed at startup" framing of the
Secret Service compatibility layer's object topology — every other
decision in ADR-004 (read-only, `"plain"`-only session, the shared
`Prompt` instance) stands unchanged.

## Context

ADR-004 already named the compatibility layer's fixed, one-shot topology
scan "the layer's most significant MVP limitation," explicitly contrasted
with `org.secrets.Manager`'s live-state behavior — a decision framed as an
MVP shortcut to revisit, not a permanent architectural choice.

Real-world use against a real 1Password account surfaced exactly why that
matters, in two concrete ways:

1. `main.rs` called `secret_service::discover(&state)` once, synchronously,
   before the daemon could start serving anything — and treated any
   failure as fatal to the *entire* process, including `org.secrets.Manager`
   and the SSH agent, neither of which needs this topology at all. A vault
   large enough to hit 1Password's own undocumented `ItemsGetAll` 50-item
   limit made `secretsd` refuse to start outright.
2. The registered `Collection`/`Item` object set never changed afterwards.
   A vault or item appearing later — whether because the backend's own
   contents changed outside `secretsd`'s control, or because the local
   backend's vault file was created for the first time by `secrets unlock`
   while `secretsd` was already running — stayed invisible over Secret
   Service until a restart.

Neither problem is specific to 1Password; both follow directly from
"discover once, synchronously, fatally" being the whole design.

## Decision

Replace the fixed, one-shot topology with a live one:

- **`LiveTopology`** (`secretsd::secret_service::LiveTopology`), an
  `Arc<Mutex<Topology>>`-backed handle shared between `ServiceIface`,
  every `CollectionIface`, and the refresher below — each interface method
  takes its own snapshot rather than reading a construction-time copy.
- **A background refresher** (`secretsd::secret_service::refresh`), a
  plain OS thread — not its own `tokio` runtime; `zbus::blocking`'s
  `ObjectServer::at`/`remove` and `Connection::emit_signal` are already
  synchronous from the caller's side, so a second executor would be pure
  overhead. It performs the *first* topology scan itself, immediately
  after `secretsd` is already serving `org.secrets.Manager`/the Secret
  Service base objects — never before, and never as a condition of startup
  succeeding — then re-scans:
  - **Periodically**, every 30 seconds (`REFRESH_INTERVAL`, hardcoded for
    now, not a config knob).
  - **Reactively**, immediately, whenever `org.secrets.Manager`'s `Unlock`
    or `Lock` is called (`ManagerIface` holds an `mpsc::Sender<()>` it
    pokes best-effort after each) — the one case that matters most in
    practice: the local backend's vault file being created for the first
    time.
  - A failed scan (initial or later) is **only ever logged**, never fatal
    — the previous topology stays in place until the next attempt
    succeeds.
- **Reconciliation** diffs the previous topology against a fresh scan and
  adds/removes exactly the `Collection`/`Item` objects that changed via
  `zbus::blocking::ObjectServer::at`/`remove`, emitting the standard
  Secret Service signals for each change:
  `Service.CollectionCreated`/`CollectionDeleted`,
  `Collection.ItemCreated`/`ItemDeleted` — emitted via
  `Connection::emit_signal` directly, not a `#[zbus(signal)]` codegen'd
  method (which would need an async `SignalEmitter`/`block_on` at the call
  site, reintroducing the executor this design otherwise avoids). Every
  individual registration/removal/signal failure is logged and skipped,
  never aborting the rest of that reconciliation pass.
- The `"default"` alias's duplicate registration (ADR-013 item 2) is
  recomputed on every pass too, but only actually re-registered when the
  *identity* of "the first vault" changes — because `CollectionIface`
  reads the shared `LiveTopology` live rather than a snapshot, it already
  reflects that vault's own item changes without needing re-registration.

## Consequences

- A backend error during any scan — 1Password Desktop unreachable, an
  IPC limit, an authorization prompt not yet approved — no longer takes
  down `secretsd` as a whole; `org.secrets.Manager` and the SSH agent keep
  working regardless, and Secret Service simply reports whatever the last
  successful scan found (empty, on a first-ever failure).
- A vault/item appearing after `secretsd` is already running becomes
  visible over Secret Service without a restart — immediately for
  `Unlock`/`Lock`-triggered changes, within 30 seconds otherwise.
- Already-connected `secret-tool`/`libsecret` clients are notified live via
  the standard `CollectionCreated`/`CollectionDeleted`/`ItemCreated`/
  `ItemDeleted` signals, not just new connections that re-enumerate.
- **`Changed` signals** (`CollectionChanged`/`ItemChanged`) are explicitly
  **not** implemented — nothing today diffs a field's metadata (e.g. its
  `FieldKind`) distinctly from that field simply being added or removed. A
  deliberate, documented gap, not a silent omission.
- The refresh interval is hardcoded, not yet a `secretsd.toml` field — see
  `crate::secret_service::refresh::REFRESH_INTERVAL`'s own doc comment.
  Revisit if a real deployment needs a different cadence.
- Still exactly one in-process topology, held only in memory — nothing
  here changes persistence or multi-daemon behavior.
- Test harnesses that drive a real `secretsd` binary
  (`crates/secretsd/tests/support`) can no longer assume the topology is
  populated the instant the daemon reports ready (`org.secrets.Manager`
  answering); they poll for the expected `Collection` set explicitly
  (`TestDaemon::wait_until_collections`) instead.
