# Architecture Decisions

Records of the decisions that shape this project, and — more usefully — the
reasons behind them. An ADR is written when a choice is hard to reverse or
likely to be re-proposed.

The point is not the decision; it is the alternatives that were rejected and
why. A record that only states the outcome saves nobody the argument.

A decision is changed by writing a new ADR that supersedes the old one, never
by editing the old one. The history is the value.

## Format

`NNN-kebab-case-title.md`, numbered in the order written, with the sections:

- **Status** — Proposed, Accepted, or Superseded by ADR-NNN
- **Context** — the forces in play, before any decision
- **Decision** — what was decided
- **Consequences** — what this costs, including what it makes harder

## Index

- [ADR-001](001-dbus-as-the-ipc-mechanism.md) — D-Bus as the IPC mechanism
- [ADR-002](002-secret-uri-scheme.md) — The `secret://` URI scheme
  (extended by ADR-018's optional `store@` qualifier)
- [ADR-003](003-workspace-and-crate-boundaries.md) — Workspace and crate
  boundaries
- [ADR-004](004-secret-service-compatibility-scope.md) — Secret Service
  compatibility scope
- [ADR-005](005-native-manager-api-design.md) — The `org.secrets.Manager`
  native API
- [ADR-006](006-local-backend-cryptography.md) — Local backend cryptography
- [ADR-007](007-ssh-agent-implementation.md) — SSH agent implementation
- [ADR-008](008-backend-abstraction-and-roadmap.md) — Backend abstraction
  and the pluggable-backend roadmap (its "cannot run two backends at once"
  limitation lifted by ADR-018)
- [ADR-009](009-session-and-lock-state-machine.md) — Session and lock state
  machine (superseded in part by ADR-018: locking is per-store, composed
  daemon-wide)
- [ADR-010](010-cli-as-thin-dbus-client.md) — The CLI as a thin D-Bus
  client only
- [ADR-011](011-backend-session-and-authentication-state.md) — Backend
  session and authentication state (extended by ADR-018: one session per
  store, not one for "the" backend)
- [ADR-012](012-1password-desktop-backend.md) — 1Password Desktop backend
- [ADR-013](013-standard-secret-service-and-extension-namespace.md) —
  Standard Secret Service as the primary contract, `org.secrets.*` as
  extensions (its object-path scheme and `"default"` alias extended by
  ADR-018 to a store-nested topology)
- [ADR-014](014-cli-secret-disclosure-modes.md) — `secrets get`'s output
  modes and terminal disclosure refusal
- [ADR-015](015-live-secret-service-topology.md) — Live Secret Service
  topology (supersedes ADR-004's "fixed at startup" framing)
- [ADR-016](016-show-command-and-field-value-obfuscation.md) — `secrets
  show` and field-value obfuscation by kind
- [ADR-017](017-prompt-broker-and-provider-protocol.md) — The prompt
  broker and provider protocol
- [ADR-018](018-multi-store-support.md) — Multi-store support (supersedes
  ADR-009's/ADR-013's single-store framing in part; extends ADR-002/
  ADR-008/ADR-011)
- [ADR-019](019-pass-backend.md) — The `pass`/`gopass` backend (revises
  ADR-011's "likely no `BackendSession`" prediction's reasoning, without
  changing its conclusion)
