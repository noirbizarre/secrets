# Secrets — Project Plan

Tracking document for the `secrets` MVP and beyond. Categories are numbered
`x.y`; numbers are never reassigned, so a finished item just flips its
checkbox. New work under a category is appended with the next `y`, new
categories get the next `x`.

This file is plain markdown, not rendered by `rust.tpl`.

## 0. Meta

- [x] 0.1 File an issue on `noirbizarre/rust.tpl` requesting native Cargo
      workspace support (root package as one member among several) —
      [rust.tpl#8](https://github.com/noirbizarre/rust.tpl/issues/8)
      (closed: shipped natively)
- [x] 0.2 ~~Decide interim workspace strategy~~ — superseded: `rust.tpl`
      shipped native `workspace` support (a `workspace` boolean question
      rendering a virtual manifest) before any workaround was needed
- [x] 0.3 Run `git tpl init` against `rust.tpl` with `workspace = true`

## 1. Repository & Tooling Scaffolding

- [x] 1.1 `git tpl init` with `workspace = true` and the agreed template
      answers (crate=secrets, description, keywords, categories, msrv,
      publish, docs, targets)
- [x] 1.2 Confirm mise/prek/CI/release/docs-site skeleton renders and
      builds — `mise run ci` (format, clippy -D warnings, spelling,
      actionlint, markdownlint, tests, docs build) passes clean; CI's test
      matrix trimmed to Linux only (see the `# --- project-specific ---`
      comment in `.github/workflows/ci.yaml`) since this project cannot
      compile on Windows/macOS (`xdg`, D-Bus session bus, Unix SSH agent
      socket) — worth raising upstream as a `test_targets`-style question
      alongside the existing release `targets` question, not yet filed
- [x] 1.3 Add `crates/secrets-core`, `crates/secretsd`, `crates/secrets-cli`
      as workspace members
- [x] 1.4 `systemd/secretsd.service` user unit
- [x] 1.5 Add `crates/secrets-client` as a workspace member — the public
      Rust client library, so future Rust applications depend on one
      crate instead of reimplementing `secrets-cli`'s own D-Bus plumbing

## 2. Documentation

- [x] 2.1 README: what/why/architecture/vision, Mermaid diagram
- [x] 2.2 `docs/architecture/overview.md`
- [x] 2.3 `docs/architecture/external-clients.md` — GD Secrets /
      `secrets-tui` / browser extensions boundary (pure D-Bus clients, no
      owned state)
- [x] 2.4 `docs/secret-uri.md` — `secret://` scheme, resource reference vs.
      D-Bus as the IPC mechanism
- [x] 2.5 `docs/dbus/secrets-manager.md` — `org.secrets.Manager`
- [x] 2.6 `docs/dbus/secret-service.md` — Secret Service compat scope
      (plain algorithm only for MVP)
- [x] 2.7 `docs/dbus/ssh-agent.md`
- [x] 2.8 `docs/security.md` — MVP security model and its limitations
- [x] 2.9 `docs/dbus/README.md` — D-Bus protocol as the Secrets IPC
      boundary, indexing the native/Secret-Service/SSH-agent protocol docs
- [x] 2.10 Reframe `docs/dbus/`, `docs/architecture/overview.md`,
      `docs/architecture/external-clients.md` and `README.md`: the
      standard Secret Service interfaces are the primary, interoperable
      contract; `org.secrets.Manager` is documented as the `org.secrets.*`
      extension namespace for `secret://`-shaped operations the standard
      cannot express — not a replacement API (see ADR-013, §3.11)
- [x] 2.11 `docs/dbus/prompt-broker.md` — the prompt broker/provider
      protocol (`org.secrets.PromptBroker1`/`PromptProvider1`/
      `PromptRequest1`); updates to `docs/dbus/README.md`,
      `docs/dbus/secret-service.md` (conditional interactive prompting),
      `docs/architecture/overview.md` and
      `docs/architecture/external-clients.md` (prompt providers as a new
      external-peer category) and `docs/security.md` (the new inbound
      trust direction a provider represents) — see
      [ADR-017](docs/adr/017-prompt-broker-and-provider-protocol.md),
      issue #21

## 3. Architecture Decision Records (`docs/adr/`)

- [x] 3.1 [ADR-001](docs/adr/001-dbus-as-the-ipc-mechanism.md) — D-Bus
      session bus as the IPC mechanism (not a custom socket protocol)
- [x] 3.2 [ADR-002](docs/adr/002-secret-uri-scheme.md) — `secret://` URI
      scheme: hierarchical item path, field as terminal segment,
      percent-encoding for escaping
- [x] 3.3 [ADR-003](docs/adr/003-workspace-and-crate-boundaries.md) —
      Workspace/crate boundaries: `secrets-core` (domain/model),
      `secrets-client` (public Rust client library), `secretsd` (daemon),
      `secrets` CLI, and the D-Bus protocol as its own first-class
      boundary, in a native `rust.tpl` workspace (see rust.tpl#8)
- [x] 3.4 [ADR-004](docs/adr/004-secret-service-compatibility-scope.md) —
      Secret Service compatibility scope (plain algorithm only for the MVP)
- [x] 3.5 [ADR-005](docs/adr/005-native-manager-api-design.md) — Native
      `org.secrets.Manager` API design and its forward-compatibility
      strategy
- [x] 3.6 [ADR-006](docs/adr/006-local-backend-cryptography.md) — Local
      backend cryptography: AES-256-GCM + Argon2id + `zeroize`
- [x] 3.7 [ADR-007](docs/adr/007-ssh-agent-implementation.md) — SSH agent
      via `ssh-agent-lib` + `ssh-key`, no hand-rolled protocol or crypto
- [x] 3.8 [ADR-008](docs/adr/008-backend-abstraction-and-roadmap.md) —
      Backend abstraction and the pluggable backend roadmap
- [x] 3.9 [ADR-009](docs/adr/009-session-and-lock-state-machine.md) —
      Session/lock state machine, daemon as sole authority
- [x] 3.10 [ADR-010](docs/adr/010-cli-as-thin-dbus-client.md) — CLI as a
      thin D-Bus client only, no independent state
- [x] 3.11 [ADR-013](docs/adr/013-standard-secret-service-and-extension-namespace.md)
      — Standard Secret Service as the primary contract, `org.secrets.*`
      as extensions; also closes the gap where `org.freedesktop.secrets`
      was never requested as a bus name
- [x] 3.12 [ADR-011](docs/adr/011-backend-session-and-authentication-state.md)
      — Backend session and authentication state: `Arc<dyn Backend>` plus
      an optional `Arc<dyn BackendSession>`, so locking can vary per backend
      without `DaemonState` losing its status as sole lock authority
- [x] 3.13 [ADR-012](docs/adr/012-1password-desktop-backend.md) — 1Password
      Desktop backend via its native app-integration IPC, not the `op` CLI
- [x] 3.14 [ADR-014](docs/adr/014-cli-secret-disclosure-modes.md) —
      `secrets get`'s output modes (`--raw`/`--json`/`--clipboard`) and its
      default refusal to print a bare value to a terminal
- [x] 3.15 [ADR-015](docs/adr/015-live-secret-service-topology.md) — Live
      Secret Service topology: a background scan reconciles
      `Collection`/`Item` objects instead of a fixed, fatal, one-shot scan
      at startup; supersedes ADR-004's "fixed at startup" framing only

## 4. `secrets-core` (domain/core library)

- [x] 4.1 `SecretUri` parser and typed representation (`uri.rs`)
- [x] 4.2 Data model: `Vault` / `Item` / `FieldMeta` / `FieldKind`
      (`model.rs`)
- [x] 4.3 `Backend` trait (`backend.rs`)
- [x] 4.4 `Resolver` (`resolver.rs`)
- [x] 4.5 Shared D-Bus interface definitions (`Manager` proxy trait,
      `ManagerError`) — the D-Bus protocol's source of truth, consumed by
      `secretsd` (implements the interface) and `secrets-client` (proxies
      it) (`dbus.rs`)
- [x] 4.6 Error types (`CoreError`), mapped to D-Bus error names at the
      daemon boundary (`error.rs`, `dbus.rs`)
- [x] 4.7 Unit tests: URI parsing, validation, escaping, resolution (27
      tests)
- [x] 4.8 `ItemUri` (item-level `secret://<vault>/<item...>` reference,
      no field), `FieldKind::is_secret`/`Display`/`FromStr`, and the
      `FieldDisplay` wire type + `OBFUSCATED_FIELD_PLACEHOLDER` constant
      — for `Manager.ShowItem` (`uri.rs`, `model.rs`, `dbus.rs`; see
      [ADR-016](docs/adr/016-show-command-and-field-value-obfuscation.md))
- [x] 4.9 `secrets_core::prompt` — toolkit-independent `PromptKind`/
      `PromptAnswer`/`PromptOutcome`; `secrets_core::dbus`'s
      `PromptBroker1`/`PromptProvider1`/`PromptRequest1` proxy traits and
      `PromptError` — the prompt broker/provider protocol's shared,
      wire-level contract (see
      [ADR-017](docs/adr/017-prompt-broker-and-provider-protocol.md),
      issue #21)

## 5. `secretsd` (daemon)

- [x] 5.1 D-Bus service bootstrap (`zbus::blocking`, `main.rs`)
- [x] 5.2 `org.secrets.Manager`: Get / Resolve / List / Lock / Unlock /
      Status / ShowItem (`manager.rs`)
- [x] 5.3 Secret Service compat: Service / Collection / Item / Session /
      Prompt, plain algorithm (`secret_service/`)
- [x] 5.4 Session & lock state machine (Locked / Unlocked) (`state.rs`)
- [x] 5.5 Local backend implementation: encrypted file store, Argon2id +
      AES-256-GCM, first-run demo seeding (`backend/local.rs`, `crypto.rs`)
- [x] 5.6 SSH agent (`ssh-agent-lib`); identities unavailable while locked
      (`ssh_agent.rs`)
- [x] 5.7 Daemon integration tests (automated) — a real `secretsd` binary
      spawned on a private `dbus-daemon` session bus over an isolated
      local-backend vault, driven through client-side proxies for
      `Service`/`Collection`/`Item`/`Session`/`Prompt`
      (`tests/secret_service.rs`, `tests/support/`); see §9.4
- [x] 5.8 Also request the standard `org.freedesktop.secrets` bus name,
      best-effort, and serve the `"default"` alias's collection at its
      literal `/org/freedesktop/secrets/aliases/default` object path —
      closes the gap where standard Secret Service clients (which
      hardcode that bus name) could not reach `secretsd` at all (see
      ADR-013, §3.11)
- [ ] 5.9 Secret Service write support
      (`CreateCollection`/`CreateItem`/`SetSecret`/`Delete`/`SetAlias`) —
      deliberately deferred by ADR-004/ADR-013, tracked by
      [issue #8](https://github.com/noirbizarre/secrets/issues/8)
- [x] 5.10 Live Secret Service topology — a background scan (periodic +
      reactive on `Manager.Unlock`/`Lock`) reconciles `Collection`/`Item`
      objects instead of a fixed, fatal, one-shot scan at startup; emits
      the standard `CollectionCreated`/`CollectionDeleted`/`ItemCreated`/
      `ItemDeleted` signals (`secret_service/refresh.rs`); supersedes
      ADR-004's "fixed at startup" framing — see
      [ADR-015](docs/adr/015-live-secret-service-topology.md)
- [x] 5.11 `secretsd::prompt` — the `PromptBroker`, provider registry,
      `org.secrets.PromptBroker1`/`PromptRequest1` interface
      implementations, and the `NameOwnerChanged`-based provider-vanish
      watcher; `secret_service::prompt::UnlockPrompt` adapts
      `org.freedesktop.Secret.Prompt`'s `Service.Unlock` flow to it — a
      registered `"unlock"`-capable provider can now genuinely unlock the
      daemon's own passphrase lock, with no provider registered behaving
      exactly as the original MVP stub (`prompt.rs`, `service.rs`,
      `main.rs`). See
      [ADR-017](docs/adr/017-prompt-broker-and-provider-protocol.md),
      issue #21

## 6. `secrets-cli`

- [x] 6.1 Command structure: `list` / `get` / `resolve` / `lock` /
      `unlock` / `status` (`cli.rs`, `lib.rs`)
- [x] 6.2 Stub future commands: `inject` / `run` / `totp` (clap surface
      only, `CliError::NotYetImplemented`)
- [x] 6.3 D-Bus client wiring — thin, no local vault/session state; via the
      `secrets-client` dependency (§12), not an in-crate implementation
- [x] 6.4 Interactive prompts via `demand` (unlock passphrase, masked)
- [x] 6.5 Config loading: `~/.config/secrets/config.toml`, XDG, `toml`
      crate (`config.rs`)
- [x] 6.6 CLI integration tests (`assert_cmd`, against a test daemon) — see
      §9.5
- [x] 6.7 `secrets show` — list an item's fields (name, kind, value),
      secret-shaped values obfuscated server-side; requires unlock, no
      terminal-disclosure refusal (unlike `get`) — see
      [ADR-016](docs/adr/016-show-command-and-field-value-obfuscation.md)

## 7. Backends

- [x] 7.1 Local encrypted-file backend (MVP)
- [ ] 7.2 [Future] Vaultwarden
- [ ] 7.3 [Future] Bitwarden
- [x] 7.4 1Password Desktop, via its native IPC library (not the `op`
      CLI) — `crates/secretsd/src/backend/onepassword/`, selected via
      `[backend] type = "1password"` in `secretsd.toml`. See
      [ADR-012](docs/adr/012-1password-desktop-backend.md) and
      `docs/architecture/1password-poc-results.md` for the investigation
      and validation this is built on. TOTP/SSH-specific behavior
      deliberately not implemented here (Secrets-level concerns, see the
      ADR).
- [ ] 7.5 [Future] `pass`
- [ ] 7.6 [Future] `gopass`
- [ ] 7.7 [Future] `passage`

## 8. Security

- [x] 8.1 Threat model / MVP limitations write-up (`docs/security.md`)
- [x] 8.2 Tests asserting no secret value ever reaches logs or error
      output (`secrets_core::resolver::tests`,
      `secrets_core::secret_value::tests`), extended to `secretsd`'s own
      captured stdout/stderr across a full locked/unlock/get/lock D-Bus
      session (`tests/secret_service.rs`'s `assert_no_secrets_leaked`), and
      to the `secrets` CLI's own stdout/stderr across the same cycle
      (`secrets-cli/tests/end_to_end.rs`, §9.5) — every error-path
      assertion there, plus `resolve`'s success path, checks a demo secret
      value never appears outside `get`'s one deliberate line
- [x] 8.3 Memory hygiene: `SecretValue`/`VaultKey` are
      `Zeroize`/`ZeroizeOnDrop`; documented `SIGKILL`/abort limitation in
      `docs/security.md`

## 9. Testing & Quality

- [x] 9.1 URI parser test suite (27 tests, `secrets-core`)
- [x] 9.2 Locked vs. unlocked behavior tests (`backend/local.rs` unit
      tests, plus the automated D-Bus pass in §9.4)
- [x] 9.3 Error-mapping tests (`CoreError` → `ManagerError`,
      `secrets_core::dbus::tests`)
- [x] 9.4 D-Bus integration tests, automated
      ([#3](https://github.com/noirbizarre/secrets/issues/3)) —
      `crates/secretsd/tests/secret_service.rs`: locked → unlock →
      list/search → get → lock over the standard Secret Service
      interfaces, missing items/attributes, locked-resource errors,
      stable object paths/properties, every unsupported write rejected
      with `NotSupported`, clean `SIGTERM` shutdown, and an assertion
      that no demo secret value ever appears in `secretsd`'s own captured
      log output. Replaces the manual `dbus-run-session` pass this entry
      used to describe. `org.secrets.Manager` is out of scope here (see
      the test file's own module doc) — only used to unlock/lock, which
      the Secret Service interfaces cannot do on their own.
- [x] 9.5 CLI-to-daemon integration tests (automated)
      ([#4](https://github.com/noirbizarre/secrets/issues/4)) —
      `crates/secrets-cli/tests/end_to_end.rs`: real `secrets`/`secretsd`
      binaries over a private D-Bus session bus, covering `status`,
      `list`, `get`, `resolve`, `unlock`, `lock`, daemon absent, locked
      backend, missing vault/item/field, malformed `secret://` URIs and a
      clap usage error, asserting exit codes, stdout/stderr text, and that
      no demo secret value ever appears anywhere except `get`'s own
      deliberate output. Unlike §9.4, drives the daemon only through the
      CLI itself (no raw `zbus`), and locates the cross-package
      `secretsd` binary via `escargot` rather than
      `CARGO_BIN_EXE_secretsd` (only set for tests in `secretsd`'s own
      package — see `tests/support/mod.rs`'s module doc).
- [x] 9.6 "no secret in error/log" regression tests — see §8.2
- [x] 9.7 Prompt broker/provider protocol tests — in-process registry
      unit tests (`secretsd::prompt::broker`), and an in-repo,
      D-Bus-speaking mock provider
      (`crates/secretsd/tests/support/mock_provider.rs`, not a real
      provider implementation) driving `crates/secretsd/tests/
      secret_service.rs` through the real wire protocol: a correct
      passphrase relay, a decline, a vanished provider mid-prompt, a
      timeout (via the test-only `SECRETS_PROMPT_TIMEOUT_MS` override,
      see `secretsd::prompt::broker::PROMPT_TIMEOUT_OVERRIDE_ENV`), and
      the no-provider-registered path staying identical to the original
      MVP stub

## 10. CI / Release

- [x] 10.1 Confirm `rust.tpl` CI matrix covers the workspace layout —
      required trimming the test job to Linux only (§1.2); `mise run ci`
      passes end to end.
- [x] 10.2 Release targets restricted to Linux (gnu + musl, x86_64 +
      aarch64)

## 11. External client repositories (documentation boundary only)

- [x] 11.1 GD Secrets boundary doc (`docs/architecture/external-clients.md`)
- [x] 11.2 `secrets-tui` / browser extensions native messaging boundary doc
      (`docs/architecture/external-clients.md`)

## 12. `secrets-client` (public Rust client library)

- [x] 12.1 Crate scaffold: `crates/secrets-client`, depends only on
      `secrets-core` (never on `secretsd`)
- [x] 12.2 `SecretsClient`: `connect` / `status` / `unlock` / `lock` /
      `list_vaults` / `list_items` / `resolve` / `get`, blocking (mirrors
      `ManagerProxyBlocking`; see ADR-005 on why no async runtime is
      required)
- [x] 12.3 `secrets-cli` depends on `secrets-client` instead of owning its
      own D-Bus client
- [ ] 12.4 [Future] Async variant and additional ergonomic API (e.g.
      `SecretUri`-typed helpers) — the seam that lets a Rust application
      such as Over integrate with Secrets natively, without implementing
      its own D-Bus layer; not implemented in this task
