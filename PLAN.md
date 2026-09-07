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

## 3. Architecture Decision Records (`docs/adr/`)

- [x] 3.1 [ADR-001](docs/adr/001-dbus-as-the-ipc-mechanism.md) — D-Bus
      session bus as the IPC mechanism (not a custom socket protocol)
- [x] 3.2 [ADR-002](docs/adr/002-secret-uri-scheme.md) — `secret://` URI
      scheme: hierarchical item path, field as terminal segment,
      percent-encoding for escaping
- [x] 3.3 [ADR-003](docs/adr/003-workspace-and-crate-boundaries.md) —
      Workspace/crate boundaries: `secrets-core` / `secretsd` /
      `secrets-cli` as three peer members of a native `rust.tpl` workspace
      (see rust.tpl#8)
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

## 4. `secrets-core` (shared library)

- [x] 4.1 `SecretUri` parser and typed representation (`uri.rs`)
- [x] 4.2 Data model: `Vault` / `Item` / `FieldMeta` / `FieldKind`
      (`model.rs`)
- [x] 4.3 `Backend` trait (`backend.rs`)
- [x] 4.4 `Resolver` (`resolver.rs`)
- [x] 4.5 Shared D-Bus interface definitions (`Manager` proxy trait,
      `ManagerError`) reusable by `secretsd` and `secrets-cli` (`dbus.rs`)
- [x] 4.6 Error types (`CoreError`), mapped to D-Bus error names at the
      daemon boundary (`error.rs`, `dbus.rs`)
- [x] 4.7 Unit tests: URI parsing, validation, escaping, resolution (27
      tests)

## 5. `secretsd` (daemon)

- [x] 5.1 D-Bus service bootstrap (`zbus::blocking`, `main.rs`)
- [x] 5.2 `org.secrets.Manager`: Get / Resolve / List / Lock / Unlock /
      Status (`manager.rs`)
- [x] 5.3 Secret Service compat: Service / Collection / Item / Session /
      Prompt, plain algorithm (`secret_service/`)
- [x] 5.4 Session & lock state machine (Locked / Unlocked) (`state.rs`)
- [x] 5.5 Local backend implementation: encrypted file store, Argon2id +
      AES-256-GCM, first-run demo seeding (`backend/local.rs`, `crypto.rs`)
- [x] 5.6 SSH agent (`ssh-agent-lib`); identities unavailable while locked
      (`ssh_agent.rs`)
- [ ] 5.7 Daemon integration tests (automated, in-process D-Bus) — covered
      so far only by a manual end-to-end pass over a private session bus
      (`dbus-run-session`); see §9.4

## 6. `secrets-cli`

- [x] 6.1 Command structure: `list` / `get` / `resolve` / `lock` /
      `unlock` / `status` (`cli.rs`, `lib.rs`)
- [x] 6.2 Stub future commands: `inject` / `run` / `totp` (clap surface
      only, `CliError::NotYetImplemented`)
- [x] 6.3 D-Bus client wiring — thin, no local vault/session state
      (`client.rs`)
- [x] 6.4 Interactive prompts via `demand` (unlock passphrase, masked)
- [x] 6.5 Config loading: `~/.config/secrets/config.toml`, XDG, `toml`
      crate (`config.rs`)
- [ ] 6.6 CLI integration tests (`assert_cmd`, against a test daemon) — dev
      dependency present, not yet written; see §9.5

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
      `secrets_core::secret_value::tests`) — not yet extended to
      `secretsd`/`secrets-cli`'s own log output specifically
- [x] 8.3 Memory hygiene: `SecretValue`/`VaultKey` are
      `Zeroize`/`ZeroizeOnDrop`; documented `SIGKILL`/abort limitation in
      `docs/security.md`

## 9. Testing & Quality

- [x] 9.1 URI parser test suite (27 tests, `secrets-core`)
- [x] 9.2 Locked vs. unlocked behavior tests (`backend/local.rs` unit
      tests, plus the manual end-to-end pass in §9.4)
- [x] 9.3 Error-mapping tests (`CoreError` → `ManagerError`,
      `secrets_core::dbus::tests`)
- [ ] 9.4 D-Bus integration tests, automated — verified manually instead:
      a full `secrets status` → `unlock` → `list` → `get` →
      `get` (`NotFound`) → `lock` → `get` (`VaultLocked`) run against a
      real `secretsd` over a private `dbus-run-session` bus, plus
      `ssh-add -L` before and after lock, all passing. Automating this
      (spawn `secretsd`, drive it via `Client`) is the next step.
- [ ] 9.5 CLI-to-daemon integration tests (automated) — see §9.4; the
      manual run exercised every MVP CLI command already.
- [x] 9.6 "no secret in error/log" regression tests — see §8.2

## 10. CI / Release

- [x] 10.1 Confirm `rust.tpl` CI matrix covers the workspace layout —
      required trimming the test job to Linux only (§1.2); `mise run ci`
      passes end to end.
- [x] 10.2 Release targets restricted to Linux (gnu + musl, x86_64 +
      aarch64)

## 11. Future clients (documentation only for the MVP)

- [x] 11.1 GD Secrets boundary doc (`docs/architecture/external-clients.md`)
- [x] 11.2 `secrets-tui` / browser extensions native messaging boundary doc
      (`docs/architecture/external-clients.md`)
