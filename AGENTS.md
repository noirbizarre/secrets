# AGENTS.md

Notes for anyone — human or otherwise — changing this repository.

## What this project is

Local-first secret broker and secret manager for Linux desktops.

`secretsd` is the one process that owns the secret store, session/lock
state and access control. Every client — `secrets` (this repo, via
`secrets-client`), and eventually separately maintained clients such as GD
Secrets, `secrets-tui`, and browser extensions — is a thin D-Bus client
with no vault or session state of its own. **`secret://` is the resource
reference; D-Bus is the transport** — do not conflate the two, and do not
add a second IPC mechanism (see `docs/adr/001-dbus-as-the-ipc-mechanism.md`).
This is not a password-manager UI: it is the plumbing other tools use to
reach one. See `docs/architecture/overview.md` before proposing a change
that would blur any of these boundaries.

## Non-negotiable invariants

Each of these should be enforced by a hook or a test. An invariant nothing
checks is a comment, and it will be violated.

1. **A `CoreError`/`ManagerError` never contains a secret's value, only
   names and descriptions** — enforced by
   `secrets_core::resolver::tests::resolving_an_unknown_field_reports_not_found_without_the_value`
   and `secrets_core::dbus::tests`.
2. **`secrets-cli` holds no vault or session state** — every command in
   `crates/secrets-cli/src/lib.rs` goes through `secrets_client::SecretsClient`
   (aliased `Client` there), never reads a vault file. See ADR-010.
3. **Locking is daemon-wide and lives in exactly one place**
   (`secretsd::state::DaemonState`) — every interface (`org.secrets.Manager`,
   the Secret Service objects, the SSH agent) reads the same
   `is_unlocked()`, never its own copy. See ADR-009.
4. **`SecretValue`/`VaultKey` are `Zeroize`/`ZeroizeOnDrop`** — a plaintext
   value's lifetime is bounded by its owner's scope, not left to the
   allocator. See `docs/security.md`.

## Layout

A Cargo workspace: `Cargo.toml` at the root is a virtual manifest — no code of
its own — and each member crate lives under its own directory with its own
`Cargo.toml` and `src/`.

## Style

**Every non-obvious line carries a comment saying why.** Not what — the code
says what. Ideally naming the failure it prevents. A comment that restates the
code is worse than none.

**Errors are typed and actionable.** `thiserror` for the library, `miette` at
the binary edge. A diagnostic must carry the two things the user does not
already know: what specifically failed, and what to do about it. Diagnostic
codes are `secrets::<module>::<kind>`, and a code is a public identifier
users grep for — renaming one is a breaking change.

**Test names are sentences.** `an_unchanged_input_produces_no_output`, not
`test_run_2`. The name should say what would be broken if it failed.

## Commits

Conventional Commits, enforced by commitlint on `commit-msg`. The type becomes a
changelog heading, so choose it as if someone will read it in release notes —
because they will.

## Releases

Driven by gh-ship. Never bump a version or push a tag by hand: `cliff.toml`
derives the version from the commit history, `prepare-release` applies it, and
`.github/ship.yml` is the contract between them. See CONTRIBUTING.md.

## Before you push

```sh
mise run ci
```

Formatting, Clippy, spelling, workflow and Markdown linting, tests and the documentation build. Same as CI.

## This repository is generated from a template

The toolchain, hooks, CI and release workflows come from
[rust.tpl](https://github.com/noirbizarre/rust.tpl) and are updated with
`git tpl update`. Files carrying template-owned content end with a
`# --- project-specific ---` marker: add below it, never above.

Changing template-owned content here fixes it in one repository. Changing it in
the template fixes it in all of them — prefer that.
