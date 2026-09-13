# ADR-014: `secrets get`'s output modes and terminal disclosure refusal

## Status

Accepted

## Context

`secrets get` printed a fetched value with a bare `println!`, unconditionally,
regardless of where stdout pointed — a pipe into another program, a redirect
to a file, or a real terminal a human is looking at. That is exactly right
for the first two; for the third, it means the one command that ever prints
secret material does so identically whether the caller is a script or a
person sitting at a terminal that a colleague, a screen share, or a
terminal-multiplexer's scrollback/logging feature might also be looking at.
Issue #5 asked for this to be made explicit: a default that is safe by
construction, plus deliberate, named ways to opt back into seeing (or
otherwise handling) the value.

Separately, `list`, `status` and `resolve` only ever print metadata — vault
and item names, lock state, a canonicalised URI — which
[`docs/security.md`](../security.md) already treats as not secret material
(readable even while locked, per
[ADR-009](009-session-and-lock-state-machine.md)). They needed no new
disclosure rule, only a second, script-friendly shape alongside the plain
one already there.

## Decision

1. **`secrets get`** gains three mutually exclusive flags: `--raw`,
   `--json`, `--clipboard` (clap `conflicts_with_all` between them, so at
   most one is ever set).
   - **No flag** (the default): if stdout is a real terminal
     (`std::io::stdout().is_terminal()` — stable `std`, no new
     dependency), refuse with a new named error,
     `CliError::RefusedTerminalOutput`
     (`secrets::cli::refused_terminal_output`), whose `help` names all
     three flags below as explicit alternatives. If stdout is not a
     terminal (piped or redirected — the common scripted case, and what
     every existing end-to-end test for `get` already exercises),
     behave exactly as before: print the bare value and a trailing
     newline, nothing else.
   - **`--raw`**: print the bare value and a trailing newline,
     unconditionally — bypasses the terminal check, because the flag
     itself is the deliberate ask the default is guarding against
     forgetting to make.
   - **`--json`**: print `{"uri": "<canonical-uri>", "value": "<value>"}`
     as one line, unconditionally, for scripts that want the queried URI
     alongside its value without re-parsing plain stdout.
   - **`--clipboard`**: never prints the value. Copies it to the OS
     clipboard via [`arboard`](https://docs.rs/arboard) and prints
     `copied secret to clipboard` to stdout instead. **No auto-clear
     timer** in this iteration — the value stays on the clipboard until
     something else overwrites it or the session ends; see "Known
     limitations" below.
   - Mode selection is a pure function,
     `secrets_cli::output::resolve_get_mode(raw, json, clipboard,
     stdout_is_terminal) -> Result<GetMode, CliError>`, so the
     refuse-on-a-terminal rule is unit-tested directly. Exercising the
     refusal end-to-end would need a PTY-based harness — `assert_cmd`'s
     pipes are never a real TTY — which is out of scope here, the same
     limitation the CLI's masked-passphrase-prompt tests already accept.
   - The string `secrets_client::SecretsClient::get` returns is wrapped
     in `secrets_core::SecretValue` the instant it arrives in
     `secrets-cli`'s `Get` handler, and read back only via
     `expose_secret()` at the single call site each mode needs it —
     extending the existing "boundary type" discipline
     (`secrets_core::secret_value`'s own doc comment) one hop further,
     from `secretsd` through the client into the CLI's own formatting
     code. `secrets-client`'s public `get(&self, uri: &str) ->
     Result<String>` signature is unchanged: it is also the surface a
     future non-CLI Rust client would use (ADR-010), and this decision is
     scoped to the `secrets` CLI, not that library.
2. **`list`, `status`, `resolve`** each gain a `--json` flag, with no
   terminal-awareness at all, since none of them can print a secret value:
   - `status --json` → `{"status": "locked"}` / `{"status": "unlocked"}`
   - `list --json` (no vault) → `{"vaults": ["Infrastructure", "Personal"]}`
   - `list <vault> --json` → `{"vault": "Personal", "items": ["GitHub"]}`
   - `resolve --json` → `{"uri": "secret://Personal/GitHub/password"}`
   Each shape is a small `#[derive(serde::Serialize)]` struct in
   `secrets_cli::output`, not an ad hoc `serde_json::json!` call, so the
   shape is a type, not a string template, and any future consumer has
   something to point at.
3. **Errors stay plain text on stderr, `--json` or not.** `--json` changes
   only the shape of a *successful* result; a failure is still rendered
   through `miette` exactly as today. Every pre-existing `CliError`
   variant (`VaultLocked`, `NotFound`, `InvalidUri`, `PermissionDenied`,
   `InvalidOperation`, `BackendUnavailable`,
   `BackendRequiresAuthentication`) already covers "locked, missing,
   invalid" from the issue's scope; this decision adds exactly two more:
   `RefusedTerminalOutput` (above) and `ClipboardUnavailable(String)`
   (`secrets::cli::clipboard_unavailable`, when no clipboard/display is
   reachable — e.g. a headless session).
4. **Which D-Bus surface each command uses is unchanged and undocumented
   nowhere new**: every read command this ADR touches
   (`status`/`list`/`resolve`/`get`) already goes through
   `org.secrets.Manager`, the `org.secrets.*` extension namespace
   (ADR-005, ADR-013) — nothing here moves any command onto or off of the
   standard Secret Service interfaces. [`docs/dbus/README.md`](../dbus/README.md)
   gets a short table restating this mapping from the CLI's own command
   names, for a reader who only looks at `secrets --help` and never opens
   `docs/dbus/secrets-manager.md`.

## Consequences

- Running `secrets get secret://Personal/GitHub/password` directly at a
  shell prompt now fails by default, with a message naming the three ways
  to proceed — a behaviour change from before this ADR, but the one the
  issue asked for.
- Every script or pipeline that already redirects or pipes `secrets get`'s
  output (`secrets get ... | xclip`, `SECRET=$(secrets get ...)`, ...) is
  unaffected: stdout is not a terminal in either case, so the default
  still prints the bare value exactly as before.
- `secrets get --clipboard` leaves the value on the clipboard with no
  expiry. A future auto-clear (a detached timer process, or a
  foreground delay before the command returns) is deferred, not designed
  away — tracked as a known limitation in `docs/security.md` rather than
  a silent gap.
- `arboard` is a new compiled dependency of `secrets-cli` only (X11 via
  `x11rb`, also working under XWayland; no external `xclip`/`wl-copy`
  binary required at runtime). Its actual clipboard I/O is not exercised
  by the end-to-end suite, which runs headless — only `resolve_get_mode`'s
  branch that selects `GetMode::Clipboard` is unit-tested; the clipboard
  write itself needs manual verification (`wl-paste`/`xclip -o` after
  running the command on a real desktop session).
- `secrets-cli` gains a direct dependency on `secrets-core` (previously
  only transitive, through `secrets-client`) to use `SecretValue` — an
  instance of ADR-010's "used only for shared types", not a step toward
  resolving secrets directly from the CLI.
