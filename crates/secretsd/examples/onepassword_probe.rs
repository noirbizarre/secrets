//! A diagnostic probe: one real, end-to-end round trip against the
//! user's installed 1Password Desktop, confirming (or refuting) the
//! architecture built in Steps 5–7 against the real thing rather than
//! fixtures.
//!
//! A `cargo example`, deliberately — never part of the automated test
//! suite or CI, and never run automatically: `cargo test`/`cargo
//! nextest run` do not execute examples. Run manually, once, with intent:
//!
//! ```text
//! SECRETS_OP_ACCOUNT_NAME="<your account name or UUID>" \
//! SECRETS_OP_TEST_REFERENCE="op://vault/item/field" \
//! cargo run --example onepassword_probe
//! ```
//!
//! Requires 1Password Desktop installed, running, and — per
//! `docs/architecture/1password-integration.md` — Settings > Developer >
//! "Integrate with other apps" enabled.
//!
//! **Never prints a secret value, a session token, or a raw IPC
//! payload** — only the fixed diagnostic lines below, and, on failure,
//! which stage failed and a structural (never value-carrying) error.

use std::time::Duration;

use secretsd::backend::onepassword::ffi::IpcLibrary;
use secretsd::backend::onepassword::ipc::IpcClient;
use secretsd::backend::onepassword::protocol;

const ACCOUNT_NAME_ENV: &str = "SECRETS_OP_ACCOUNT_NAME";
const TEST_REFERENCE_ENV: &str = "SECRETS_OP_TEST_REFERENCE";

/// Generous, not indefinite: the first real call may need a human to
/// click "Approve" in the 1Password Desktop app, but this probe must
/// still exit rather than hang forever if nobody does.
const PROBE_TIMEOUT: Duration = Duration::from_secs(120);

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(stage) => {
            eprintln!("FAILED at: {stage}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Returns `Err(<failing stage, plus a structural reason>)` on any
/// failure — the caller reports it and exits non-zero, no fallback.
fn run() -> Result<(), String> {
    let account_name = std::env::var(ACCOUNT_NAME_ENV)
        .map_err(|_| format!("setup: {ACCOUNT_NAME_ENV} is not set"))?;
    let secret_reference = std::env::var(TEST_REFERENCE_ENV)
        .map_err(|_| format!("setup: {TEST_REFERENCE_ENV} is not set"))?;

    let library = IpcLibrary::load().map_err(|error| format!("1Password IPC library: {error}"))?;
    println!("1Password IPC library: OK");

    let client = IpcClient::with_timeout(library, PROBE_TIMEOUT);
    println!("Client initialization: OK");

    let init_request =
        protocol::init_client_request(&account_name, "secretsd-probe", env!("CARGO_PKG_VERSION"));
    let init_response = client
        .invoke(&init_request)
        .map_err(|error| format!("Desktop authorization (init_client call): {error}"))?;
    let client_id = protocol::parse_client_id(init_response.as_bytes()).map_err(|error| {
        format!("Desktop authorization (parsing init_client response): {error}")
    })?;
    println!("Desktop authorization: OK");

    let resolve_request =
        protocol::resolve_secret_request(&account_name, client_id, &secret_reference);
    let resolve_response = client
        .invoke(&resolve_request)
        .map_err(|error| format!("Secret resolution (invoke call): {error}"))?;
    let secret = protocol::parse_resolved_secret(resolve_response.as_bytes())
        .map_err(|error| format!("Secret resolution (parsing response): {error}"))?;

    if secret.expose_secret().is_empty() {
        return Err("Secret resolution: resolved value was empty".to_string());
    }
    println!("Secret resolution: OK");

    Ok(())
}
