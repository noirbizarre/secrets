//! `secrets-cli` — the `secrets` command's library surface.
//!
//! Everything here is a thin wrapper over
//! [`secrets_client::SecretsClient`]: no vault or session state is held or
//! duplicated locally. `secretsd` is the sole authority; this crate only
//! parses arguments, calls the client library, and formats responses. See
//! ADR-010.
#![warn(missing_docs)]
// See secrets-core's lib.rs for why: a diagnostic that says what to do
// costs more bytes than clippy's threshold, and is worth it.
#![allow(clippy::result_large_err)]

pub mod cli;
pub mod config;
pub mod error;
pub mod output;

use std::io::IsTerminal;

use cli::Command;
use error::{CliError, Result};
use output::{
    GetMode, GetPayload, ItemsPayload, ResolvePayload, ShowPayload, StatusPayload, VaultsPayload,
};
use secrets_client::SecretsClient as Client;

/// Run a parsed subcommand to completion, printing its output.
///
/// # Errors
///
/// Returns [`CliError`] if the daemon cannot be reached, rejects the
/// operation, or the command is one of the not-yet-implemented future
/// commands (`inject`, `run`, `totp`).
pub fn run(command: Command) -> Result<()> {
    match command {
        Command::Status { json } => {
            let client = Client::connect()?;
            let status = client.status()?;
            if json {
                print_json(&StatusPayload { status: &status });
            } else {
                println!("{status}");
            }
        }
        Command::Unlock => {
            let client = Client::connect()?;
            let passphrase = prompt_passphrase()?;
            client.unlock(&passphrase)?;
            println!("unlocked");
        }
        Command::Lock => {
            let client = Client::connect()?;
            client.lock()?;
            println!("locked");
        }
        Command::List { vault, json } => {
            let client = Client::connect()?;
            match vault {
                Some(vault) => {
                    let items = client.list_items(&vault)?;
                    if json {
                        print_json(&ItemsPayload {
                            vault: &vault,
                            items: &items,
                        });
                    } else {
                        for item in items {
                            println!("{item}");
                        }
                    }
                }
                None => {
                    let vaults = client.list_vaults()?;
                    if json {
                        print_json(&VaultsPayload { vaults: &vaults });
                    } else {
                        for vault in vaults {
                            println!("{vault}");
                        }
                    }
                }
            }
        }
        Command::Get {
            uri,
            raw,
            json,
            clipboard,
        } => {
            // Decided before the daemon is even called: a refusal costs
            // nothing extra this way, and never depends on the value
            // itself, only on what the user asked for and where stdout
            // goes — see ADR-014.
            let mode =
                output::resolve_get_mode(raw, json, clipboard, std::io::stdout().is_terminal())?;
            let client = Client::connect()?;
            // secrets-client wraps this in `SecretValue` the instant it
            // arrives from the wire: from here on the plaintext is
            // reachable only through `expose_secret()`, one call below
            // per `mode` — never through a stray `{:?}` or `Serialize`.
            let value = client.get(&uri)?;
            match mode {
                GetMode::Raw => println!("{}", value.expose_secret()),
                GetMode::Json => print_json(&GetPayload {
                    uri: &uri,
                    value: value.expose_secret(),
                }),
                GetMode::Clipboard => {
                    arboard::Clipboard::new()
                        .and_then(|mut clipboard| clipboard.set_text(value.expose_secret()))
                        .map_err(|error| CliError::ClipboardUnavailable(error.to_string()))?;
                    println!("copied secret to clipboard");
                }
            }
        }
        Command::Resolve { uri, json } => {
            let client = Client::connect()?;
            let resolved = client.resolve(&uri)?;
            if json {
                print_json(&ResolvePayload { uri: &resolved });
            } else {
                println!("{resolved}");
            }
        }
        Command::Show { uri, json } => {
            let client = Client::connect()?;
            // No `SecretValue` here to expose: a secret-shaped field's
            // `value` is already the fixed obfuscated placeholder by the
            // time it arrives — substituted server-side before it ever
            // crossed the bus (see `secrets_core::dbus::show_item`).
            let fields = client.show_item(&uri)?;
            if json {
                print_json(&ShowPayload {
                    uri: &uri,
                    fields: &fields,
                });
            } else {
                for field in &fields {
                    println!("{} ({}): {}", field.name, field.kind, field.value);
                }
            }
        }
        Command::Inject(_) => return Err(CliError::NotYetImplemented { command: "inject" }),
        Command::Run(_) => return Err(CliError::NotYetImplemented { command: "run" }),
        Command::Totp { .. } => return Err(CliError::NotYetImplemented { command: "totp" }),
    }
    Ok(())
}

/// Serialize and print one line of JSON.
///
/// Every payload type here is a small, non-secret-aware struct built by
/// its call site (see `output.rs`), so this has nothing to redact: the
/// decision to expose a value already happened before this is called.
fn print_json<T: serde::Serialize>(payload: &T) {
    // These payload shapes are plain structs of strings/slices — there is
    // no failure mode for `serde_json` to hit here.
    println!(
        "{}",
        serde_json::to_string(payload).expect("output payloads always serialize")
    );
}

/// Prompt for the unlock passphrase interactively, masked as it is typed.
fn prompt_passphrase() -> Result<String> {
    demand::Input::new("Passphrase")
        .password(true)
        .prompt("> ")
        .run()
        .map_err(|_| CliError::PromptCancelled)
}
