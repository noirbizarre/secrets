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

use cli::Command;
use error::{CliError, Result};
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
        Command::Status => {
            let client = Client::connect()?;
            println!("{}", client.status()?);
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
        Command::List { vault } => {
            let client = Client::connect()?;
            match vault {
                Some(vault) => {
                    for item in client.list_items(&vault)? {
                        println!("{item}");
                    }
                }
                None => {
                    for vault in client.list_vaults()? {
                        println!("{vault}");
                    }
                }
            }
        }
        Command::Get { uri } => {
            let client = Client::connect()?;
            // The one place a secret's plaintext is deliberately printed:
            // the user explicitly asked for it via `secrets get`. Nowhere
            // else in this crate prints a value.
            println!("{}", client.get(&uri)?);
        }
        Command::Resolve { uri } => {
            let client = Client::connect()?;
            println!("{}", client.resolve(&uri)?);
        }
        Command::Inject(_) => return Err(CliError::NotYetImplemented { command: "inject" }),
        Command::Run(_) => return Err(CliError::NotYetImplemented { command: "run" }),
        Command::Totp { .. } => return Err(CliError::NotYetImplemented { command: "totp" }),
    }
    Ok(())
}

/// Prompt for the unlock passphrase interactively, masked as it is typed.
fn prompt_passphrase() -> Result<String> {
    demand::Input::new("Passphrase")
        .password(true)
        .prompt("> ")
        .run()
        .map_err(|_| CliError::PromptCancelled)
}
