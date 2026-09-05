//! Argument types only.
//!
//! No behaviour lives here — parsing is one concern, doing the work
//! (`lib.rs`) is another. `secrets inject`/`run`/`totp` are declared with
//! their eventual shape so `--help` and scripts can already depend on the
//! surface, but each currently returns
//! [`crate::error::CliError::NotYetImplemented`].

use clap::{Args, Parser, Subcommand};

/// The Secrets CLI: a thin D-Bus client over `secretsd`.
#[derive(Debug, Parser)]
#[command(name = "secrets", version, about, long_about = None)]
pub struct Cli {
    /// Increase verbosity. Repeat for more.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// The subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// List vaults, or the items within one.
    List {
        /// The vault to list items from. Omit to list vault names instead.
        vault: Option<String>,
    },

    /// Fetch a secret's value.
    Get {
        /// A `secret://<vault>/<item>/<field>` reference.
        uri: String,
    },

    /// Validate and canonicalise a `secret://` reference, without printing
    /// its value.
    Resolve {
        /// A `secret://<vault>/<item>/<field>` reference.
        uri: String,
    },

    /// Lock the store.
    Lock,

    /// Unlock the store, prompting for the passphrase interactively.
    Unlock,

    /// Show whether the store is locked or unlocked.
    Status,

    /// Inject secrets into a template. Not yet implemented.
    Inject(InjectArgs),

    /// Run a command with secrets injected into its environment. Not yet
    /// implemented.
    Run(RunArgs),

    /// Generate a TOTP code for a `secret://` reference. Not yet
    /// implemented.
    Totp {
        /// A `secret://<vault>/<item>/<field>` reference to a TOTP field.
        uri: String,
    },
}

/// Arguments for the future `secrets inject` command.
#[derive(Debug, Args)]
pub struct InjectArgs {
    /// A template file containing `secret://` references to substitute.
    pub template: std::path::PathBuf,
}

/// Arguments for the future `secrets run` command.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Environment variables to set from `secret://` references, as
    /// `NAME=secret://...` pairs.
    #[arg(short, long = "env", value_name = "NAME=secret://...")]
    pub env: Vec<String>,

    /// The command to run, with secrets injected into its environment.
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    // Catches derive mistakes that would otherwise only surface as a panic
    // the first time a user runs the binary.
    #[test]
    fn the_command_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
