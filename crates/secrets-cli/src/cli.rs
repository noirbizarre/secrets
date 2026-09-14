//! Argument types only.
//!
//! No behaviour lives here — parsing is one concern, doing the work
//! (`lib.rs`) is another. `secrets inject`/`run`/`totp` are declared with
//! their eventual shape so `--help` and scripts can already depend on the
//! surface, but each currently returns
//! [`crate::error::CliError::NotYetImplemented`]. `--verbose` is reserved
//! the same way: parsed today, but not yet wired to any logging output.

use clap::{Args, Parser, Subcommand};

/// The Secrets CLI: a thin D-Bus client over `secretsd`.
#[derive(Debug, Parser)]
#[command(name = "secrets", version, about, long_about = None)]
pub struct Cli {
    /// Increase verbosity. Repeat for more.
    ///
    /// Reserved: accepted and counted, but this crate has no logging
    /// infrastructure yet, so no flag value currently changes any output.
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

        /// Print as a JSON object instead of one name per line.
        #[arg(long)]
        json: bool,
    },

    /// Fetch a secret's value.
    ///
    /// With no flag, prints the bare value when stdout is not a terminal
    /// (the scripted/piped case); refuses when it is, naming the three
    /// flags below as explicit alternatives — see ADR-014.
    Get {
        /// A `secret://<vault>/<item>/<field>` reference.
        uri: String,

        /// Print the bare value, even to a terminal.
        #[arg(long, conflicts_with_all = ["json", "clipboard"])]
        raw: bool,

        /// Print `{"uri": ..., "value": ...}` instead of the bare value.
        #[arg(long, conflicts_with_all = ["raw", "clipboard"])]
        json: bool,

        /// Copy the value to the clipboard instead of printing it. Not
        /// auto-cleared.
        #[arg(long, conflicts_with_all = ["raw", "json"])]
        clipboard: bool,
    },

    /// Validate and canonicalise a `secret://` reference, without printing
    /// its value.
    Resolve {
        /// A `secret://<vault>/<item>/<field>` reference.
        uri: String,

        /// Print as a JSON object instead of a bare line.
        #[arg(long)]
        json: bool,
    },

    /// Show every field an item has: its name, kind, and value if the
    /// kind isn't secret-shaped.
    ///
    /// Fields whose kind is secret-shaped (`password`, `totp`,
    /// `ssh-key`, `private-key`, `note`, any custom field) always show a
    /// fixed placeholder instead of their real value — this command
    /// exists to discover *which* fields an item has, not to read them;
    /// use `get` for that. No terminal-disclosure refusal applies here
    /// (unlike `get`): no real secret material ever reaches this
    /// command.
    Show {
        /// A `secret://<vault>/<item...>` reference — no field segment.
        uri: String,

        /// Print as a JSON array of `{"name", "kind", "value"}` objects
        /// instead of one line per field.
        #[arg(long)]
        json: bool,
    },

    /// Lock the store.
    Lock,

    /// Unlock the store, prompting for the passphrase interactively.
    Unlock,

    /// Show whether the store is locked or unlocked.
    Status {
        /// Print as a JSON object instead of a bare line.
        #[arg(long)]
        json: bool,
    },

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
