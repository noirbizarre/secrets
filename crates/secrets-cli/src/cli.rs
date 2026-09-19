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
        /// The vault to list items from. Omit to list vault names
        /// instead. Accepts the same optional `"<store>@"` prefix as a
        /// `secret://` reference (ADR-018) — `--store` is only
        /// meaningful in the no-`vault` (vault-listing) mode below.
        vault: Option<String>,

        /// Only list vaults from this store, and print them unqualified
        /// (ADR-018). Ignored when `vault` is given — that argument's
        /// own optional `"<store>@"` prefix already selects a store, if
        /// any.
        #[arg(long)]
        store: Option<String>,

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

    /// Lock the store, or one specific store with `--store`.
    Lock {
        /// Lock only this store (ADR-018). Omit to lock every configured
        /// store.
        #[arg(long)]
        store: Option<String>,
    },

    /// Unlock the store, or one specific store with `--store`, prompting
    /// for the passphrase interactively.
    Unlock {
        /// Unlock only this store (ADR-018). Omit for the daemon-wide
        /// composite: a no-op with no real passphrase lock configured,
        /// direct with exactly one, and an actionable error naming every
        /// candidate with more than one.
        #[arg(long)]
        store: Option<String>,
    },

    /// Show whether the store is locked or unlocked, or one specific
    /// store's own status with `--store`.
    Status {
        /// Show only this store's own status (ADR-018). Omit for the
        /// daemon-wide composite.
        #[arg(long)]
        store: Option<String>,

        /// Print as a JSON object instead of a bare line.
        #[arg(long)]
        json: bool,
    },

    /// List every configured store and whether it is locked (ADR-018).
    Stores {
        /// Print as a JSON array instead of one `<id>: <status>` line
        /// per store.
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
