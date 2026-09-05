//! The `secrets` binary.

#![allow(clippy::result_large_err)]

use std::process::ExitCode;

use clap::Parser;
use secrets_cli::cli::Cli;

fn main() -> ExitCode {
    let args = Cli::parse();

    match secrets_cli::run(args.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Rendered here rather than returned as `miette::Result`, so
            // the exit code is chosen explicitly instead of inherited from
            // whatever the report wrapper decides.
            eprintln!("{:?}", miette::Report::new(error));
            ExitCode::FAILURE
        }
    }
}
