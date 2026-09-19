//! `secretsd`'s library surface.
//!
//! Split out from the binary (`main.rs`) purely so other compilation
//! units within this crate — currently the `onepassword_probe` example
//! (see `examples/`) — can reach these modules at all: a `cargo example`
//! links against a crate's library target, never a sibling binary's
//! private module tree. `main.rs` itself is a thin wrapper over this
//! library, the same split `secrets-cli` already uses (`secrets_cli`
//! lib + `secrets` bin).
//!
//! See `main.rs` for the full architectural picture (deliberately
//! synchronous, except the SSH agent).

pub mod backend;
pub mod config;
pub mod crypto;
pub mod error;
pub mod manager;
pub mod paths;
pub mod prompt;
pub mod secret_service;
pub mod ssh_agent;
pub mod state;

#[cfg(test)]
pub(crate) mod test_support;
