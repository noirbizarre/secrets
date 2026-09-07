//! The public Rust client library for the Secrets D-Bus protocol.
//!
//! Applications that want to read from `secretsd` — the `secrets` CLI
//! today, and eventually other Rust applications (a GTK app, an `Over`
//! integration, ...) — depend on this crate instead of learning `zbus`,
//! D-Bus object paths, interface names, error mapping, or daemon
//! discovery themselves.
//!
//! `secrets-client` is a client of the `org.secrets.Manager` **protocol**,
//! not an abstraction over `secretsd`'s implementation: it holds no vault
//! or session state of its own (the same rule
//! [ADR-010](https://github.com/noirbizarre/secrets/blob/main/docs/adr/010-cli-as-thin-dbus-client.md)
//! already applies to the CLI), and it does not depend on `secretsd`. It
//! does not replace or redefine D-Bus either — it is an ergonomic Rust
//! binding for the same contract documented in `docs/dbus/`; a non-Rust
//! application can speak that protocol directly instead.
//!
//! ```no_run
//! # fn main() -> Result<(), secrets_client::Error> {
//! let client = secrets_client::SecretsClient::connect()?;
//! let value = client.get("secret://Personal/GitHub/password")?;
//! println!("{value}");
//! # Ok(())
//! # }
//! ```
//!
//! This first version is deliberately small and **blocking**: it mirrors
//! `secrets_core::dbus::ManagerProxyBlocking` directly (see
//! [ADR-005](https://github.com/noirbizarre/secrets/blob/main/docs/adr/005-native-manager-api-design.md)
//! for why the underlying interface generates both a blocking and an
//! async proxy from one declaration) rather than requiring callers to
//! bring an async runtime. An async variant can be added later as an
//! addition, not a breaking change, once a concrete consumer needs one.
#![warn(missing_docs)]
// `Error` (an alias for `secrets_core::dbus::ManagerError`) carries enough
// context to be actionable, which puts it past clippy's 128-byte `Result`
// threshold. See the same allow in secrets-core, secretsd and secrets-cli.
#![allow(clippy::result_large_err)]

mod client;

pub use client::SecretsClient;

/// This crate's error type.
///
/// Re-exported from [`secrets_core::dbus::ManagerError`] rather than
/// duplicated: it is the same named-error mapping `secretsd` implements
/// against, so a match on a specific variant here (`Error::VaultLocked`,
/// say) is a match on the exact same `org.secrets.Error.*` D-Bus error
/// name documented in `docs/dbus/secrets-manager.md`.
pub use secrets_core::dbus::ManagerError as Error;

/// This crate's result alias.
pub type Result<T> = std::result::Result<T, Error>;
