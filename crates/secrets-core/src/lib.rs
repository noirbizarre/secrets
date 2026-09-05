//! Shared model, `secret://` URI parsing and the backend contract for the
//! Secrets ecosystem.
//!
//! Consumed by both `secretsd` and `secrets-cli` (and, eventually,
//! `secrets-gtk` and `secrets-browser`): nothing in this crate knows a D-Bus
//! connection, a terminal, or a GTK window exists. It is pure domain logic
//! plus the wire-level types every client and the daemon must agree on.
//!
//! ```text
//! secret://...
//!       |
//!       v
//!   uri::SecretUri   (this crate)
//!       |
//!       v
//!   resolver::Resolver   (this crate)
//!       |
//!       v
//!   backend::Backend   (implemented by secretsd)
//! ```
#![warn(missing_docs)]
// `CoreError` carries enough context to be actionable (the point of
// AGENTS.md's rule on diagnostics), which puts it past clippy's 128-byte
// `Result` threshold. See the same allow in secrets-cli and secretsd.
#![allow(clippy::result_large_err)]

pub mod backend;
pub mod dbus;
pub mod error;
pub mod model;
pub mod resolver;
pub mod secret_value;
pub mod uri;

pub use backend::Backend;
pub use error::{CoreError, Result};
pub use model::{FieldKind, FieldMeta, Item, Vault};
pub use resolver::Resolver;
pub use secret_value::SecretValue;
pub use uri::{ItemPath, SecretUri, UriError};
