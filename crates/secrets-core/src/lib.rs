//! The domain/core library for the Secrets ecosystem: `secret://` URI
//! parsing, the vault/item/field model, the backend contract, and the
//! shared D-Bus protocol types (names, the `Manager` proxy trait, error
//! mapping).
//!
//! Consumed directly by `secretsd` (which implements [`Backend`] and the
//! `Manager` D-Bus interface over it) and by `secrets-client` (which
//! proxies that same interface for every other Rust application). Nothing
//! in this crate knows a terminal, a GTK window, or `secretsd`'s own
//! implementation details exist — it is domain logic plus the wire-level
//! types every implementation and every client must agree on.
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
// `Result` threshold. See the same allow in secrets-client and
// secrets-cli (secretsd's own DaemonError sits under the threshold, so
// it doesn't need it — yet).
#![allow(clippy::result_large_err)]

pub mod backend;
pub mod dbus;
pub mod error;
pub mod model;
pub mod prompt;
pub mod resolver;
pub mod secret_value;
pub mod store_id;
pub mod uri;

pub use backend::{Backend, BackendSession, BackendStatus};
pub use error::{CoreError, Result};
pub use model::{FieldKind, FieldMeta, Item, Vault};
pub use prompt::{PromptAnswer, PromptKind, PromptOutcome};
pub use resolver::Resolver;
pub use secret_value::SecretValue;
pub use store_id::{StoreId, StoreIdError};
pub use uri::{ItemPath, ItemUri, SecretUri, UriError};
