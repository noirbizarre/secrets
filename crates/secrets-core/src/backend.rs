//! The contract every secret store implementation must satisfy.
//!
//! Kept deliberately small: three read operations, nothing about how a
//! backend authenticates, stores, or transports its data. A backend that
//! wants to expose more (write support, sync, sharing) does so behind its
//! own configuration — this trait only carries what the daemon needs to
//! resolve a `secret://` reference.

use crate::error::Result;
use crate::model::{Item, Vault};
use crate::secret_value::SecretValue;
use crate::uri::ItemPath;

/// A source of vaults, items and field values.
///
/// Implementations: the MVP's local encrypted-file store today; Vaultwarden,
/// Bitwarden, 1Password, `pass`, `gopass` and `passage` are the roadmap (see
/// `PLAN.md` §7 and `docs/architecture/overview.md`).
///
/// `Send + Sync` because `secretsd` holds the active backend behind a
/// `Mutex`/`Arc` shared across D-Bus method calls, which may be dispatched
/// from different tasks.
pub trait Backend: Send + Sync {
    /// List the vaults this backend currently exposes.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::CoreError::BackendUnavailable`] if the
    /// backend cannot be reached at all (not to be confused with "locked",
    /// which the daemon's session state — not the backend — is
    /// authoritative over).
    fn list_vaults(&self) -> Result<Vec<Vault>>;

    /// List the items within a vault, with their field metadata but not
    /// field values.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::CoreError::NotFound`] if `vault` does not
    /// exist, or [`crate::error::CoreError::BackendUnavailable`] on a
    /// backend-level failure.
    fn list_items(&self, vault: &str) -> Result<Vec<Item>>;

    /// Read a single field's value.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::CoreError::NotFound`] if the vault, item or
    /// field does not exist, or
    /// [`crate::error::CoreError::BackendUnavailable`] on a backend-level
    /// failure.
    fn get_field(&self, vault: &str, item: &ItemPath, field: &str) -> Result<SecretValue>;
}
