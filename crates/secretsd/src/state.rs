//! The daemon's shared, authoritative state.
//!
//! One [`DaemonState`], held behind an `Arc` and shared by every D-Bus
//! interface (`org.secrets.Manager`, the Secret Service compatibility
//! objects) and the SSH agent. There is exactly one source of truth for
//! "are we locked", so the three surfaces can never disagree.

use std::sync::Arc;

use secrets_core::{CoreError, Item, Resolver, SecretUri, SecretValue, Vault};

use crate::backend::local::LocalBackend;
use crate::error::Result;

/// Shared daemon state: today, exactly the one backend the MVP ships.
///
/// Holding `Arc<LocalBackend>` concretely — rather than `Arc<dyn Backend>`
/// — is a deliberate MVP simplification: `LocalBackend` is also the only
/// implementation of the (not-yet-defined) session/unlock contract a
/// second, differently-authenticated backend (Vaultwarden's OAuth, say)
/// would need. See ADR-0008.
pub struct DaemonState {
    backend: Arc<LocalBackend>,
}

impl DaemonState {
    /// Wrap a backend as shared daemon state.
    #[must_use]
    pub fn new(backend: Arc<LocalBackend>) -> Self {
        Self { backend }
    }

    /// `"locked"` or `"unlocked"`, matching
    /// [`secrets_core::dbus::STATUS_LOCKED`] /
    /// [`secrets_core::dbus::STATUS_UNLOCKED`].
    #[must_use]
    pub fn status(&self) -> &'static str {
        if self.backend.is_unlocked() {
            secrets_core::dbus::STATUS_UNLOCKED
        } else {
            secrets_core::dbus::STATUS_LOCKED
        }
    }

    /// Whether the store is currently unlocked.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.backend.is_unlocked()
    }

    /// Unlock (or, on first run, initialize) the store.
    ///
    /// # Errors
    ///
    /// See [`LocalBackend::unlock`].
    pub fn unlock(&self, passphrase: &str) -> Result<()> {
        self.backend.unlock(passphrase)
    }

    /// Lock the store, dropping the derived key from memory.
    pub fn lock(&self) {
        self.backend.lock();
    }

    /// List every vault name. Available regardless of lock state.
    ///
    /// # Errors
    ///
    /// Propagates the backend's error, if any.
    pub fn list_vaults(&self) -> std::result::Result<Vec<Vault>, CoreError> {
        Resolver::new(self.backend.as_ref()).list_vaults()
    }

    /// List a vault's items, with field metadata but not values. Available
    /// regardless of lock state.
    ///
    /// # Errors
    ///
    /// Propagates the backend's error, if any.
    pub fn list_items(&self, vault: &str) -> std::result::Result<Vec<Item>, CoreError> {
        Resolver::new(self.backend.as_ref()).list_items(vault)
    }

    /// Validate that a `secret://` reference names an existing vault, item
    /// and field, without reading the field's value.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::VaultLocked`] if the store is locked, or
    /// [`CoreError::NotFound`] if the reference does not resolve.
    pub fn resolve(&self, uri: &SecretUri) -> std::result::Result<(), CoreError> {
        if !self.is_unlocked() {
            return Err(CoreError::VaultLocked {
                vault: uri.vault().to_string(),
            });
        }
        let items = self.list_items(uri.vault())?;
        let exists = items.iter().any(|item| {
            item.path.segments() == uri.item().segments() && item.has_field(uri.field())
        });
        if exists {
            Ok(())
        } else {
            Err(CoreError::NotFound {
                vault: uri.vault().to_string(),
                item: uri.item().to_string(),
                field: uri.field().to_string(),
            })
        }
    }

    /// Fetch a field's value.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::VaultLocked`] if the store is locked, or
    /// propagates the backend's error otherwise.
    pub fn get(&self, uri: &SecretUri) -> std::result::Result<SecretValue, CoreError> {
        if !self.is_unlocked() {
            return Err(CoreError::VaultLocked {
                vault: uri.vault().to_string(),
            });
        }
        Resolver::new(self.backend.as_ref()).resolve(uri)
    }

    /// Access the underlying backend directly — used by the SSH agent,
    /// which needs to enumerate and decrypt `SshKey` fields itself rather
    /// than through a `secret://` URI.
    #[must_use]
    pub fn backend(&self) -> &Arc<LocalBackend> {
        &self.backend
    }
}

/// Open the backend at the standard XDG data path.
///
/// # Errors
///
/// Returns [`DaemonError`] if the path cannot be resolved or the existing
/// vault file cannot be parsed.
pub fn open_default_state() -> Result<DaemonState> {
    let path = crate::paths::vault_file()?;
    let backend = LocalBackend::open(path)?;
    Ok(DaemonState::new(Arc::new(backend)))
}
