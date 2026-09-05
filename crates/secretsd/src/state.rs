//! The daemon's shared, authoritative state.
//!
//! One [`DaemonState`], held behind an `Arc` and shared by every D-Bus
//! interface (`org.secrets.Manager`, the Secret Service compatibility
//! objects) and the SSH agent. There is exactly one source of truth for
//! "are we locked", so the three surfaces can never disagree.

use std::sync::Arc;

use secrets_core::{Backend, CoreError, Item, Resolver, SecretUri, SecretValue, Vault};

use crate::backend::local::LocalBackend;
use crate::error::Result;

/// Shared daemon state.
///
/// `backend` is the read path (`list_vaults`/`list_items`/resolution) —
/// held as `Arc<dyn Backend>` so it works against any backend, per
/// ADR-0008. `local` is kept alongside it, concretely typed, purely for
/// lock/unlock/status: those three operations are not part of the
/// `Backend` trait (they vary too much between backend shapes to force
/// into one signature yet), and the local backend remains the only
/// implementation of them for now. See ADR-0011 for the follow-up that
/// generalizes an *external* backend's own authentication/session state
/// — distinct from this daemon-wide lock.
pub struct DaemonState {
    backend: Arc<dyn Backend>,
    local: Arc<LocalBackend>,
}

impl DaemonState {
    /// Wrap a backend (for resolution) and the local backend (for
    /// lock/unlock) as shared daemon state.
    ///
    /// Two parameters rather than one because they answer different
    /// questions today — see the struct's own doc comment. Callers other
    /// than [`open_default_state`] will typically pass the same
    /// concrete backend upcast twice, as it does.
    #[must_use]
    pub fn new(backend: Arc<dyn Backend>, local: Arc<LocalBackend>) -> Self {
        Self { backend, local }
    }

    /// `"locked"` or `"unlocked"`, matching
    /// [`secrets_core::dbus::STATUS_LOCKED`] /
    /// [`secrets_core::dbus::STATUS_UNLOCKED`].
    #[must_use]
    pub fn status(&self) -> &'static str {
        if self.local.is_unlocked() {
            secrets_core::dbus::STATUS_UNLOCKED
        } else {
            secrets_core::dbus::STATUS_LOCKED
        }
    }

    /// Whether the store is currently unlocked.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.local.is_unlocked()
    }

    /// Unlock (or, on first run, initialize) the store.
    ///
    /// # Errors
    ///
    /// See [`LocalBackend::unlock`].
    pub fn unlock(&self, passphrase: &str) -> Result<()> {
        self.local.unlock(passphrase)
    }

    /// Lock the store, dropping the derived key from memory.
    pub fn lock(&self) {
        self.local.lock();
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
    /// Deliberately distinct from [`secrets_core::Resolver::resolve`],
    /// which *does* return the value: this is an existence check only,
    /// exposed over D-Bus as `Manager.Resolve` (see
    /// `docs/dbus/secrets-manager.md`). A backend's own native reference
    /// format (e.g. a future `op://...` internal encoding) never appears
    /// in this method's output or errors — only the `secret://` form the
    /// caller supplied.
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

    /// Access the underlying backend directly — used by the SSH agent and
    /// the Secret Service compatibility layer, which need to enumerate and
    /// decrypt fields themselves rather than through a single `secret://`
    /// URI. Returns the trait object, not the concrete local backend: both
    /// call sites only ever call [`Backend::get_field`].
    #[must_use]
    pub fn backend(&self) -> &Arc<dyn Backend> {
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
    let local = Arc::new(LocalBackend::open(path)?);
    let backend: Arc<dyn Backend> = local.clone();
    Ok(DaemonState::new(backend, local))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    /// Builds a `DaemonState` the same way `open_default_state` does,
    /// against a throwaway vault file, so these tests exercise the exact
    /// `Arc<dyn Backend>` + `Arc<LocalBackend>` wiring production code
    /// uses.
    fn state_over_fresh_vault() -> (tempfile::TempDir, DaemonState) {
        let dir = tempdir().unwrap();
        let local = Arc::new(LocalBackend::open(dir.path().join("vault.toml")).unwrap());
        let backend: Arc<dyn Backend> = local.clone();
        (dir, DaemonState::new(backend, local))
    }

    #[test]
    fn a_fresh_state_reports_locked_before_unlocking() {
        let (_dir, state) = state_over_fresh_vault();
        assert_eq!(state.status(), secrets_core::dbus::STATUS_LOCKED);
        assert!(!state.is_unlocked());
    }

    #[test]
    fn unlocking_through_daemon_state_reaches_the_backend_trait_object() {
        let (_dir, state) = state_over_fresh_vault();
        state.unlock("test passphrase").unwrap();
        assert_eq!(state.status(), secrets_core::dbus::STATUS_UNLOCKED);

        // Exercises the `Arc<dyn Backend>` path end to end, not just the
        // concrete `LocalBackend` (already covered by
        // `backend::local::tests`).
        let vaults = state.list_vaults().unwrap();
        assert!(vaults.iter().any(|v| v.name == "Personal"));

        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        let value = state.get(&uri).unwrap();
        assert_eq!(value.expose_secret(), "correct horse battery staple");
    }

    #[test]
    fn resolve_validates_without_returning_the_value() {
        let (_dir, state) = state_over_fresh_vault();
        state.unlock("test passphrase").unwrap();

        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        // `resolve` succeeds but its `Ok` carries no value to expose.
        state.resolve(&uri).unwrap();

        let missing = SecretUri::parse("secret://Personal/GitHub/does-not-exist").unwrap();
        let error = state.resolve(&missing).unwrap_err();
        assert!(matches!(error, CoreError::NotFound { .. }));
    }

    #[test]
    fn locked_state_rejects_get_through_the_backend_trait_object() {
        let (_dir, state) = state_over_fresh_vault();
        // Never unlocked: the demo vault does not exist on disk yet either.
        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        let error = state.get(&uri).unwrap_err();
        assert!(matches!(error, CoreError::VaultLocked { .. }));
    }
}
