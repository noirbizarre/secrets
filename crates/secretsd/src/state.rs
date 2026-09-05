//! The daemon's shared, authoritative state.
//!
//! One [`DaemonState`], held behind an `Arc` and shared by every D-Bus
//! interface (`org.secrets.Manager`, the Secret Service compatibility
//! objects) and the SSH agent. There is exactly one source of truth for
//! "are we locked", so the three surfaces can never disagree.

use std::sync::Arc;

use secrets_core::{
    Backend, BackendSession, BackendStatus, CoreError, Item, Resolver, SecretUri, SecretValue,
    Vault,
};

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
/// implementation of them for now.
///
/// `session` is the daemon-wide lock's conceptual opposite number: an
/// *external* backend's own authentication/session state (see
/// [`BackendSession`], ADR-0011), distinct from `local`'s lock/unlock.
/// `None` for backends with no such concept — the local backend never
/// sets this, since its "unlock" already is the daemon lock.
pub struct DaemonState {
    backend: Arc<dyn Backend>,
    local: Arc<LocalBackend>,
    session: Option<Arc<dyn BackendSession>>,
}

impl DaemonState {
    /// Wrap a backend (for resolution), the local backend (for
    /// lock/unlock) and an optional backend session handle as shared
    /// daemon state.
    ///
    /// Three parameters rather than one because they answer different
    /// questions today — see the struct's own doc comment. Callers other
    /// than [`open_default_state`] will typically pass the same
    /// concrete backend upcast for `backend`/`local`, and `None` for
    /// `session` unless that backend has its own authentication concept.
    #[must_use]
    pub fn new(
        backend: Arc<dyn Backend>,
        local: Arc<LocalBackend>,
        session: Option<Arc<dyn BackendSession>>,
    ) -> Self {
        Self {
            backend,
            local,
            session,
        }
    }

    /// Check the active backend's own session state, if it has one.
    ///
    /// Called in addition to (never instead of) the daemon lock check in
    /// [`DaemonState::get`]/[`DaemonState::resolve`] — the two answer
    /// different questions and neither substitutes for the other.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::BackendRequiresAuthentication`] if the backend
    /// reports [`BackendStatus::RequiresAuthentication`] or
    /// [`BackendStatus::SessionExpired`], or
    /// [`CoreError::BackendUnavailable`] if it reports
    /// [`BackendStatus::Unavailable`]. `None` (no session concept) and
    /// [`BackendStatus::Available`]/[`BackendStatus::Authenticated`] both
    /// pass.
    fn check_backend_session(&self) -> std::result::Result<(), CoreError> {
        let Some(session) = &self.session else {
            return Ok(());
        };
        match session.backend_status() {
            BackendStatus::Available | BackendStatus::Authenticated => Ok(()),
            BackendStatus::RequiresAuthentication => Err(CoreError::BackendRequiresAuthentication(
                "the backend has no active session; it must be authenticated before secrets can be read".to_string(),
            )),
            BackendStatus::SessionExpired => Err(CoreError::BackendRequiresAuthentication(
                "the backend's session has expired and needs renewal".to_string(),
            )),
            BackendStatus::Unavailable => Err(CoreError::BackendUnavailable(
                "the backend is not reachable".to_string(),
            )),
        }
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
    /// Named `validate_reference`, not `resolve`, on purpose: this is an
    /// existence check only, exposed over D-Bus as `Manager.Resolve` (see
    /// `docs/dbus/secrets-manager.md` — the *wire* method name stays
    /// `Resolve` for compatibility with existing clients; only this
    /// internal Rust name changes). Deliberately distinct from
    /// [`secrets_core::Resolver::resolve`], which *does* return the
    /// value. A backend's own native reference format (e.g. a future
    /// `op://...` internal encoding a 1Password backend might use) never
    /// appears in this method's output or errors — only the `secret://`
    /// form the caller supplied, echoed back canonicalised.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::VaultLocked`] if the store is locked, or
    /// [`CoreError::NotFound`] if the reference does not resolve.
    pub fn validate_reference(&self, uri: &SecretUri) -> std::result::Result<(), CoreError> {
        if !self.is_unlocked() {
            return Err(CoreError::VaultLocked {
                vault: uri.vault().to_string(),
            });
        }
        self.check_backend_session()?;
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
        self.check_backend_session()?;
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
    // The local backend has no session concept of its own — its "unlock"
    // already is the daemon-wide lock, so there is nothing for
    // `check_backend_session` to consult here.
    Ok(DaemonState::new(backend, local, None))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    /// Builds a `DaemonState` the same way `open_default_state` does,
    /// against a throwaway vault file, so these tests exercise the exact
    /// `Arc<dyn Backend>` + `Arc<LocalBackend>` wiring production code
    /// uses. No backend session (matches the local backend, which has
    /// none).
    fn state_over_fresh_vault() -> (tempfile::TempDir, DaemonState) {
        let dir = tempdir().unwrap();
        let local = Arc::new(LocalBackend::open(dir.path().join("vault.toml")).unwrap());
        let backend: Arc<dyn Backend> = local.clone();
        (dir, DaemonState::new(backend, local, None))
    }

    /// A fixture [`BackendSession`] whose reported status is set by the
    /// test, so `check_backend_session`'s gating can be exercised without
    /// a real external backend.
    struct FixedSession(BackendStatus);

    impl BackendSession for FixedSession {
        fn backend_status(&self) -> BackendStatus {
            self.0
        }
    }

    /// Same as [`state_over_fresh_vault`], but with a backend session
    /// fixture attached, reporting `status`.
    fn state_with_backend_session(status: BackendStatus) -> (tempfile::TempDir, DaemonState) {
        let dir = tempdir().unwrap();
        let local = Arc::new(LocalBackend::open(dir.path().join("vault.toml")).unwrap());
        let backend: Arc<dyn Backend> = local.clone();
        let session: Arc<dyn BackendSession> = Arc::new(FixedSession(status));
        (dir, DaemonState::new(backend, local, Some(session)))
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
    fn validate_reference_confirms_existence_without_returning_the_value() {
        let (_dir, state) = state_over_fresh_vault();
        state.unlock("test passphrase").unwrap();

        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        // Succeeds but its `Ok` carries no value to expose — unlike `get`.
        state.validate_reference(&uri).unwrap();

        let missing = SecretUri::parse("secret://Personal/GitHub/does-not-exist").unwrap();
        let error = state.validate_reference(&missing).unwrap_err();
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

    #[test]
    fn a_backend_requiring_authentication_blocks_get_even_when_the_daemon_is_unlocked() {
        // The daemon-wide lock and a backend's own session are different
        // questions (ADR-0011): being unlocked must not be enough on its
        // own when the active backend also has an unmet session
        // requirement.
        let (_dir, state) = state_with_backend_session(BackendStatus::RequiresAuthentication);
        state.unlock("test passphrase").unwrap();
        assert!(state.is_unlocked());

        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        let error = state.get(&uri).unwrap_err();
        assert!(matches!(error, CoreError::BackendRequiresAuthentication(_)));
    }

    #[test]
    fn an_expired_backend_session_blocks_resolve_with_a_distinct_error_from_vault_locked() {
        let (_dir, state) = state_with_backend_session(BackendStatus::SessionExpired);
        state.unlock("test passphrase").unwrap();

        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        let error = state.validate_reference(&uri).unwrap_err();
        assert!(matches!(error, CoreError::BackendRequiresAuthentication(_)));
    }

    #[test]
    fn an_unavailable_backend_blocks_get_with_backend_unavailable() {
        let (_dir, state) = state_with_backend_session(BackendStatus::Unavailable);
        state.unlock("test passphrase").unwrap();

        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        let error = state.get(&uri).unwrap_err();
        assert!(matches!(error, CoreError::BackendUnavailable(_)));
    }

    #[test]
    fn an_authenticated_backend_session_does_not_block_get() {
        let (_dir, state) = state_with_backend_session(BackendStatus::Authenticated);
        state.unlock("test passphrase").unwrap();

        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        let value = state.get(&uri).unwrap();
        assert_eq!(value.expose_secret(), "correct horse battery staple");
    }

    #[test]
    fn no_backend_session_at_all_behaves_exactly_as_before_step_2() {
        // Regression guard for the local backend: `session` is `None`, so
        // `check_backend_session` must be a no-op, never blocking a
        // request the daemon lock alone already allows.
        let (_dir, state) = state_over_fresh_vault();
        state.unlock("test passphrase").unwrap();

        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        assert!(state.get(&uri).is_ok());
        assert!(state.validate_reference(&uri).is_ok());
    }
}
