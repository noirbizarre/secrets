//! The daemon's shared, authoritative state.
//!
//! One [`DaemonState`], held behind an `Arc` and shared by every D-Bus
//! interface (`org.secrets.Manager`, the Secret Service compatibility
//! objects) and the SSH agent. There is exactly one source of truth for
//! "are we locked", so the three surfaces can never disagree.

use std::sync::Arc;

use secrets_core::{
    Backend, BackendSession, BackendStatus, CoreError, Item, ItemPath, Resolver, SecretUri,
    SecretValue, Vault,
};

use crate::backend::local::LocalBackend;
use crate::error::{DaemonError, Result};

/// The daemon-wide lock/unlock mechanism (ADR-0009) — distinct from a
/// backend's own session (ADR-0011, [`BackendSession`]). `LocalBackend`
/// implements this over its passphrase-derived key (its "unlock" *is*
/// the daemon lock — see ADR-0006/0009). A backend with no local secret
/// of its own to protect this way (1Password Desktop, which gates access
/// through its own [`BackendSession`] instead) uses
/// [`AlwaysUnlocked`] — there is nothing for a daemon-wide passphrase
/// lock to mean in that case, so it is a deliberate, documented no-op,
/// not an oversight.
///
/// Kept `secretsd`-internal (not in `secrets-core`): unlike `Backend`/
/// `BackendSession`, no other crate needs to know this trait's shape —
/// `secrets-cli` only ever reaches lock state through `DaemonState` via
/// D-Bus, never this trait directly.
pub trait LockController: Send + Sync {
    /// Whether the store is currently unlocked.
    fn is_unlocked(&self) -> bool;

    /// Unlock (or, for `LocalBackend`, on first run, initialize) the
    /// store.
    ///
    /// # Errors
    ///
    /// Backend-specific; see the implementing type.
    fn unlock(&self, passphrase: &str) -> Result<()>;

    /// Lock the store, dropping any derived key from memory.
    fn lock(&self);
}

/// The trivial [`LockController`] for backends with no daemon-wide
/// passphrase lock of their own — see the trait's own doc comment for
/// why this is correct, not a missing feature. `unlock`/`lock` are
/// deliberate no-ops; `is_unlocked` always reports `true`, so the
/// daemon-wide lock check in [`DaemonState::get`]/
/// [`DaemonState::validate_reference`] always passes, leaving the
/// *real* gating to that backend's own [`BackendSession`].
pub struct AlwaysUnlocked;

impl LockController for AlwaysUnlocked {
    fn is_unlocked(&self) -> bool {
        true
    }

    fn unlock(&self, _passphrase: &str) -> Result<()> {
        Ok(())
    }

    fn lock(&self) {}
}

/// Shared daemon state.
///
/// `backend` is the read path (`list_vaults`/`list_items`/resolution) —
/// held as `Arc<dyn Backend>` so it works against any backend, per
/// ADR-0008. `lock_controller` is kept alongside it for lock/unlock/
/// status: those three operations are not part of the `Backend` trait
/// (they vary too much between backend shapes to force into one
/// signature) — see [`LockController`].
///
/// `session` is the daemon-wide lock's conceptual opposite number: an
/// *external* backend's own authentication/session state (see
/// [`BackendSession`], ADR-0011), distinct from `lock_controller`'s
/// lock/unlock. `None` for backends with no such concept — the local
/// backend never sets this, since its "unlock" already is the daemon
/// lock.
pub struct DaemonState {
    backend: Arc<dyn Backend>,
    lock_controller: Arc<dyn LockController>,
    session: Option<Arc<dyn BackendSession>>,
}

impl DaemonState {
    /// Wrap a backend (for resolution), a lock controller (for
    /// lock/unlock) and an optional backend session handle as shared
    /// daemon state.
    ///
    /// Three parameters rather than one because they answer different
    /// questions today — see the struct's own doc comment. The local
    /// backend passes the same concrete value upcast for `backend`/
    /// `lock_controller`, and `None` for `session`; a backend with its
    /// own session (1Password) passes [`AlwaysUnlocked`] for
    /// `lock_controller` and `Some(...)` for `session`.
    #[must_use]
    pub fn new(
        backend: Arc<dyn Backend>,
        lock_controller: Arc<dyn LockController>,
        session: Option<Arc<dyn BackendSession>>,
    ) -> Self {
        Self {
            backend,
            lock_controller,
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
        if self.lock_controller.is_unlocked() {
            secrets_core::dbus::STATUS_UNLOCKED
        } else {
            secrets_core::dbus::STATUS_LOCKED
        }
    }

    /// Whether the store is currently unlocked.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.lock_controller.is_unlocked()
    }

    /// Unlock (or, for `LocalBackend`, on first run, initialize) the
    /// store. A no-op for backends with no daemon-wide lock of their own
    /// — see [`LockController`]/[`AlwaysUnlocked`].
    ///
    /// # Errors
    ///
    /// See the active [`LockController`] implementation.
    pub fn unlock(&self, passphrase: &str) -> Result<()> {
        self.lock_controller.unlock(passphrase)
    }

    /// Lock the store, dropping any derived key from memory. A no-op for
    /// backends with no daemon-wide lock of their own.
    pub fn lock(&self) {
        self.lock_controller.lock();
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

    /// Access the underlying backend directly — used to enumerate vaults/
    /// items (`list_vaults`/`list_items`), which are available regardless
    /// of lock state. For reading a field's *value*, use
    /// [`DaemonState::read_field`] instead: it applies the same
    /// lock/session gating as [`DaemonState::get`], which calling
    /// [`Backend::get_field`] directly on this handle would bypass.
    #[must_use]
    pub fn backend(&self) -> &Arc<dyn Backend> {
        &self.backend
    }

    /// Whether a read can happen right now: both the daemon-wide lock
    /// ([`LockController::is_unlocked`]) and the active backend's own
    /// session ([`check_backend_session`](Self::check_backend_session)), if
    /// it has one.
    ///
    /// The single answer to "is this readable", shared by every surface
    /// that needs it (the Secret Service compatibility layer, the SSH
    /// agent) so none of them can drift from `get`/`validate_reference`'s
    /// own gating — see the invariant this trait's doc comment describes.
    #[must_use]
    pub fn is_accessible(&self) -> bool {
        self.is_unlocked() && self.check_backend_session().is_ok()
    }

    /// Fetch one (vault, item, field) triple's value directly, applying the
    /// same lock/session gating as [`DaemonState::get`].
    ///
    /// Used by callers that already have a (vault, item, field) triple in
    /// hand rather than a `secret://` URI — the Secret Service compatibility
    /// layer (one Secret Service `Item` per triple) and the SSH agent
    /// (iterating `SshKey` fields directly). Both used to call
    /// `self.backend().get_field(...)` straight through, which skipped
    /// [`check_backend_session`](Self::check_backend_session) entirely: for
    /// a backend using [`AlwaysUnlocked`] (1Password Desktop), that meant a
    /// `RequiresAuthentication`/`SessionExpired`/`Unavailable` session was
    /// never reported as "locked" on those surfaces — see #7.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::VaultLocked`] if the store is locked,
    /// [`CoreError::BackendRequiresAuthentication`] or
    /// [`CoreError::BackendUnavailable`] if the backend's own session
    /// blocks it (see [`check_backend_session`](Self::check_backend_session)),
    /// or propagates the backend's error otherwise.
    pub fn read_field(
        &self,
        vault: &str,
        item: &ItemPath,
        field: &str,
    ) -> std::result::Result<SecretValue, CoreError> {
        if !self.is_unlocked() {
            return Err(CoreError::VaultLocked {
                vault: vault.to_string(),
            });
        }
        self.check_backend_session()?;
        self.backend.get_field(vault, item, field)
    }
}

/// Open the configured backend (see [`crate::config::Config`]) and wrap
/// it as shared daemon state. Exactly one backend is active — no
/// multi-backend routing (ADR-0008).
///
/// # Errors
///
/// Returns [`DaemonError`] if the config file exists but cannot be
/// parsed, if `[backend] type = "1password"` is missing a required
/// field, if the local vault file's path cannot be resolved or it
/// cannot be parsed, or if the configured backend fails to start (e.g.
/// 1Password Desktop's native library cannot be loaded).
pub fn open_default_state() -> Result<DaemonState> {
    match crate::config::Config::load()?.backend {
        crate::config::BackendKind::Local => {
            let path = crate::paths::vault_file()?;
            let local = Arc::new(LocalBackend::open(path)?);
            let backend: Arc<dyn Backend> = local.clone();
            let lock_controller: Arc<dyn LockController> = local;
            // The local backend has no session concept of its own — its
            // "unlock" already is the daemon-wide lock, so there is
            // nothing for `check_backend_session` to consult here.
            Ok(DaemonState::new(backend, lock_controller, None))
        }
        crate::config::BackendKind::OnePassword { account_name } => {
            let one_password = Arc::new(
                crate::backend::onepassword::OnePasswordBackend::open(account_name)
                    .map_err(|error| DaemonError::BackendUnavailable(error.to_string()))?,
            );
            let backend: Arc<dyn Backend> = one_password.clone();
            let session: Arc<dyn BackendSession> = one_password;
            // 1Password Desktop has no daemon-wide passphrase lock of its
            // own — its own approval/session flow (`BackendSession`,
            // ADR-0011) does the real gating instead. See
            // `LockController`/`AlwaysUnlocked`'s own doc comments.
            Ok(DaemonState::new(
                backend,
                Arc::new(AlwaysUnlocked),
                Some(session),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{state_over_fresh_vault, state_with_backend_session};

    use super::*;

    #[test]
    fn always_unlocked_reports_unlocked_and_ignores_lock_unlock_calls() {
        // Confirms the documented contract directly: AlwaysUnlocked is a
        // deliberate no-op, not a bug waiting to be noticed.
        let controller = AlwaysUnlocked;
        assert!(controller.is_unlocked());
        controller.unlock("anything").unwrap();
        assert!(controller.is_unlocked());
        controller.lock();
        assert!(controller.is_unlocked());
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

    #[test]
    fn is_accessible_reflects_both_the_daemon_lock_and_the_backend_session() {
        // Regression guard for #7: `is_accessible` is what the Secret
        // Service layer and the SSH agent now consult instead of the
        // daemon lock alone — it must answer "no" for every reason a read
        // could fail, not just a locked daemon.
        let (_dir, locked) = state_over_fresh_vault();
        assert!(!locked.is_accessible(), "a fresh, never-unlocked store");

        let (_dir, unlocked) = state_over_fresh_vault();
        unlocked.unlock("test passphrase").unwrap();
        assert!(unlocked.is_accessible(), "unlocked, no backend session");

        let (_dir, needs_auth) = state_with_backend_session(BackendStatus::RequiresAuthentication);
        needs_auth.unlock("test passphrase").unwrap();
        assert!(
            !needs_auth.is_accessible(),
            "daemon unlocked but backend session requires authentication"
        );

        let (_dir, authenticated) = state_with_backend_session(BackendStatus::Authenticated);
        authenticated.unlock("test passphrase").unwrap();
        assert!(authenticated.is_accessible());
    }

    #[test]
    fn read_field_applies_the_same_gating_as_get() {
        let item = ItemPath::new(vec!["GitHub".to_string()]).unwrap();

        let (_dir, locked) = state_over_fresh_vault();
        let error = locked
            .read_field("Personal", &item, "password")
            .unwrap_err();
        assert!(matches!(error, CoreError::VaultLocked { .. }));

        let (_dir, needs_auth) = state_with_backend_session(BackendStatus::RequiresAuthentication);
        needs_auth.unlock("test passphrase").unwrap();
        let error = needs_auth
            .read_field("Personal", &item, "password")
            .unwrap_err();
        assert!(matches!(error, CoreError::BackendRequiresAuthentication(_)));

        let (_dir, unlocked) = state_over_fresh_vault();
        unlocked.unlock("test passphrase").unwrap();
        let value = unlocked.read_field("Personal", &item, "password").unwrap();
        assert_eq!(value.expose_secret(), "correct horse battery staple");
    }
}
