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

/// A backend's own authentication/session state.
///
/// Deliberately **not** the same thing as the daemon-wide lock
/// (`secretsd::state::DaemonState`, [`crate::dbus::STATUS_LOCKED`] /
/// [`crate::dbus::STATUS_UNLOCKED`], see ADR-0009): that state machine has
/// exactly two values and lives in one place regardless of backend. This
/// enum is for backends that separately authenticate against something
/// external to `secretsd` — 1Password Desktop's own unlock, an OAuth
/// token, a GPG agent already running — where "is the daemon unlocked"
/// and "does the backend currently have a usable session" can disagree
/// (the daemon can be unlocked while 1Password Desktop's own session has
/// expired, for instance).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendStatus {
    /// The backend can serve requests right now and has no separate
    /// authentication concept to report (or that concept is currently
    /// satisfied).
    Available,
    /// The backend cannot be reached at all (its process isn't running,
    /// its socket is missing, ...). Distinct from
    /// [`BackendStatus::RequiresAuthentication`]: re-authenticating does
    /// not fix this.
    Unavailable,
    /// The backend is reachable but has no valid session yet. Resolving
    /// this typically requires an out-of-band, interactive step (e.g.
    /// unlocking the 1Password Desktop app itself) that `secretsd` does
    /// not perform on the caller's behalf.
    RequiresAuthentication,
    /// The backend has a valid session and can serve requests.
    Authenticated,
    /// A previously valid session has expired. Distinct from
    /// [`BackendStatus::RequiresAuthentication`]: renewal is expected to
    /// succeed without fresh interactive user consent, e.g. by asking the
    /// backend to refresh its own token.
    SessionExpired,
}

/// A backend's own authentication/session lifecycle.
///
/// Optional and separate from [`Backend`]: implemented only by backends
/// that have an external authentication concept of their own. The local
/// file backend, for instance, never implements this — its "unlock" *is*
/// the daemon-wide lock, not a distinct session.
///
/// `secretsd`'s `DaemonState` holds at most one `Arc<dyn BackendSession>`
/// alongside its `Arc<dyn Backend>`, consulted before `get`/`resolve` in
/// addition to (not instead of) the daemon lock check.
pub trait BackendSession: Send + Sync {
    /// The backend's current authentication/session state.
    fn backend_status(&self) -> BackendStatus;
}
