//! The `org.secrets.Manager` D-Bus interface implementation.
//!
//! Thin on purpose: every method forwards straight to [`DaemonState`],
//! translating [`secrets_core::CoreError`]/[`DaemonError`] into the D-Bus
//! error names defined in `secrets_core::dbus`. See
//! `docs/dbus/secrets-manager.md` for the wire contract.

use std::sync::Arc;
use std::sync::mpsc;

use secrets_core::dbus::{FieldDisplay, ManagerError};
use secrets_core::{ItemUri, SecretUri, StoreId};

use crate::error::DaemonError;
use crate::state::DaemonState;

/// Parse a bare store-id argument (`unlock_store`/`lock_store`/
/// `status_store`'s `store` parameter) into a [`StoreId`].
///
/// # Errors
///
/// Maps a [`secrets_core::StoreIdError`] to [`ManagerError::InvalidUri`] —
/// not [`ManagerError::StoreNotFound`], which is reserved for a
/// *syntactically valid* id that just isn't configured: the two are the
/// same "your input string didn't parse"/"it parsed but isn't real"
/// distinction `SecretUri::parse` already draws between its own
/// `InvalidStore` and a resolver's `StoreNotFound`.
fn parse_store_id(raw: &str) -> Result<StoreId, ManagerError> {
    StoreId::new(raw).map_err(|error| ManagerError::InvalidUri(error.to_string()))
}

/// Split a `Manager.list_items` vault argument into an optional
/// `store@` qualifier and the bare vault name — the same split
/// `secret://` URIs use (ADR-018), but over a plain, never
/// percent-encoded string: this argument is never a full URI, just a
/// vault name as `list_vaults` itself returns it.
///
/// # Errors
///
/// Maps a malformed store qualifier the same way [`parse_store_id`] does.
fn split_store_and_vault(raw: &str) -> Result<(Option<StoreId>, String), ManagerError> {
    match raw.split_once('@') {
        Some((store, vault)) => Ok((Some(parse_store_id(store)?), vault.to_string())),
        None => Ok((None, raw.to_string())),
    }
}

/// Map a lock-path [`DaemonError`] to its D-Bus error name.
fn map_lock_error(error: DaemonError) -> ManagerError {
    match error {
        // A wrong passphrase is the caller's fault, not the backend's —
        // distinct D-Bus error name so a client does not retry blindly.
        DaemonError::IncorrectPassphrase => ManagerError::PermissionDenied(error.to_string()),
        DaemonError::StoreNotFound(_) => ManagerError::StoreNotFound(error.to_string()),
        DaemonError::StoreSelectionRequired(_) => {
            ManagerError::StoreSelectionRequired(error.to_string())
        }
        other => ManagerError::BackendUnavailable(other.to_string()),
    }
}

/// The object served at `secrets_core::dbus::MANAGER_PATH`.
pub struct ManagerIface {
    state: Arc<DaemonState>,
    /// Wakes `secret_service::refresh`'s background loop immediately
    /// after a successful `unlock`/`lock`, instead of leaving it to the
    /// next periodic scan (see `secret_service::refresh::spawn`, ADR-015)
    /// — the one case that matters in practice: the local backend's vault
    /// file being created for the first time. Sending is always
    /// best-effort (`let _ = ...`): a full/disconnected channel must never
    /// fail the D-Bus call itself.
    refresh_trigger: mpsc::Sender<()>,
}

impl ManagerIface {
    /// Wrap shared daemon state and the topology refresher's trigger
    /// channel as a servable interface.
    #[must_use]
    pub fn new(state: Arc<DaemonState>, refresh_trigger: mpsc::Sender<()>) -> Self {
        Self {
            state,
            refresh_trigger,
        }
    }
}

#[zbus::interface(name = "org.secrets.Manager")]
impl ManagerIface {
    /// See [`secrets_core::dbus::Manager::status`].
    fn status(&self) -> String {
        self.state.status_summary().to_string()
    }

    /// See [`secrets_core::dbus::Manager::unlock`].
    fn unlock(&self, passphrase: &str) -> Result<(), ManagerError> {
        self.state
            .unlock_default(passphrase)
            .map_err(map_lock_error)?;
        // On first-ever unlock, this is exactly when the local backend's
        // vault file (and its collections) start existing — wake the
        // refresher immediately rather than leaving them invisible over
        // Secret Service for up to `REFRESH_INTERVAL`.
        let _ = self.refresh_trigger.send(());
        Ok(())
    }

    /// See [`secrets_core::dbus::Manager::lock`].
    fn lock(&self) {
        self.state.lock_all();
        let _ = self.refresh_trigger.send(());
    }

    /// See [`secrets_core::dbus::Manager::list_vaults`].
    fn list_vaults(&self) -> Result<Vec<String>, ManagerError> {
        Ok(self
            .state
            .list_all_vaults()?
            .into_iter()
            .map(|(store, vault)| format!("{store}@{}", vault.name))
            .collect())
    }

    /// See [`secrets_core::dbus::Manager::list_items`].
    fn list_items(&self, vault: &str) -> Result<Vec<String>, ManagerError> {
        let (store, vault) = split_store_and_vault(vault)?;
        Ok(self
            .state
            .list_items(store.as_ref(), &vault)?
            .into_iter()
            .map(|item| item.path.to_string())
            .collect())
    }

    /// See [`secrets_core::dbus::Manager::list_stores`].
    fn list_stores(&self) -> Vec<String> {
        self.state.store_ids().map(StoreId::to_string).collect()
    }

    /// See [`secrets_core::dbus::Manager::status_store`].
    fn status_store(&self, store: &str) -> Result<String, ManagerError> {
        let id = parse_store_id(store)?;
        Ok(self.state.status(&id)?.to_string())
    }

    /// See [`secrets_core::dbus::Manager::unlock_store`].
    fn unlock_store(&self, store: &str, passphrase: &str) -> Result<(), ManagerError> {
        let id = parse_store_id(store)?;
        self.state.unlock(&id, passphrase).map_err(map_lock_error)?;
        let _ = self.refresh_trigger.send(());
        Ok(())
    }

    /// See [`secrets_core::dbus::Manager::lock_store`].
    fn lock_store(&self, store: &str) -> Result<(), ManagerError> {
        let id = parse_store_id(store)?;
        self.state.lock(&id).map_err(map_lock_error)?;
        let _ = self.refresh_trigger.send(());
        Ok(())
    }

    /// See [`secrets_core::dbus::Manager::resolve`].
    fn resolve(&self, uri: &str) -> Result<String, ManagerError> {
        let parsed =
            SecretUri::parse(uri).map_err(|error| ManagerError::InvalidUri(error.to_string()))?;
        self.state.validate_reference(&parsed)?;
        Ok(parsed.to_string())
    }

    /// See [`secrets_core::dbus::Manager::get`].
    fn get(&self, uri: &str) -> Result<String, ManagerError> {
        let parsed =
            SecretUri::parse(uri).map_err(|error| ManagerError::InvalidUri(error.to_string()))?;
        let value = self.state.get(&parsed)?;
        Ok(value.expose_secret().to_string())
    }

    /// See [`secrets_core::dbus::Manager::show_item`].
    fn show_item(&self, item_uri: &str) -> Result<Vec<FieldDisplay>, ManagerError> {
        let parsed = ItemUri::parse(item_uri)
            .map_err(|error| ManagerError::InvalidUri(error.to_string()))?;
        Ok(self.state.show_item(&parsed)?)
    }
}
