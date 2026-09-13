//! The `org.secrets.Manager` D-Bus interface implementation.
//!
//! Thin on purpose: every method forwards straight to [`DaemonState`],
//! translating [`secrets_core::CoreError`]/[`DaemonError`] into the D-Bus
//! error names defined in `secrets_core::dbus`. See
//! `docs/dbus/secrets-manager.md` for the wire contract.

use std::sync::Arc;
use std::sync::mpsc;

use secrets_core::SecretUri;
use secrets_core::dbus::ManagerError;

use crate::error::DaemonError;
use crate::state::DaemonState;

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
        self.state.status().to_string()
    }

    /// See [`secrets_core::dbus::Manager::unlock`].
    fn unlock(&self, passphrase: &str) -> Result<(), ManagerError> {
        self.state.unlock(passphrase).map_err(|error| match error {
            // A wrong passphrase is the caller's fault, not the backend's —
            // distinct D-Bus error name so a client does not retry blindly.
            DaemonError::IncorrectPassphrase => ManagerError::PermissionDenied(error.to_string()),
            other => ManagerError::BackendUnavailable(other.to_string()),
        })?;
        // On first-ever unlock, this is exactly when the local backend's
        // vault file (and its collections) start existing — wake the
        // refresher immediately rather than leaving them invisible over
        // Secret Service for up to `REFRESH_INTERVAL`.
        let _ = self.refresh_trigger.send(());
        Ok(())
    }

    /// See [`secrets_core::dbus::Manager::lock`].
    fn lock(&self) {
        self.state.lock();
        let _ = self.refresh_trigger.send(());
    }

    /// See [`secrets_core::dbus::Manager::list_vaults`].
    fn list_vaults(&self) -> Result<Vec<String>, ManagerError> {
        Ok(self
            .state
            .list_vaults()?
            .into_iter()
            .map(|vault| vault.name)
            .collect())
    }

    /// See [`secrets_core::dbus::Manager::list_items`].
    fn list_items(&self, vault: &str) -> Result<Vec<String>, ManagerError> {
        Ok(self
            .state
            .list_items(vault)?
            .into_iter()
            .map(|item| item.path.to_string())
            .collect())
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
}
