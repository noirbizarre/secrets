//! A thin, blocking D-Bus client for `org.secrets.Manager`.
//!
//! Every method here is a direct proxy call — no local vault or session
//! state is cached or duplicated. `secretsd` is the sole authority on
//! locking and secret resolution; this type exists only to translate
//! `secrets_core::dbus::ManagerError` into [`CliError`].

use secrets_core::dbus::{ManagerError, ManagerProxyBlocking};

use crate::error::{CliError, Result};

/// Convert a raw `zbus` call result into a [`CliError`], routing it through
/// [`ManagerError`] first.
///
/// This extra step matters: `ManagerError`'s `From<zbus::Error>` (generated
/// by `#[derive(DBusError)]`) is what recognises a named
/// `org.secrets.Error.*` reply and picks the matching variant — going
/// straight from `zbus::Error` to `CliError` via `?` would skip that and
/// collapse every daemon-side error into "daemon unreachable".
fn map<T>(result: zbus::Result<T>) -> Result<T> {
    result.map_err(|error| CliError::from(ManagerError::from(error)))
}

/// A connected client for the daemon's native API.
pub struct Client<'a> {
    proxy: ManagerProxyBlocking<'a>,
}

impl Client<'static> {
    /// Connect to `secretsd` on the session bus.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::DaemonUnreachable`] if the session bus or the
    /// daemon cannot be reached — most commonly because `secretsd` is not
    /// running.
    pub fn connect() -> Result<Self> {
        let connection = zbus::blocking::Connection::session()?;
        let proxy = ManagerProxyBlocking::new(&connection)?;
        Ok(Self { proxy })
    }
}

impl Client<'_> {
    /// `"locked"` or `"unlocked"`.
    pub fn status(&self) -> Result<String> {
        map(self.proxy.status())
    }

    /// Unlock the store.
    pub fn unlock(&self, passphrase: &str) -> Result<()> {
        map(self.proxy.unlock(passphrase))
    }

    /// Lock the store.
    pub fn lock(&self) -> Result<()> {
        map(self.proxy.lock())
    }

    /// List every vault name.
    pub fn list_vaults(&self) -> Result<Vec<String>> {
        map(self.proxy.list_vaults())
    }

    /// List a vault's item paths.
    pub fn list_items(&self, vault: &str) -> Result<Vec<String>> {
        map(self.proxy.list_items(vault))
    }

    /// Validate a `secret://` reference without reading its value.
    pub fn resolve(&self, uri: &str) -> Result<String> {
        map(self.proxy.resolve(uri))
    }

    /// Fetch a field's value.
    pub fn get(&self, uri: &str) -> Result<String> {
        map(self.proxy.get(uri))
    }
}
