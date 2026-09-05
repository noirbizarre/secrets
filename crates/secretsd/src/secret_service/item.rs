//! `org.freedesktop.Secret.Item`: one per (vault, item, field) triple.
//!
//! Secret Service items hold exactly one secret value each, but a
//! `secrets-core` item can hold several fields — so each field of a
//! `secrets-core` item is exposed as its own `Item` object here, labelled
//! to make the relationship legible (`"GitHub (password)"`).

use std::collections::HashMap;
use std::sync::Arc;

use secrets_core::{Backend, ItemPath};

use super::Secret;
use crate::state::DaemonState;

/// One (vault, item, field) triple.
pub struct ItemIface {
    state: Arc<DaemonState>,
    vault: String,
    item: ItemPath,
    field: String,
}

impl ItemIface {
    /// Wrap one field as a servable Secret Service item.
    #[must_use]
    pub fn new(state: Arc<DaemonState>, vault: String, item: ItemPath, field: String) -> Self {
        Self {
            state,
            vault,
            item,
            field,
        }
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl ItemIface {
    /// Whether the daemon is currently locked.
    #[zbus(property)]
    fn locked(&self) -> bool {
        !self.state.is_unlocked()
    }

    /// `vault`, `item` and `field`, so `Service`/`Collection.SearchItems`
    /// have something to match against.
    #[zbus(property)]
    fn attributes(&self) -> HashMap<String, String> {
        HashMap::from([
            ("vault".to_string(), self.vault.clone()),
            ("item".to_string(), self.item.to_string()),
            ("field".to_string(), self.field.clone()),
        ])
    }

    /// `"<item> (<field>)"`, since a Secret Service item is one value, not
    /// a `secrets-core` item's full field set.
    #[zbus(property)]
    fn label(&self) -> String {
        format!("{} ({})", self.item, self.field)
    }

    /// Fetch this field's value.
    ///
    /// # Errors
    ///
    /// Fails while locked, or if the value cannot be decrypted.
    fn get_secret(&self, session: zbus::zvariant::OwnedObjectPath) -> zbus::fdo::Result<Secret> {
        if !self.state.is_unlocked() {
            return Err(zbus::fdo::Error::Failed(
                "the store is locked; run `secrets unlock` first".to_string(),
            ));
        }
        let value = self
            .state
            .backend()
            .get_field(&self.vault, &self.item, &self.field)
            .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
        Ok(Secret {
            session,
            parameters: Vec::new(),
            value: value.expose_secret().as_bytes().to_vec(),
            content_type: "text/plain".to_string(),
        })
    }

    /// Not supported: the local backend is read-only through this
    /// compatibility layer in the MVP.
    fn set_secret(&self, _secret: Secret) -> zbus::fdo::Result<()> {
        Err(zbus::fdo::Error::NotSupported(
            "setting a secret is not supported in this MVP".to_string(),
        ))
    }

    /// Not supported, for the same reason as `SetSecret`.
    fn delete(&self) -> zbus::fdo::Result<zbus::zvariant::OwnedObjectPath> {
        Err(zbus::fdo::Error::NotSupported(
            "deleting items is not supported in this MVP".to_string(),
        ))
    }
}
