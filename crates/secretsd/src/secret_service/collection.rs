//! `org.freedesktop.Secret.Collection`: one per vault.

use std::collections::HashMap;
use std::sync::Arc;

use zbus::zvariant::OwnedObjectPath;

use super::KnownItem;
use crate::state::DaemonState;

/// One vault, exposed as a Secret Service collection.
pub struct CollectionIface {
    state: Arc<DaemonState>,
    vault: String,
    /// This vault's items, pre-filtered from the full topology snapshot.
    items: Vec<KnownItem>,
}

impl CollectionIface {
    /// Wrap a vault's known items as a servable collection.
    #[must_use]
    pub fn new(state: Arc<DaemonState>, vault: String, items: Vec<KnownItem>) -> Self {
        Self {
            state,
            vault,
            items,
        }
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Collection")]
impl CollectionIface {
    /// This vault's items, as `Item` object paths.
    #[zbus(property)]
    fn items(&self) -> Vec<OwnedObjectPath> {
        self.items.iter().map(|known| known.path.clone()).collect()
    }

    /// The vault's name.
    #[zbus(property)]
    fn label(&self) -> String {
        self.vault.clone()
    }

    /// Whether this vault is currently readable — reflects both the
    /// daemon-wide lock and the active backend's own session state; see
    /// [`crate::state::DaemonState::is_accessible`].
    #[zbus(property)]
    fn locked(&self) -> bool {
        !self.state.is_accessible()
    }

    /// Search this vault's items by attribute.
    fn search_items(&self, attributes: HashMap<String, String>) -> Vec<OwnedObjectPath> {
        self.items
            .iter()
            .filter(|known| {
                attributes.iter().all(|(key, value)| match key.as_str() {
                    "vault" => &known.vault == value,
                    "item" => known.item.to_string() == *value,
                    "field" => &known.field == value,
                    _ => false,
                })
            })
            .map(|known| known.path.clone())
            .collect()
    }

    /// Not supported: the local backend is read-only through this
    /// compatibility layer in the MVP.
    fn create_item(
        &self,
        _properties: HashMap<String, zbus::zvariant::OwnedValue>,
        _secret: super::Secret,
        _replace: bool,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        Err(zbus::fdo::Error::NotSupported(
            "creating items is not supported in this MVP; manage vault contents through the backend directly".to_string(),
        ))
    }

    /// Not supported, for the same reason as `CreateItem`.
    fn delete(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        Err(zbus::fdo::Error::NotSupported(
            "deleting collections is not supported in this MVP".to_string(),
        ))
    }
}
