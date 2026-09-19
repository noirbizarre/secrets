//! `org.freedesktop.Secret.Collection`: one per (store, vault) pair
//! (ADR-018).

use std::collections::HashMap;
use std::sync::Arc;

use secrets_core::StoreId;
use zbus::zvariant::OwnedObjectPath;

use super::LiveTopology;
use crate::state::DaemonState;

/// One vault, exposed as a Secret Service collection.
pub struct CollectionIface {
    state: Arc<DaemonState>,
    store: StoreId,
    vault: String,
    /// Shared with `ServiceIface` and every other `CollectionIface` — see
    /// [`LiveTopology`]. This vault's own items are filtered out of a
    /// fresh snapshot on every call, rather than held as a
    /// construction-time copy.
    topology: LiveTopology,
}

impl CollectionIface {
    /// Wrap a store id, a vault's name and the shared, live topology
    /// handle as a servable collection.
    #[must_use]
    pub fn new(
        state: Arc<DaemonState>,
        store: StoreId,
        vault: String,
        topology: LiveTopology,
    ) -> Self {
        Self {
            state,
            store,
            vault,
            topology,
        }
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Collection")]
impl CollectionIface {
    /// This vault's items, as `Item` object paths.
    #[zbus(property)]
    fn items(&self) -> Vec<OwnedObjectPath> {
        self.topology
            .snapshot()
            .items
            .iter()
            .filter(|known| known.store == self.store && known.vault == self.vault)
            .map(|known| known.path.clone())
            .collect()
    }

    /// The vault's name.
    #[zbus(property)]
    fn label(&self) -> String {
        self.vault.clone()
    }

    /// Whether this vault is currently readable — reflects both this
    /// store's own lock and its own session state; see
    /// [`crate::state::DaemonState::is_accessible`]. A different store
    /// may report differently (ADR-018 supersedes ADR-009's "daemon-wide,
    /// not per-vault" framing on this point).
    #[zbus(property)]
    fn locked(&self) -> bool {
        !self.state.is_accessible(&self.store)
    }

    /// Search this vault's items by attribute.
    fn search_items(&self, attributes: HashMap<String, String>) -> Vec<OwnedObjectPath> {
        self.topology
            .snapshot()
            .items
            .iter()
            .filter(|known| {
                known.store == self.store
                    && known.vault == self.vault
                    && attributes.iter().all(|(key, value)| match key.as_str() {
                        "store" => known.store.as_str() == value,
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
