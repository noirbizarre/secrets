//! `org.freedesktop.Secret.Service`, the entry point clients discover at
//! `/org/freedesktop/secrets`.

use std::collections::HashMap;
use std::sync::Arc;

use secrets_core::Backend;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

use super::{PROMPT_PATH, SESSION_PATH, Secret, Topology, collection_path};
use crate::state::DaemonState;

/// The root Secret Service object.
pub struct ServiceIface {
    state: Arc<DaemonState>,
    topology: Topology,
}

impl ServiceIface {
    /// Wrap daemon state and a topology snapshot as the root service
    /// object.
    #[must_use]
    pub fn new(state: Arc<DaemonState>, topology: Topology) -> Self {
        Self { state, topology }
    }

    /// Items (across every vault) whose synthetic attributes are a
    /// superset of `attributes` — see the module doc for what attributes
    /// exist (`vault`, `item`, `field`).
    fn matching_items(&self, attributes: &HashMap<String, String>) -> Vec<&super::KnownItem> {
        self.topology
            .items
            .iter()
            .filter(|known| {
                attributes.iter().all(|(key, value)| match key.as_str() {
                    "vault" => &known.vault == value,
                    "item" => known.item.to_string() == *value,
                    "field" => &known.field == value,
                    _ => false,
                })
            })
            .collect()
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl ServiceIface {
    /// Every vault, as its `Collection` object path.
    #[zbus(property)]
    fn collections(&self) -> Vec<OwnedObjectPath> {
        self.topology
            .vaults
            .iter()
            .map(|name| collection_path(name))
            .collect()
    }

    /// Negotiate a session. Only `"plain"` is supported in this MVP — see
    /// ADR-0004 — so `input`/`output` are always empty.
    fn open_session(
        &self,
        algorithm: &str,
        _input: Value<'_>,
    ) -> zbus::fdo::Result<(OwnedValue, OwnedObjectPath)> {
        if algorithm != "plain" {
            return Err(zbus::fdo::Error::NotSupported(
                "only the \"plain\" algorithm is supported in this MVP".to_string(),
            ));
        }
        let output: OwnedValue = Value::from("").try_into().expect("string always converts");
        let session: OwnedObjectPath = SESSION_PATH.try_into().expect("valid object path");
        Ok((output, session))
    }

    /// Creating new collections is not supported: the local backend's
    /// vault set is fixed for the MVP. Returns
    /// `org.freedesktop.DBus.Error.NotSupported` rather than silently
    /// no-op'ing.
    fn create_collection(
        &self,
        _properties: HashMap<String, OwnedValue>,
        _alias: &str,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        Err(zbus::fdo::Error::NotSupported(
            "creating collections is not supported in this MVP; manage vaults through the backend directly".to_string(),
        ))
    }

    /// Search every known item for one matching every given attribute.
    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        let unlocked_now = self.state.is_unlocked();
        let matches: Vec<OwnedObjectPath> = self
            .matching_items(&attributes)
            .into_iter()
            .map(|known| known.path.clone())
            .collect();
        if unlocked_now {
            (matches, Vec::new())
        } else {
            (Vec::new(), matches)
        }
    }

    /// Reflects the daemon-wide lock state for the given objects. Cannot
    /// itself prompt for a passphrase (see [`super::prompt`]) — an object
    /// that is still locked stays in `locked`, with the shared prompt
    /// object returned for spec-compliant discoverability, not because it
    /// can do anything about it. Use `secrets unlock` instead.
    fn unlock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        let prompt: OwnedObjectPath = PROMPT_PATH.try_into().expect("valid object path");
        if self.state.is_unlocked() {
            (objects, "/".try_into().expect("valid object path"))
        } else {
            (Vec::new(), prompt)
        }
    }

    /// Locks the whole daemon (there is no per-collection locking in the
    /// MVP's single-passphrase model), regardless of which objects were
    /// named.
    fn lock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        self.state.lock();
        (objects, "/".try_into().expect("valid object path"))
    }

    /// Batch-fetch secrets for several items at once.
    fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
    ) -> zbus::fdo::Result<HashMap<OwnedObjectPath, Secret>> {
        if !self.state.is_unlocked() {
            return Err(zbus::fdo::Error::Failed(
                "the store is locked; run `secrets unlock` first".to_string(),
            ));
        }
        let mut secrets = HashMap::new();
        for item_object_path in items {
            let Some(known) = self
                .topology
                .items
                .iter()
                .find(|known| known.path == item_object_path)
            else {
                continue;
            };
            let value = self
                .state
                .backend()
                .get_field(&known.vault, &known.item, &known.field)
                .map_err(|error| zbus::fdo::Error::Failed(error.to_string()))?;
            secrets.insert(
                item_object_path,
                Secret {
                    session: session.clone(),
                    parameters: Vec::new(),
                    value: value.expose_secret().as_bytes().to_vec(),
                    content_type: "text/plain".to_string(),
                },
            );
        }
        Ok(secrets)
    }

    /// Resolves the well-known `"default"` alias to the first vault, if
    /// any. No other aliases are recognised in the MVP.
    fn read_alias(&self, name: &str) -> OwnedObjectPath {
        if name == "default"
            && let Some(first) = self.topology.vaults.first()
        {
            return collection_path(first);
        }
        "/".try_into().expect("valid object path")
    }

    /// Not supported: alias assignment would need to persist across
    /// restarts, which the MVP's static topology does not attempt.
    fn set_alias(&self, _name: &str, _collection: OwnedObjectPath) -> zbus::fdo::Result<()> {
        Err(zbus::fdo::Error::NotSupported(
            "setting aliases is not supported in this MVP".to_string(),
        ))
    }
}
