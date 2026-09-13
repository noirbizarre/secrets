//! `org.freedesktop.Secret.Service`, the entry point clients discover at
//! `/org/freedesktop/secrets`.

use std::collections::HashMap;
use std::sync::Arc;

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
        // Reflects both the daemon-wide lock and the active backend's own
        // session state (see `DaemonState::is_accessible`) — not just the
        // daemon lock, so a 1Password session needing (re)authentication
        // reports matches as locked here too.
        let accessible_now = self.state.is_accessible();
        let matches: Vec<OwnedObjectPath> = self
            .matching_items(&attributes)
            .into_iter()
            .map(|known| known.path.clone())
            .collect();
        if accessible_now {
            (matches, Vec::new())
        } else {
            (Vec::new(), matches)
        }
    }

    /// Reflects the daemon-wide lock *and* backend session state for the
    /// given objects. Cannot itself prompt for a passphrase (see
    /// [`super::prompt`]) — an object that is still locked stays in
    /// `locked`, with the shared prompt object returned for spec-compliant
    /// discoverability, not because it can do anything about it. Use
    /// `secrets unlock` instead (and, for a backend session needing
    /// reauthorization, its own app — see `docs/backends/1password.md`).
    fn unlock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        let prompt: OwnedObjectPath = PROMPT_PATH.try_into().expect("valid object path");
        if self.state.is_accessible() {
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
                .read_field(&known.vault, &known.item, &known.field)
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

#[cfg(test)]
mod tests {
    use secrets_core::{BackendStatus, ItemPath};

    use super::*;
    use crate::test_support::{state_over_fresh_vault, state_with_backend_session};

    fn topology_over_github_password() -> Topology {
        let item = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
        let path = super::super::item_path("Personal", &item, "password");
        Topology {
            vaults: vec!["Personal".to_string()],
            items: vec![super::super::KnownItem {
                vault: "Personal".to_string(),
                item,
                field: "password".to_string(),
                path,
            }],
        }
    }

    fn service_over(state: DaemonState) -> ServiceIface {
        ServiceIface::new(Arc::new(state), topology_over_github_password())
    }

    #[test]
    fn search_items_reports_matches_as_locked_when_the_backend_session_requires_authentication() {
        // Regression guard for #7: an `AlwaysUnlocked` backend (like
        // 1Password) must still show `SearchItems` matches as locked when
        // its own session is unmet.
        let (_dir, state) = state_with_backend_session(BackendStatus::RequiresAuthentication);
        state.unlock("test passphrase").unwrap();
        let service = service_over(state);

        let (unlocked, locked) = service.search_items(HashMap::from([(
            "vault".to_string(),
            "Personal".to_string(),
        )]));
        assert!(unlocked.is_empty());
        assert_eq!(locked.len(), 1);
    }

    #[test]
    fn search_items_reports_matches_as_unlocked_when_accessible() {
        let (_dir, state) = state_over_fresh_vault();
        state.unlock("test passphrase").unwrap();
        let service = service_over(state);

        let (unlocked, locked) = service.search_items(HashMap::from([(
            "vault".to_string(),
            "Personal".to_string(),
        )]));
        assert_eq!(unlocked.len(), 1);
        assert!(locked.is_empty());
    }

    #[test]
    fn get_secrets_fails_when_the_backend_session_requires_authentication() {
        let (_dir, state) = state_with_backend_session(BackendStatus::RequiresAuthentication);
        state.unlock("test passphrase").unwrap();
        let service = service_over(state);
        let topology = topology_over_github_password();
        let session: OwnedObjectPath = SESSION_PATH.try_into().unwrap();

        let result = service.get_secrets(vec![topology.items[0].path.clone()], session);
        assert!(result.is_err());
    }

    #[test]
    fn get_secrets_succeeds_when_accessible() {
        let (_dir, state) = state_over_fresh_vault();
        state.unlock("test passphrase").unwrap();
        let service = service_over(state);
        let topology = topology_over_github_password();
        let session: OwnedObjectPath = SESSION_PATH.try_into().unwrap();

        let secrets = service
            .get_secrets(vec![topology.items[0].path.clone()], session)
            .unwrap();
        let secret = secrets.values().next().unwrap();
        assert_eq!(
            String::from_utf8(secret.value.clone()).unwrap(),
            "correct horse battery staple"
        );
    }
}
