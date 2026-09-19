//! `org.freedesktop.Secret.Item`: one per (store, vault, item, field)
//! quadruple (ADR-018).
//!
//! Secret Service items hold exactly one secret value each, but a
//! `secrets-core` item can hold several fields — so each field of a
//! `secrets-core` item is exposed as its own `Item` object here, labelled
//! to make the relationship legible (`"GitHub (password)"`).

use std::collections::HashMap;
use std::sync::Arc;

use secrets_core::{ItemPath, StoreId};

use super::Secret;
use crate::state::DaemonState;

/// One (store, vault, item, field) quadruple.
pub struct ItemIface {
    state: Arc<DaemonState>,
    store: StoreId,
    vault: String,
    item: ItemPath,
    field: String,
}

impl ItemIface {
    /// Wrap one field as a servable Secret Service item.
    #[must_use]
    pub fn new(
        state: Arc<DaemonState>,
        store: StoreId,
        vault: String,
        item: ItemPath,
        field: String,
    ) -> Self {
        Self {
            state,
            store,
            vault,
            item,
            field,
        }
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl ItemIface {
    /// Whether this item is currently readable — reflects both this
    /// store's own lock and its own session state (see
    /// [`crate::state::DaemonState::is_accessible`]), so a 1Password
    /// session that needs (re)authentication shows as locked here too, not
    /// just through `org.secrets.Manager`.
    #[zbus(property)]
    fn locked(&self) -> bool {
        !self.state.is_accessible(&self.store)
    }

    /// `store`, `vault`, `item` and `field`, so
    /// `Service`/`Collection.SearchItems` have something to match
    /// against.
    #[zbus(property)]
    fn attributes(&self) -> HashMap<String, String> {
        HashMap::from([
            ("store".to_string(), self.store.to_string()),
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
    /// Fails while locked, while this store's own session needs
    /// (re)authentication, or if the value cannot be decrypted.
    fn get_secret(&self, session: zbus::zvariant::OwnedObjectPath) -> zbus::fdo::Result<Secret> {
        let value = self
            .state
            .read_field(&self.store, &self.vault, &self.item, &self.field)
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use secrets_core::BackendStatus;

    use super::*;
    use crate::test_support::{
        default_store_id, state_over_fresh_vault, state_with_backend_session,
    };

    fn item_over(state: DaemonState) -> ItemIface {
        ItemIface::new(
            Arc::new(state),
            default_store_id(),
            "Personal".to_string(),
            ItemPath::new(vec!["GitHub".to_string()]).unwrap(),
            "password".to_string(),
        )
    }

    #[test]
    fn locked_reflects_the_store_lock_alone_when_the_backend_has_no_session() {
        let (_dir, state) = state_over_fresh_vault();
        let item = item_over(state);
        assert!(item.locked());
    }

    #[test]
    fn locked_is_false_once_unlocked_with_no_backend_session() {
        let (_dir, state) = state_over_fresh_vault();
        state
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();
        let item = item_over(state);
        assert!(!item.locked());
    }

    #[test]
    fn locked_reports_true_when_the_backend_session_requires_authentication_even_if_unlocked() {
        // Regression guard for #7: an `AlwaysUnlocked` backend (like
        // 1Password) must not make `Item.Locked` report `false` while its
        // own session is unmet.
        let (_dir, state) = state_with_backend_session(BackendStatus::RequiresAuthentication);
        state
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();
        let item = item_over(state);
        assert!(item.locked());
    }

    #[test]
    fn get_secret_fails_when_the_backend_session_requires_authentication() {
        let (_dir, state) = state_with_backend_session(BackendStatus::RequiresAuthentication);
        state
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();
        let item = item_over(state);
        let session: zbus::zvariant::OwnedObjectPath =
            super::super::SESSION_PATH.try_into().unwrap();
        assert!(item.get_secret(session).is_err());
    }

    #[test]
    fn get_secret_succeeds_when_accessible() {
        let (_dir, state) = state_over_fresh_vault();
        state
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();
        let item = item_over(state);
        let session: zbus::zvariant::OwnedObjectPath =
            super::super::SESSION_PATH.try_into().unwrap();
        let secret = item.get_secret(session).unwrap();
        assert_eq!(
            String::from_utf8(secret.value).unwrap(),
            "correct horse battery staple"
        );
    }
}
