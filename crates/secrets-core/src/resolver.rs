//! Turns a parsed [`SecretUri`] into a value, via a [`Backend`].
//!
//! This is the one place that connects the URI parser to the backend
//! contract. It knows nothing about D-Bus, sessions, or locking — those are
//! `secretsd`'s job, layered on top by checking lock state before ever
//! constructing a `Resolver` call.

use crate::backend::Backend;
use crate::error::Result;
use crate::model::{Item, Vault};
use crate::secret_value::SecretValue;
use crate::uri::SecretUri;

/// Resolves `secret://` references against a [`Backend`].
///
/// Borrows the backend rather than owning it, so callers can hold it behind
/// whatever synchronization they need (a `Mutex`, an `Arc`) and construct a
/// short-lived `Resolver` per request.
pub struct Resolver<'a> {
    backend: &'a dyn Backend,
}

impl<'a> Resolver<'a> {
    /// Resolve against the given backend.
    #[must_use]
    pub fn new(backend: &'a dyn Backend) -> Self {
        Self { backend }
    }

    /// Resolve a URI to its field value.
    ///
    /// # Errors
    ///
    /// Propagates whatever the backend returns — typically
    /// [`crate::error::CoreError::NotFound`] for an unknown vault, item or
    /// field.
    pub fn resolve(&self, uri: &SecretUri) -> Result<SecretValue> {
        self.backend.get_field(uri.vault(), uri.item(), uri.field())
    }

    /// List every vault the backend exposes.
    ///
    /// # Errors
    ///
    /// Propagates the backend's error, if any.
    pub fn list_vaults(&self) -> Result<Vec<Vault>> {
        self.backend.list_vaults()
    }

    /// List the items (with field metadata, not values) within a vault.
    ///
    /// # Errors
    ///
    /// Propagates the backend's error, if any.
    pub fn list_items(&self, vault: &str) -> Result<Vec<Item>> {
        self.backend.list_items(vault)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CoreError;
    use crate::model::{FieldKind, FieldMeta};
    use crate::uri::ItemPath;
    use pretty_assertions::assert_eq;

    /// A backend fixed at construction time, just enough to exercise the
    /// resolver without a real store.
    struct FixedBackend;

    impl Backend for FixedBackend {
        fn list_vaults(&self) -> Result<Vec<Vault>> {
            Ok(vec![Vault::new("Personal")])
        }

        fn list_items(&self, vault: &str) -> Result<Vec<Item>> {
            if vault != "Personal" {
                return Err(CoreError::NotFound {
                    vault: vault.to_string(),
                    item: String::new(),
                    field: String::new(),
                });
            }
            Ok(vec![Item {
                path: ItemPath::new(vec!["GitHub".to_string()]).unwrap(),
                fields: vec![FieldMeta {
                    name: "password".to_string(),
                    kind: FieldKind::Password,
                }],
            }])
        }

        fn get_field(&self, vault: &str, item: &ItemPath, field: &str) -> Result<SecretValue> {
            if vault == "Personal" && item.segments() == ["GitHub"] && field == "password" {
                Ok(SecretValue::new("hunter2".to_string()))
            } else {
                Err(CoreError::NotFound {
                    vault: vault.to_string(),
                    item: item.to_string(),
                    field: field.to_string(),
                })
            }
        }
    }

    #[test]
    fn resolving_a_known_uri_returns_its_value() {
        let backend = FixedBackend;
        let resolver = Resolver::new(&backend);
        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();

        let value = resolver.resolve(&uri).unwrap();

        assert_eq!(value.expose_secret(), "hunter2");
    }

    #[test]
    fn resolving_an_unknown_field_reports_not_found_without_the_value() {
        let backend = FixedBackend;
        let resolver = Resolver::new(&backend);
        let uri = SecretUri::parse("secret://Personal/GitHub/totp").unwrap();

        let error = resolver.resolve(&uri).unwrap_err();

        assert!(matches!(error, CoreError::NotFound { .. }));
        // The error must name what was searched, never a value.
        assert!(!error.to_string().contains("hunter2"));
    }

    #[test]
    fn listing_items_returns_field_metadata_without_values() {
        let backend = FixedBackend;
        let resolver = Resolver::new(&backend);

        let items = resolver.list_items("Personal").unwrap();

        assert_eq!(items.len(), 1);
        assert!(items[0].has_field("password"));
    }
}
