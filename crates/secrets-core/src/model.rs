//! The generic vault/item/field data model.
//!
//! Deliberately not password-shaped: a [`Field`] can hold a username, a
//! TOTP seed, an SSH private key, a certificate, or an arbitrary custom
//! value. Nothing here assumes "the" secret an item holds is a password.

use crate::uri::ItemPath;

/// A named collection of items.
///
/// Maps to an `org.freedesktop.Secret.Collection` in the Secret Service
/// compatibility layer, and to whatever grouping concept the active backend
/// uses natively (a Bitwarden/Vaultwarden "organization vault", a `pass`
/// store, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vault {
    /// The vault's name, as it appears in a `secret://` URI.
    pub name: String,
}

impl Vault {
    /// Name a vault.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// What kind of thing a [`Field`] holds.
///
/// This is metadata describing the field's *shape*, never its value — a
/// `FieldKind` is safe to list, log or display; a field's content never is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldKind {
    /// An account identifier — not itself secret, but part of the pair
    /// with a password.
    Username,
    /// A password or passphrase.
    Password,
    /// A TOTP seed (the shared secret, not a generated code).
    Totp,
    /// An SSH private key.
    SshKey,
    /// An X.509 (or similar) certificate. Frequently not secret at all, but
    /// stored alongside its private key for convenience.
    Certificate,
    /// A private key that is not specifically an SSH key (e.g. a TLS
    /// client key).
    PrivateKey,
    /// Free-form text with no more specific shape.
    Note,
    /// Anything else, named by the backend or the user.
    Custom(String),
}

/// One named value within an item, without its content.
///
/// Listing an item's fields must never require reading their values —
/// that is exactly the operation locking exists to gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldMeta {
    /// The field's name, as it appears as the last segment of a
    /// `secret://` URI.
    pub name: String,
    /// What kind of value this field holds.
    pub kind: FieldKind,
}

/// A named entry within a [`Vault`], holding one or more fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// The item's path within its vault (one or more segments).
    pub path: ItemPath,
    /// The fields this item holds, without their values.
    pub fields: Vec<FieldMeta>,
}

impl Item {
    /// Whether this item declares a field with the given name.
    #[must_use]
    pub fn has_field(&self, name: &str) -> bool {
        self.fields.iter().any(|field| field.name == name)
    }
}
