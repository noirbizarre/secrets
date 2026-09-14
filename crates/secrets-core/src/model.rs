//! The generic vault/item/field data model.
//!
//! Deliberately not password-shaped: a [`Field`] can hold a username, a
//! TOTP seed, an SSH private key, a certificate, or an arbitrary custom
//! value. Nothing here assumes "the" secret an item holds is a password.

use std::fmt;
use std::str::FromStr;

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

impl FieldKind {
    /// Whether a field of this kind's *value* must never be fetched from
    /// the backend, or displayed, by anything that shows field values
    /// without an explicit `get`-style request for that specific field —
    /// see `secrets show` (ADR-016).
    ///
    /// `false` only for `Username` and `Certificate`, per this enum's own
    /// doc comments: a username is "not itself secret", and a certificate
    /// is "frequently not secret at all". Every other kind — including
    /// `Note` and `Custom`, whose actual content this type cannot predict
    /// — defaults to `true` (fail closed: an unknown shape is treated as
    /// sensitive, not assumed safe).
    ///
    /// This is a different question from whether the *kind tag itself* is
    /// safe to display — it always is, per the doc comment above this
    /// enum. This method is about the value the field holds, never the
    /// kind naming it.
    #[must_use]
    pub fn is_secret(&self) -> bool {
        !matches!(self, FieldKind::Username | FieldKind::Certificate)
    }
}

/// Canonical lowercase string form, used both for the local backend's TOML
/// serialization (`secretsd::backend::local`) and for `FieldDisplay`'s
/// wire representation (`secrets_core::dbus`) — one string scheme, so the
/// two never drift apart. `Custom` renders as `"custom:<name>"`.
impl fmt::Display for FieldKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FieldKind::Username => write!(f, "username"),
            FieldKind::Password => write!(f, "password"),
            FieldKind::Totp => write!(f, "totp"),
            FieldKind::SshKey => write!(f, "ssh-key"),
            FieldKind::Certificate => write!(f, "certificate"),
            FieldKind::PrivateKey => write!(f, "private-key"),
            FieldKind::Note => write!(f, "note"),
            FieldKind::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

/// Parses the exact inverse of [`FieldKind`]'s `Display` impl. Never
/// fails: an unrecognized string becomes `Custom(other)`, the same
/// fallback `Display`/`FromStr`'s callers (the local backend, 1Password
/// backend's own heuristic) already use for anything they don't
/// recognize either.
impl FromStr for FieldKind {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "username" => FieldKind::Username,
            "password" => FieldKind::Password,
            "totp" => FieldKind::Totp,
            "ssh-key" => FieldKind::SshKey,
            "certificate" => FieldKind::Certificate,
            "private-key" => FieldKind::PrivateKey,
            "note" => FieldKind::Note,
            other => FieldKind::Custom(other.strip_prefix("custom:").unwrap_or(other).to_string()),
        })
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    #[rstest]
    #[case(FieldKind::Username, false)]
    #[case(FieldKind::Password, true)]
    #[case(FieldKind::Totp, true)]
    #[case(FieldKind::SshKey, true)]
    #[case(FieldKind::Certificate, false)]
    #[case(FieldKind::PrivateKey, true)]
    #[case(FieldKind::Note, true)]
    #[case(FieldKind::Custom("recovery-code".to_string()), true)]
    fn is_secret_matches_the_documented_classification(
        #[case] kind: FieldKind,
        #[case] expected: bool,
    ) {
        assert_eq!(kind.is_secret(), expected);
    }

    #[rstest]
    #[case(FieldKind::Username, "username")]
    #[case(FieldKind::Password, "password")]
    #[case(FieldKind::Totp, "totp")]
    #[case(FieldKind::SshKey, "ssh-key")]
    #[case(FieldKind::Certificate, "certificate")]
    #[case(FieldKind::PrivateKey, "private-key")]
    #[case(FieldKind::Note, "note")]
    #[case(FieldKind::Custom("recovery-code".to_string()), "custom:recovery-code")]
    fn display_and_from_str_round_trip(#[case] kind: FieldKind, #[case] rendered: &str) {
        assert_eq!(kind.to_string(), rendered);
        assert_eq!(rendered.parse::<FieldKind>().unwrap(), kind);
    }

    #[test]
    fn from_str_never_fails_falling_back_to_custom() {
        // Mirrors the 1Password backend's own "unrecognized becomes
        // Custom, never a failure" heuristic (ADR-012).
        assert_eq!(
            "something-unheard-of".parse::<FieldKind>().unwrap(),
            FieldKind::Custom("something-unheard-of".to_string())
        );
    }
}
