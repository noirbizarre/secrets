//! A store's identity: the name a `secretsd.toml` `[store.<id>]` table
//! assigns to one configured backend instance.
//!
//! Distinct from a vault name (see `crate::model::Vault`): one store can
//! expose several named vaults (a local vault file's `vaults` map, or a
//! 1Password account's own vault list). `StoreId` is the identifier for
//! the *instance*, not for what it contains — see ADR-018.

use std::fmt;
use std::str::FromStr;

/// A config-assigned name identifying one backend instance (a "store").
///
/// The charset is deliberately narrow — ASCII letters, digits, `-` and
/// `_`, starting with a letter or digit — so a `StoreId` never needs
/// percent-encoding anywhere it appears: a `secret://` URI's `store@`
/// segment (ADR-018), a TOML table key, or a D-Bus object path segment.
/// One guaranteed-safe representation beats three encodings kept in sync
/// by hand. `@` is excluded by construction, which is exactly why it is
/// safe to use as the URI's store/vault separator: a valid `StoreId` can
/// never be mistaken for part of that separator.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StoreId(String);

impl StoreId {
    /// Validate and wrap a store id.
    ///
    /// # Errors
    ///
    /// Returns [`StoreIdError::Empty`] for the empty string, or
    /// [`StoreIdError::InvalidCharacters`] if any character is outside
    /// `[A-Za-z0-9_-]`.
    pub fn new(input: impl Into<String>) -> Result<Self, StoreIdError> {
        let input = input.into();
        if input.is_empty() {
            return Err(StoreIdError::Empty);
        }
        if !input
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(StoreIdError::InvalidCharacters(input));
        }
        Ok(Self(input))
    }

    /// The store id's underlying string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for StoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for StoreId {
    type Err = StoreIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl TryFrom<String> for StoreId {
    type Error = StoreIdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<StoreId> for String {
    fn from(value: StoreId) -> Self {
        value.0
    }
}

// `try_from`/`into` (rather than a hand-rolled `Deserialize`/`Serialize`)
// so a `StoreId` works unmodified as a `BTreeMap<StoreId, _>` TOML table
// key (serde requires `Deserialize` on map keys) and as a plain JSON
// string in CLI output, with validation enforced in exactly one place
// (`StoreId::new`).
impl serde::Serialize for StoreId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for StoreId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Everything that can be wrong about a [`StoreId`].
///
/// Carries only the offending id or nothing at all — a store id is a
/// configuration identifier, never a secret.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreIdError {
    /// The empty string is not a valid store id.
    #[error("store id cannot be empty")]
    Empty,

    /// Contained a character outside `[A-Za-z0-9_-]`.
    #[error(
        "invalid store id {0:?}: must contain only ASCII letters, digits, '-' or '_' (an '@' or '/' would be ambiguous with the secret:// grammar)"
    )]
    InvalidCharacters(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    #[rstest]
    #[case("default")]
    #[case("work")]
    #[case("Personal-Vault_2")]
    #[case("a")]
    #[case("1password")]
    fn a_valid_store_id_is_accepted(#[case] input: &str) {
        let id = StoreId::new(input).expect("valid store id must be accepted");
        assert_eq!(id.as_str(), input);
    }

    #[test]
    fn an_empty_store_id_is_rejected() {
        let err = StoreId::new("").unwrap_err();
        assert_eq!(err, StoreIdError::Empty);
    }

    #[rstest]
    #[case("has space")]
    #[case("has/slash")]
    #[case("has@sign")]
    #[case("emoji😀")]
    fn an_invalid_store_id_is_rejected(#[case] input: &str) {
        let err = StoreId::new(input).unwrap_err();
        assert_eq!(err, StoreIdError::InvalidCharacters(input.to_string()));
    }

    #[test]
    fn display_and_from_str_round_trip() {
        let id = StoreId::new("work").unwrap();
        assert_eq!(id.to_string(), "work");
        assert_eq!("work".parse::<StoreId>().unwrap(), id);
    }

    #[test]
    fn a_store_id_deserializes_as_a_toml_map_key() {
        use std::collections::BTreeMap;

        let map: BTreeMap<StoreId, i32> = toml::from_str("default = 1\nwork = 2\n").unwrap();
        assert_eq!(map[&StoreId::new("default").unwrap()], 1);
        assert_eq!(map[&StoreId::new("work").unwrap()], 2);
    }

    #[test]
    fn an_invalid_toml_map_key_is_rejected_with_the_store_id_error() {
        let result: Result<std::collections::BTreeMap<StoreId, i32>, _> =
            toml::from_str("\"has space\" = 1\n");
        let error = result.unwrap_err().to_string();
        assert!(error.contains("must contain only ASCII letters"));
    }
}
