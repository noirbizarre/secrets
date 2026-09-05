//! The `secret://` URI scheme: parsing, validation and canonical formatting.
//!
//! Canonical shape: `secret://<vault>/<item...>/<field>`. `<item...>` is one
//! or more path segments — most items are a single segment (`GitHub`), but a
//! vault may nest items in folders (`Production/database`), and the last
//! segment is always the field. See `docs/secret-uri.md` for the full
//! rationale and worked examples.
//!
//! Any segment may contain a literal `/`, `%`, or non-ASCII byte as long as
//! it is percent-encoded (RFC 3986 `pct-encoded`) — that is how a caller
//! tells "part of this name" apart from "the next path segment".

use std::fmt;
use std::str::FromStr;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

/// The literal scheme prefix. Matched case-sensitively: `Secret://` is not
/// a `secret://` URI, the same way `HTTP://` is not `http://` in most
/// clients — being lenient here would just move the "which form is
/// canonical" question to every consumer instead of answering it once.
const SCHEME: &str = "secret://";

/// Characters left unescaped inside a single path component.
///
/// Everything else — including `/`, so a literal slash inside a name is
/// unambiguous against the structural separator — is percent-encoded.
/// Matches URI "unreserved" (RFC 3986 §2.3) plus nothing else, which is the
/// smallest set that round-trips through every `secret://` consumer without
/// needing further escaping downstream (shells, JSON, D-Bus object paths).
const COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// One or more path segments identifying an item within a vault.
///
/// Most items are a single segment. A vault that organises items in folders
/// (`Infrastructure/Production/database`) uses more than one — the model
/// does not distinguish "folder" from "item", it is simply a path, same as
/// most password managers' own folder support.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ItemPath(Vec<String>);

impl ItemPath {
    /// Build an item path from already-decoded segments.
    ///
    /// # Errors
    ///
    /// Returns [`UriError::EmptyItem`] if `segments` is empty, or
    /// [`UriError::EmptyItemSegment`] if any segment is the empty string —
    /// both would otherwise silently collapse two different item paths.
    pub fn new(segments: Vec<String>) -> Result<Self, UriError> {
        if segments.is_empty() {
            return Err(UriError::EmptyItem);
        }
        if segments.iter().any(String::is_empty) {
            return Err(UriError::EmptyItemSegment);
        }
        Ok(Self(segments))
    }

    /// The path's segments, in order, root-most first.
    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.0
    }
}

impl fmt::Display for ItemPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, segment) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, "/")?;
            }
            write!(f, "{}", utf8_percent_encode(segment, COMPONENT))?;
        }
        Ok(())
    }
}

/// A parsed `secret://<vault>/<item...>/<field>` reference.
///
/// Immutable and cheap to clone; construct it once at the edge (CLI argument,
/// D-Bus method argument) and pass it inward instead of re-parsing the
/// string at each layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretUri {
    vault: String,
    item: ItemPath,
    field: String,
}

impl SecretUri {
    /// Build a URI from already-decoded parts.
    ///
    /// # Errors
    ///
    /// Returns [`UriError::EmptyVault`] or [`UriError::EmptyField`] if
    /// either is the empty string.
    pub fn new(
        vault: impl Into<String>,
        item: ItemPath,
        field: impl Into<String>,
    ) -> Result<Self, UriError> {
        let vault = vault.into();
        let field = field.into();
        if vault.is_empty() {
            return Err(UriError::EmptyVault);
        }
        if field.is_empty() {
            return Err(UriError::EmptyField);
        }
        Ok(Self { vault, item, field })
    }

    /// Parse a `secret://` string into its typed representation.
    ///
    /// # Errors
    ///
    /// Returns a [`UriError`] describing exactly what was wrong: a missing
    /// scheme, too few components, an empty component, or invalid
    /// percent-encoding.
    pub fn parse(input: &str) -> Result<Self, UriError> {
        let rest = input
            .strip_prefix(SCHEME)
            .ok_or_else(|| UriError::MissingScheme(input.to_string()))?;

        // Split first, decode second: a `%2F` must never be mistaken for a
        // structural separator, so splitting on the still-encoded string is
        // the only order that keeps the two apart.
        let raw_segments: Vec<&str> = rest.split('/').collect();
        if raw_segments.len() < 3 {
            return Err(UriError::TooFewComponents(input.to_string()));
        }

        let mut decoded = Vec::with_capacity(raw_segments.len());
        for raw in &raw_segments {
            let segment = percent_decode_str(raw)
                .decode_utf8()
                .map_err(|_| UriError::InvalidEncoding((*raw).to_string()))?
                .into_owned();
            if segment.is_empty() {
                return Err(UriError::EmptyComponent(input.to_string()));
            }
            decoded.push(segment);
        }

        // `raw_segments.len() >= 3` was checked above, so both ends exist.
        let field = decoded.pop().expect("checked length above");
        let vault = decoded.remove(0);
        let item = ItemPath::new(decoded)?;
        Ok(Self { vault, item, field })
    }

    /// The vault name.
    #[must_use]
    pub fn vault(&self) -> &str {
        &self.vault
    }

    /// The item path (one or more segments).
    #[must_use]
    pub fn item(&self) -> &ItemPath {
        &self.item
    }

    /// The field name — always the URI's last segment.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }
}

impl fmt::Display for SecretUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "secret://{}/{}/{}",
            utf8_percent_encode(&self.vault, COMPONENT),
            self.item,
            utf8_percent_encode(&self.field, COMPONENT)
        )
    }
}

impl FromStr for SecretUri {
    type Err = UriError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Everything that can be wrong about a `secret://` string.
///
/// Every variant carries only the offending *reference* (a URI or a raw
/// component), never a secret value — a malformed URI cannot itself be a
/// secret's content, so it is always safe to log or display.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UriError {
    /// Did not start with `secret://`.
    #[error("not a secret:// URI: {0:?}")]
    MissingScheme(String),

    /// Fewer than three `/`-separated components after the scheme.
    #[error("expected secret://<vault>/<item>/<field>, got: {0:?}")]
    TooFewComponents(String),

    /// One of the components decoded to the empty string.
    #[error("empty path component in: {0:?}")]
    EmptyComponent(String),

    /// A vault name was explicitly empty.
    #[error("vault name cannot be empty")]
    EmptyVault,

    /// A field name was explicitly empty.
    #[error("field name cannot be empty")]
    EmptyField,

    /// An item path had zero segments.
    #[error("item path cannot be empty")]
    EmptyItem,

    /// A segment within an item path was empty.
    #[error("item path segment cannot be empty")]
    EmptyItemSegment,

    /// A component's percent-encoding did not decode to valid UTF-8.
    #[error("invalid percent-encoding in component: {0:?}")]
    InvalidEncoding(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use rstest::rstest;

    #[rstest]
    #[case("secret://Personal/GitHub/username", "Personal", &["GitHub"], "username")]
    #[case("secret://Personal/GitHub/password", "Personal", &["GitHub"], "password")]
    #[case("secret://Personal/GitHub/totp", "Personal", &["GitHub"], "totp")]
    #[case(
        "secret://Infrastructure/Production/database/password",
        "Infrastructure",
        &["Production", "database"],
        "password"
    )]
    #[case(
        "secret://Infrastructure/Production/ssh-key",
        "Infrastructure",
        &["Production"],
        "ssh-key"
    )]
    #[case("secret://PKI/example.com/certificate", "PKI", &["example.com"], "certificate")]
    #[case("secret://PKI/example.com/private-key", "PKI", &["example.com"], "private-key")]
    #[case("secret://PKI/example.com/chain", "PKI", &["example.com"], "chain")]
    fn every_documented_example_parses_into_its_named_parts(
        #[case] input: &str,
        #[case] vault: &str,
        #[case] item: &[&str],
        #[case] field: &str,
    ) {
        let uri = SecretUri::parse(input).expect("documented example must parse");
        assert_eq!(uri.vault(), vault);
        assert_eq!(uri.item().segments(), item);
        assert_eq!(uri.field(), field);
    }

    #[test]
    fn parsing_and_displaying_a_uri_round_trips_it() {
        let input = "secret://Infrastructure/Production/database/password";
        let uri = SecretUri::parse(input).unwrap();
        assert_eq!(uri.to_string(), input);
    }

    #[test]
    fn a_percent_encoded_slash_stays_inside_its_own_segment() {
        // "My/Folder" is ONE item segment because its slash is escaped, not
        // two segments the way an unescaped slash would split it.
        let uri = SecretUri::parse("secret://Personal/My%2FFolder/password").unwrap();
        assert_eq!(uri.item().segments(), ["My/Folder"]);
        // Round-tripping must re-escape it, or the next parse would split it.
        assert_eq!(uri.to_string(), "secret://Personal/My%2FFolder/password");
    }

    #[test]
    fn a_string_without_the_scheme_is_rejected() {
        let err = SecretUri::parse("Personal/GitHub/password").unwrap_err();
        assert_eq!(
            err,
            UriError::MissingScheme("Personal/GitHub/password".to_string())
        );
    }

    #[test]
    fn a_uri_missing_the_field_is_rejected() {
        let err = SecretUri::parse("secret://Personal/GitHub").unwrap_err();
        assert_eq!(
            err,
            UriError::TooFewComponents("secret://Personal/GitHub".to_string())
        );
    }

    #[test]
    fn a_uri_with_only_a_scheme_is_rejected() {
        let err = SecretUri::parse("secret://").unwrap_err();
        assert_eq!(err, UriError::TooFewComponents("secret://".to_string()));
    }

    #[test]
    fn an_empty_middle_component_is_rejected() {
        let err = SecretUri::parse("secret://Personal//password").unwrap_err();
        assert_eq!(
            err,
            UriError::EmptyComponent("secret://Personal//password".to_string())
        );
    }

    #[test]
    fn a_trailing_slash_leaves_an_empty_field_and_is_rejected() {
        let err = SecretUri::parse("secret://Personal/GitHub/").unwrap_err();
        assert_eq!(
            err,
            UriError::EmptyComponent("secret://Personal/GitHub/".to_string())
        );
    }

    #[test]
    fn constructing_from_parts_rejects_an_empty_vault() {
        let item = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
        let err = SecretUri::new("", item, "password").unwrap_err();
        assert_eq!(err, UriError::EmptyVault);
    }

    #[test]
    fn constructing_from_parts_rejects_an_empty_field() {
        let item = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
        let err = SecretUri::new("Personal", item, "").unwrap_err();
        assert_eq!(err, UriError::EmptyField);
    }

    #[test]
    fn an_item_path_with_no_segments_is_rejected() {
        let err = ItemPath::new(vec![]).unwrap_err();
        assert_eq!(err, UriError::EmptyItem);
    }

    #[test]
    fn an_item_path_with_an_empty_segment_is_rejected() {
        let err = ItemPath::new(vec!["Production".to_string(), String::new()]).unwrap_err();
        assert_eq!(err, UriError::EmptyItemSegment);
    }

    #[test]
    fn parsing_is_case_sensitive_on_the_scheme() {
        let err = SecretUri::parse("Secret://Personal/GitHub/password").unwrap_err();
        assert_eq!(
            err,
            UriError::MissingScheme("Secret://Personal/GitHub/password".to_string())
        );
    }
}
