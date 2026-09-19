//! The `secret://` URI scheme: parsing, validation and canonical formatting.
//!
//! Canonical shape: `secret://[<store>@]<vault>/<item...>/<field>`.
//! `<item...>` is one or more path segments — most items are a single
//! segment (`GitHub`), but a vault may nest items in folders
//! (`Production/database`), and the last segment is always the field. The
//! optional, userinfo-style `<store>@` prefix names which configured store
//! (backend instance) the vault lives in — see ADR-018; omitting it keeps
//! every URI written before ADR-018 parsing identically. See
//! `docs/secret-uri.md` for the full rationale and worked examples.
//!
//! Any segment may contain a literal `/`, `%`, or non-ASCII byte as long as
//! it is percent-encoded (RFC 3986 `pct-encoded`) — that is how a caller
//! tells "part of this name" apart from "the next path segment". The same
//! applies to a literal `@` in a vault name: percent-encode it (`%40`) so
//! it is not mistaken for the store separator, which is detected on
//! undecoded bytes.

use std::fmt;
use std::str::FromStr;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

use crate::store_id::StoreId;

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

/// Split `rest` (the string after `secret://`, still percent-encoded)
/// into an optional raw store segment and the remainder with that
/// segment's `<store>@` prefix removed.
///
/// Detection is scoped to the *first* `/`-bounded segment only — an `@`
/// appearing in an item or field segment is not structural and is left
/// untouched — and happens on undecoded bytes, mirroring how `/` is
/// detected before decoding in [`decode_segments`]: a percent-encoded `@`
/// (`%40`) can never be mistaken for the separator, since decoding never
/// happens before this split.
///
/// # Errors
///
/// Returns [`UriError::EmptyStore`] if `@` appears with nothing before it
/// (`secret://@vault/...`).
fn split_store(rest: &str) -> Result<(Option<&str>, &str), UriError> {
    let first_segment_end = rest.find('/').unwrap_or(rest.len());
    let first_segment = &rest[..first_segment_end];
    match first_segment.find('@') {
        None => Ok((None, rest)),
        Some(0) => Err(UriError::EmptyStore),
        Some(at) => Ok((Some(&first_segment[..at]), &rest[at + 1..])),
    }
}

/// Percent-decode a raw store segment and validate it as a [`StoreId`].
///
/// # Errors
///
/// Returns [`UriError::InvalidEncoding`] if the segment's percent-encoding
/// is not valid UTF-8, or [`UriError::InvalidStore`] if it decodes but
/// fails [`StoreId`]'s own validation.
fn decode_store(raw: &str) -> Result<StoreId, UriError> {
    let decoded = percent_decode_str(raw)
        .decode_utf8()
        .map_err(|_| UriError::InvalidEncoding(raw.to_string()))?
        .into_owned();
    StoreId::new(decoded.clone()).map_err(|_| UriError::InvalidStore(decoded))
}

/// Split on `/` and percent-decode each component of `remainder` — the
/// part of a `secret://` reference left after the scheme and any
/// `<store>@` prefix have already been removed.
///
/// Shared by [`SecretUri::parse`] and [`ItemUri::parse`] so the two never
/// decode the same string two different ways — they differ only in
/// `min_components` (three for a vault/item/field, two for a vault/item)
/// and how they carve up the result. The length check happens against
/// the still-encoded, still-undecoded segments, before any per-segment
/// emptiness check — so a too-short input is always reported as
/// [`UriError::TooFewComponents`], never [`UriError::EmptyComponent`],
/// matching the order a caller reads the two errors in. `original` is the
/// full, unmodified input string, used only for error messages, so an
/// error always echoes back exactly what the caller passed in — store
/// prefix included.
///
/// # Errors
///
/// Returns [`UriError::TooFewComponents`] if fewer than `min_components`
/// components remain, [`UriError::EmptyComponent`] if any component
/// decodes to the empty string, or [`UriError::InvalidEncoding`] if a
/// component's percent-encoding is not valid UTF-8.
fn decode_segments(
    original: &str,
    remainder: &str,
    min_components: usize,
) -> Result<Vec<String>, UriError> {
    // Split first, decode second: a `%2F` must never be mistaken for a
    // structural separator, so splitting on the still-encoded string is
    // the only order that keeps the two apart.
    let raw_segments: Vec<&str> = remainder.split('/').collect();
    if raw_segments.len() < min_components {
        return Err(UriError::TooFewComponents(original.to_string()));
    }

    let mut decoded = Vec::with_capacity(raw_segments.len());
    for raw in &raw_segments {
        let segment = percent_decode_str(raw)
            .decode_utf8()
            .map_err(|_| UriError::InvalidEncoding((*raw).to_string()))?
            .into_owned();
        if segment.is_empty() {
            return Err(UriError::EmptyComponent(original.to_string()));
        }
        decoded.push(segment);
    }
    Ok(decoded)
}

/// Strip the `secret://` scheme, split off an optional `<store>@` prefix,
/// then split/decode the remaining `<vault>/<item...>[/<field>]`
/// components — the full parse shared by [`SecretUri::parse`] and
/// [`ItemUri::parse`], which differ only in `min_components` and how they
/// carve up the returned segments.
///
/// # Errors
///
/// Returns [`UriError::MissingScheme`] if `input` does not start with
/// `secret://`, [`UriError::EmptyStore`]/[`UriError::InvalidStore`] for a
/// malformed store prefix, or any of [`decode_segments`]'s errors for the
/// vault/item/field portion.
fn parse_store_and_segments(
    input: &str,
    min_components: usize,
) -> Result<(Option<StoreId>, Vec<String>), UriError> {
    let rest = input
        .strip_prefix(SCHEME)
        .ok_or_else(|| UriError::MissingScheme(input.to_string()))?;
    let (raw_store, remainder) = split_store(rest)?;
    let store = raw_store.map(decode_store).transpose()?;
    let segments = decode_segments(input, remainder, min_components)?;
    Ok((store, segments))
}

/// A parsed `secret://[<store>@]<vault>/<item...>/<field>` reference.
///
/// Immutable and cheap to clone; construct it once at the edge (CLI argument,
/// D-Bus method argument) and pass it inward instead of re-parsing the
/// string at each layer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretUri {
    store: Option<StoreId>,
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
        store: Option<StoreId>,
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
        Ok(Self {
            store,
            vault,
            item,
            field,
        })
    }

    /// Parse a `secret://` string into its typed representation.
    ///
    /// # Errors
    ///
    /// Returns a [`UriError`] describing exactly what was wrong: a missing
    /// scheme, an invalid store qualifier, too few components, an empty
    /// component, or invalid percent-encoding.
    pub fn parse(input: &str) -> Result<Self, UriError> {
        let (store, mut decoded) = parse_store_and_segments(input, 3)?;

        // Length was checked above, so both ends exist.
        let field = decoded.pop().expect("checked length above");
        let vault = decoded.remove(0);
        let item = ItemPath::new(decoded)?;
        Ok(Self {
            store,
            vault,
            item,
            field,
        })
    }

    /// The qualifying store, if the reference named one explicitly.
    ///
    /// `None` means "resolve without a store qualifier" — see
    /// `secretsd::state::DaemonState`'s ambiguity-resolution rule
    /// (ADR-018): it is not the same as "the default store".
    #[must_use]
    pub fn store(&self) -> Option<&StoreId> {
        self.store.as_ref()
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
        write!(f, "secret://")?;
        if let Some(store) = &self.store {
            write!(f, "{store}@")?;
        }
        write!(
            f,
            "{}/{}/{}",
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

/// A parsed `secret://<vault>/<item...>` reference — an *item*, not a
/// field.
///
/// Distinct from [`SecretUri`], which always names a field as its last
/// segment: this exists only for operations that address a whole item at
/// once (`secrets show`; see ADR-016), and has no way to tell "an item
/// path with a nested segment named the same as some field" apart from
/// "that segment is the field" — callers must already know which shape
/// their string is, the same way a caller must already know whether a
/// bare `foo/bar` means a two-segment item or an item plus a field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ItemUri {
    store: Option<StoreId>,
    vault: String,
    item: ItemPath,
}

impl ItemUri {
    /// Build an item reference from already-decoded parts.
    ///
    /// # Errors
    ///
    /// Returns [`UriError::EmptyVault`] if `vault` is the empty string.
    pub fn new(
        store: Option<StoreId>,
        vault: impl Into<String>,
        item: ItemPath,
    ) -> Result<Self, UriError> {
        let vault = vault.into();
        if vault.is_empty() {
            return Err(UriError::EmptyVault);
        }
        Ok(Self { store, vault, item })
    }

    /// Parse a `secret://[<store>@]<vault>/<item...>` string — no field
    /// segment.
    ///
    /// # Errors
    ///
    /// Returns a [`UriError`] describing exactly what was wrong: a missing
    /// scheme, an invalid store qualifier, too few components (fewer than
    /// a vault plus one item segment), an empty component, or invalid
    /// percent-encoding.
    pub fn parse(input: &str) -> Result<Self, UriError> {
        let (store, mut decoded) = parse_store_and_segments(input, 2)?;

        // Length was checked above, so the vault exists.
        let vault = decoded.remove(0);
        let item = ItemPath::new(decoded)?;
        Ok(Self { store, vault, item })
    }

    /// The qualifying store, if the reference named one explicitly. See
    /// [`SecretUri::store`]'s doc comment for what `None` means.
    #[must_use]
    pub fn store(&self) -> Option<&StoreId> {
        self.store.as_ref()
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
}

impl fmt::Display for ItemUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "secret://")?;
        if let Some(store) = &self.store {
            write!(f, "{store}@")?;
        }
        write!(
            f,
            "{}/{}",
            utf8_percent_encode(&self.vault, COMPONENT),
            self.item
        )
    }
}

impl FromStr for ItemUri {
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

    /// Fewer `/`-separated components after the scheme than the reference
    /// shape being parsed requires (three for [`SecretUri`]'s
    /// `<vault>/<item>/<field>`, two for [`ItemUri`]'s `<vault>/<item>`).
    #[error("too few components in secret:// reference, got: {0:?}")]
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

    /// The `store@` separator appeared with nothing before it
    /// (`secret://@vault/...`).
    #[error("store name cannot be empty")]
    EmptyStore,

    /// A store qualifier decoded, but failed [`crate::store_id::StoreId`]'s
    /// own validation.
    #[error("invalid store name: {0:?}")]
    InvalidStore(String),
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
        let err = SecretUri::new(None, "", item, "password").unwrap_err();
        assert_eq!(err, UriError::EmptyVault);
    }

    #[test]
    fn constructing_from_parts_rejects_an_empty_field() {
        let item = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
        let err = SecretUri::new(None, "Personal", item, "").unwrap_err();
        assert_eq!(err, UriError::EmptyField);
    }

    #[rstest]
    #[case(
        "secret://work@Personal/GitHub/password",
        "work",
        "Personal",
        &["GitHub"],
        "password"
    )]
    #[case(
        "secret://a1-b_2@Infrastructure/Production/database/password",
        "a1-b_2",
        "Infrastructure",
        &["Production", "database"],
        "password"
    )]
    fn a_store_qualified_uri_parses_into_its_named_parts(
        #[case] input: &str,
        #[case] store: &str,
        #[case] vault: &str,
        #[case] item: &[&str],
        #[case] field: &str,
    ) {
        let uri = SecretUri::parse(input).expect("a store-qualified URI must parse");
        assert_eq!(uri.store().map(StoreId::as_str), Some(store));
        assert_eq!(uri.vault(), vault);
        assert_eq!(uri.item().segments(), item);
        assert_eq!(uri.field(), field);
    }

    #[test]
    fn an_unqualified_uri_has_no_store() {
        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        assert_eq!(uri.store(), None);
    }

    #[test]
    fn parsing_and_displaying_a_store_qualified_uri_round_trips_it() {
        let input = "secret://work@Personal/GitHub/password";
        let uri = SecretUri::parse(input).unwrap();
        assert_eq!(uri.to_string(), input);
    }

    #[test]
    fn a_percent_encoded_at_sign_stays_inside_the_vault_name() {
        // "Personal@Work" is ONE vault name, with no store qualifier,
        // because its `@` is escaped rather than literal.
        let uri = SecretUri::parse("secret://Personal%40Work/GitHub/password").unwrap();
        assert_eq!(uri.store(), None);
        assert_eq!(uri.vault(), "Personal@Work");
        assert_eq!(uri.to_string(), "secret://Personal%40Work/GitHub/password");
    }

    #[test]
    fn an_at_sign_in_a_later_segment_is_not_treated_as_a_store_separator() {
        // The store/vault split only ever looks at the first segment; an
        // `@` inside an item name is just part of that name.
        let uri = SecretUri::parse("secret://Personal/user@host/password").unwrap();
        assert_eq!(uri.store(), None);
        assert_eq!(uri.vault(), "Personal");
        assert_eq!(uri.item().segments(), ["user@host"]);
    }

    #[test]
    fn a_bare_at_sign_with_no_store_name_is_rejected() {
        let err = SecretUri::parse("secret://@Personal/GitHub/password").unwrap_err();
        assert_eq!(err, UriError::EmptyStore);
    }

    #[test]
    fn an_invalid_store_name_is_rejected() {
        let err = SecretUri::parse("secret://has space@Personal/GitHub/password").unwrap_err();
        assert_eq!(err, UriError::InvalidStore("has space".to_string()));
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

    #[rstest]
    #[case("secret://Personal/GitHub", "Personal", &["GitHub"])]
    #[case(
        "secret://Infrastructure/Production/database",
        "Infrastructure",
        &["Production", "database"]
    )]
    fn an_item_uri_parses_into_its_named_parts(
        #[case] input: &str,
        #[case] vault: &str,
        #[case] item: &[&str],
    ) {
        let uri = ItemUri::parse(input).expect("documented example must parse");
        assert_eq!(uri.vault(), vault);
        assert_eq!(uri.item().segments(), item);
    }

    #[test]
    fn parsing_and_displaying_an_item_uri_round_trips_it() {
        let input = "secret://Infrastructure/Production/database";
        let uri = ItemUri::parse(input).unwrap();
        assert_eq!(uri.to_string(), input);
    }

    #[test]
    fn an_item_uri_missing_the_item_is_rejected() {
        let err = ItemUri::parse("secret://Personal").unwrap_err();
        assert_eq!(
            err,
            UriError::TooFewComponents("secret://Personal".to_string())
        );
    }

    #[test]
    fn an_item_uri_with_only_a_scheme_is_rejected() {
        let err = ItemUri::parse("secret://").unwrap_err();
        assert_eq!(err, UriError::TooFewComponents("secret://".to_string()));
    }

    #[test]
    fn an_item_uri_without_the_scheme_is_rejected() {
        let err = ItemUri::parse("Personal/GitHub").unwrap_err();
        assert_eq!(err, UriError::MissingScheme("Personal/GitHub".to_string()));
    }

    #[test]
    fn constructing_an_item_uri_from_parts_rejects_an_empty_vault() {
        let item = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
        let err = ItemUri::new(None, "", item).unwrap_err();
        assert_eq!(err, UriError::EmptyVault);
    }

    #[test]
    fn a_store_qualified_item_uri_parses_into_its_named_parts() {
        let uri = ItemUri::parse("secret://work@Personal/GitHub").unwrap();
        assert_eq!(uri.store().map(StoreId::as_str), Some("work"));
        assert_eq!(uri.vault(), "Personal");
        assert_eq!(uri.item().segments(), ["GitHub"]);
    }

    #[test]
    fn parsing_and_displaying_a_store_qualified_item_uri_round_trips_it() {
        let input = "secret://work@Personal/GitHub";
        let uri = ItemUri::parse(input).unwrap();
        assert_eq!(uri.to_string(), input);
    }

    #[test]
    fn an_item_uri_bare_at_sign_with_no_store_name_is_rejected() {
        let err = ItemUri::parse("secret://@Personal/GitHub").unwrap_err();
        assert_eq!(err, UriError::EmptyStore);
    }

    #[test]
    fn an_item_uri_invalid_store_name_is_rejected() {
        let err = ItemUri::parse("secret://has space@Personal/GitHub").unwrap_err();
        assert_eq!(err, UriError::InvalidStore("has space".to_string()));
    }
}
