//! Parsing a decrypted `pass` entry's plaintext into fields.
//!
//! A `pass` entry has no structured field metadata of its own — it is
//! just lines of text, decrypted as a whole. Only the *first* line has a
//! guaranteed meaning (the password, per `pass`'s own convention); every
//! other line is parsed against the `key: value` convention widely used
//! by `browserpass`/`passff` (and, for TOTP, `pass-otp`) — never a
//! documented `pass` file format, just the de-facto one every consumer
//! of these files already assumes. Pure and I/O-free by design: no
//! `secrets_core` dependency beyond [`FieldKind`], no PGP, no filesystem
//! access — trivially unit-testable against plain strings.

use secrets_core::FieldKind;

/// One parsed field: its wire name, its guessed [`FieldKind`], and its
/// value. Order matches the entry's own line order except that the
/// first line always comes first (see [`parse_entry`]'s own doc comment).
pub struct ParsedField {
    pub name: String,
    pub kind: FieldKind,
    pub value: String,
}

/// The field name synthesized for a `pass` entry's first line, when that
/// line is not itself an `otpauth://` URI. Exposed so [`crate::backend::
/// pass::backend`] can build the same "locked/undecryptable" placeholder
/// field list without duplicating the literal string.
pub const PASSWORD_FIELD_NAME: &str = "password";

/// The field name synthesized for a first line (or a later bare line)
/// that is itself an `otpauth://` URI — the `pass-otp` convention for an
/// OTP-only entry, or an OTP appended to an existing entry.
pub const TOTP_FIELD_NAME: &str = "totp";

/// Parse a fully decrypted `pass` entry into its fields.
///
/// Never fails: an unrecognized `key: value` line becomes
/// [`FieldKind::Custom`], the same "unrecognized is not an error"
/// discipline `LocalBackend`/`OnePasswordBackend` already follow. A line
/// with neither a recognized key nor a colon at all (blank lines,
/// free-form notes some `pass` entries carry) is silently skipped — this
/// function only extracts what looks like a field, it does not attempt
/// to represent an entry's full free-text content.
///
/// Duplicate keys: the *last* occurrence wins, since a map is built by
/// insertion — matches "later lines override earlier ones" the way a
/// human editing the file top-to-bottom would expect.
#[must_use]
pub fn parse_entry(plaintext: &str) -> Vec<ParsedField> {
    let mut fields = std::collections::BTreeMap::new();
    // Preserve first-seen order for fields sharing an insertion rank is
    // not needed here: callers (`list_items`/`get_field`) look fields up
    // by name, never rely on iteration order.
    let mut lines = plaintext.lines();

    if let Some(first) = lines.next() {
        let first = first.trim_end_matches('\r');
        if is_otpauth_uri(first) {
            // An OTP-only entry (`pass otp insert`) has no separate
            // password line at all — reporting a `password` field here
            // would be a fabrication, not a heuristic.
            fields.insert(
                TOTP_FIELD_NAME.to_string(),
                (FieldKind::Totp, first.to_string()),
            );
        } else {
            fields.insert(
                PASSWORD_FIELD_NAME.to_string(),
                (FieldKind::Password, first.to_string()),
            );
        }
    }

    for line in lines {
        let line = line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        if is_otpauth_uri(line) {
            // The other `pass-otp` convention: the URI appended as its
            // own line, no `key:` prefix, alongside an existing password
            // line above it.
            fields.insert(
                TOTP_FIELD_NAME.to_string(),
                (FieldKind::Totp, line.to_string()),
            );
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            // Free-form note line, not a field — not this function's job
            // to represent (see doc comment above).
            continue;
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() {
            continue;
        }
        let lower = key.to_ascii_lowercase();
        let (name, kind) = match lower.as_str() {
            "login" | "username" | "user" => ("username".to_string(), FieldKind::Username),
            "totp" | "otp" => (TOTP_FIELD_NAME.to_string(), FieldKind::Totp),
            "url" | "uri" | "website" => ("url".to_string(), FieldKind::Custom("url".to_string())),
            other => (other.to_string(), FieldKind::Custom(other.to_string())),
        };
        fields.insert(name, (kind, value.to_string()));
    }

    fields
        .into_iter()
        .map(|(name, (kind, value))| ParsedField { name, kind, value })
        .collect()
}

/// Whether `line` is itself an `otpauth://` URI — the `pass-otp`
/// convention this function recognizes regardless of position (first
/// line, or a later bare line with no `key:` prefix).
fn is_otpauth_uri(line: &str) -> bool {
    line.starts_with("otpauth://")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn find<'a>(fields: &'a [ParsedField], name: &str) -> &'a ParsedField {
        fields
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("no field named {name:?} in {:?}", field_names(fields)))
    }

    fn field_names(fields: &[ParsedField]) -> Vec<&str> {
        fields.iter().map(|f| f.name.as_str()).collect()
    }

    #[test]
    fn a_password_only_entry_reports_a_single_password_field() {
        let fields = parse_entry("correct horse battery staple");
        assert_eq!(field_names(&fields), vec!["password"]);
        assert_eq!(
            find(&fields, "password").value,
            "correct horse battery staple"
        );
        assert!(matches!(
            find(&fields, "password").kind,
            FieldKind::Password
        ));
    }

    #[test]
    fn a_username_line_is_recognized_under_several_spellings() {
        for key in ["login", "username", "user"] {
            let fields = parse_entry(&format!("hunter2\n{key}: octocat"));
            let field = find(&fields, "username");
            assert_eq!(field.value, "octocat");
            assert!(matches!(field.kind, FieldKind::Username));
        }
    }

    #[test]
    fn a_totp_key_value_line_is_recognized() {
        let fields = parse_entry("hunter2\ntotp: JBSWY3DPEHPK3PXP");
        let field = find(&fields, "totp");
        assert_eq!(field.value, "JBSWY3DPEHPK3PXP");
        assert!(matches!(field.kind, FieldKind::Totp));
    }

    #[test]
    fn a_bare_otpauth_line_among_others_is_recognized_as_totp() {
        let fields = parse_entry(
            "hunter2\nlogin: octocat\notpauth://totp/Example:octocat?secret=JBSWY3DPEHPK3PXP",
        );
        let field = find(&fields, "totp");
        assert!(field.value.starts_with("otpauth://"));
        assert!(matches!(field.kind, FieldKind::Totp));
        // The password field is unaffected by an otpauth line elsewhere.
        assert_eq!(find(&fields, "password").value, "hunter2");
    }

    #[test]
    fn an_otp_only_entry_reports_a_totp_field_not_a_password_field() {
        let fields = parse_entry("otpauth://totp/Example:octocat?secret=JBSWY3DPEHPK3PXP");
        assert_eq!(field_names(&fields), vec!["totp"]);
    }

    #[test]
    fn an_unrecognized_key_becomes_a_custom_field() {
        let fields = parse_entry("hunter2\nnotes: some free text");
        let field = find(&fields, "notes");
        assert_eq!(field.value, "some free text");
        assert!(matches!(&field.kind, FieldKind::Custom(name) if name == "notes"));
    }

    #[test]
    fn a_url_line_is_recognized_under_several_spellings() {
        for key in ["url", "uri", "website"] {
            let fields = parse_entry(&format!("hunter2\n{key}: https://example.invalid"));
            let field = find(&fields, "url");
            assert_eq!(field.value, "https://example.invalid");
            assert!(matches!(&field.kind, FieldKind::Custom(name) if name == "url"));
        }
    }

    #[test]
    fn a_duplicate_key_keeps_the_last_occurrence() {
        let fields = parse_entry("hunter2\nlogin: first\nlogin: second");
        assert_eq!(find(&fields, "username").value, "second");
    }

    #[test]
    fn blank_lines_and_free_form_notes_without_a_colon_are_skipped() {
        let fields = parse_entry("hunter2\n\njust some free-form text\nlogin: octocat");
        assert_eq!(field_names(&fields).len(), 2);
    }

    #[test]
    fn an_empty_entry_reports_no_fields() {
        let fields = parse_entry("");
        assert!(fields.is_empty());
    }
}
