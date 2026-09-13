//! Output shapes and mode selection for commands whose result can be
//! printed as plain text or as JSON — and, for `secrets get` alone, the
//! rule that decides whether a secret's value may be printed at all.
//!
//! See ADR-014 for the rationale: metadata (`list`/`status`/`resolve`)
//! never needs a terminal check, since names are not secret material
//! (`docs/security.md`); a secret's value (`get`) does.

use serde::Serialize;

use crate::error::CliError;

/// How `secrets get` discloses the value it fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetMode {
    /// Print the bare value and a trailing newline, nothing else.
    Raw,
    /// Print `{"uri": ..., "value": ...}`.
    Json,
    /// Copy the value to the OS clipboard; print a confirmation instead.
    Clipboard,
}

/// Decide [`GetMode`] from the three (mutually exclusive, per `cli.rs`'s
/// `conflicts_with_all`) flags and whether stdout is a terminal.
///
/// A pure function on purpose: the "refuses on a real terminal" branch
/// cannot be exercised by the `assert_cmd`-based end-to-end suite (its
/// pipes are never a real TTY — see that suite's own module doc), so this
/// is unit-tested directly instead, with `stdout_is_terminal` supplied by
/// the caller rather than read here.
///
/// # Errors
///
/// Returns [`CliError::RefusedTerminalOutput`] when no flag was given and
/// `stdout_is_terminal` is `true`.
pub fn resolve_get_mode(
    raw: bool,
    json: bool,
    clipboard: bool,
    stdout_is_terminal: bool,
) -> Result<GetMode, CliError> {
    match (raw, json, clipboard) {
        (true, ..) => Ok(GetMode::Raw),
        (_, true, _) => Ok(GetMode::Json),
        (_, _, true) => Ok(GetMode::Clipboard),
        // No explicit flag: a real terminal keeps the value off the
        // screen (scrollback, session recording, shoulder-surfing) unless
        // the caller opts back in; a pipe/redirect is assumed scripted
        // use and gets today's behaviour unchanged.
        (false, false, false) if stdout_is_terminal => Err(CliError::RefusedTerminalOutput),
        (false, false, false) => Ok(GetMode::Raw),
    }
}

/// `status --json`'s shape.
#[derive(Serialize)]
pub struct StatusPayload<'a> {
    /// `"locked"` or `"unlocked"`.
    pub status: &'a str,
}

/// `list --json`'s shape when listing vault names.
#[derive(Serialize)]
pub struct VaultsPayload<'a> {
    /// Every vault name the active backend exposes.
    pub vaults: &'a [String],
}

/// `list <vault> --json`'s shape when listing a vault's item paths.
#[derive(Serialize)]
pub struct ItemsPayload<'a> {
    /// The vault the items belong to.
    pub vault: &'a str,
    /// The vault's item paths.
    pub items: &'a [String],
}

/// `resolve --json`'s shape.
#[derive(Serialize)]
pub struct ResolvePayload<'a> {
    /// The canonicalised `secret://` reference.
    pub uri: &'a str,
}

/// `get --json`'s shape.
///
/// Built with `value` borrowed from a call to
/// [`secrets_client::SecretValue::expose_secret`] at the single call site
/// that needs it — this type has no knowledge of `SecretValue` itself,
/// so it cannot be handed one by accident and serialize it implicitly.
#[derive(Serialize)]
pub struct GetPayload<'a> {
    /// The `secret://` reference that was fetched.
    pub uri: &'a str,
    /// The field's value.
    pub value: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_flags_on_a_terminal_is_refused() {
        let result = resolve_get_mode(false, false, false, true);
        assert!(matches!(result, Err(CliError::RefusedTerminalOutput)));
    }

    #[test]
    fn no_flags_off_a_terminal_prints_raw() {
        let result = resolve_get_mode(false, false, false, false);
        assert_eq!(result.unwrap(), GetMode::Raw);
    }

    #[test]
    fn raw_overrides_the_terminal_refusal() {
        let result = resolve_get_mode(true, false, false, true);
        assert_eq!(result.unwrap(), GetMode::Raw);
    }

    #[test]
    fn json_overrides_the_terminal_refusal() {
        let result = resolve_get_mode(false, true, false, true);
        assert_eq!(result.unwrap(), GetMode::Json);
    }

    #[test]
    fn clipboard_overrides_the_terminal_refusal() {
        let result = resolve_get_mode(false, false, true, true);
        assert_eq!(result.unwrap(), GetMode::Clipboard);
    }

    #[test]
    fn clipboard_is_selected_regardless_of_the_terminal_off_case_too() {
        let result = resolve_get_mode(false, false, true, false);
        assert_eq!(result.unwrap(), GetMode::Clipboard);
    }
}
