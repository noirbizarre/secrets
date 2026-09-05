//! Backend selection configuration.
//!
//! Prepares the `[backend]` table's shape ahead of actually selecting
//! between backends. `secretsd` does not load a config file at all yet —
//! [`Config`] is not wired into [`crate::state::open_default_state`] until
//! a step that has a second backend to select (see PLAN.md §7 and
//! ADR-0008). Landing the shape now, with its own parsing tests, means
//! that later step is pure wiring rather than also inventing this type.
//!
//! `#[allow(dead_code)]` on both types below is deliberate, not an
//! oversight: nothing outside `#[cfg(test)]` constructs them yet.

use serde::Deserialize;

/// The `[backend]` table of the (not yet loaded) daemon config file.
#[allow(dead_code)]
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Which backend to activate. Defaults to [`BackendKind::Local`], so
    /// an absent `[backend]` table — today's only supported shape — keeps
    /// behaving exactly as it does today.
    #[serde(default)]
    pub backend: BackendKind,
}

/// Which backend implementation a daemon instance activates.
///
/// Exactly one is active per daemon instance: this project does not do
/// multi-backend or multi-vault routing (see ADR-0008).
#[allow(dead_code)]
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BackendKind {
    /// The local encrypted-file backend — the only one implemented so far.
    #[default]
    Local,
    /// 1Password Desktop, via its native IPC library. Not yet implemented
    /// — see `docs/architecture/1password-integration.md`.
    #[serde(rename = "1password")]
    OnePassword,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_backend_table_defaults_to_local() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.backend, BackendKind::Local);
    }

    #[test]
    fn an_explicit_local_backend_type_parses() {
        let config: Config = toml::from_str("[backend]\ntype = \"local\"\n").unwrap();
        assert_eq!(config.backend, BackendKind::Local);
    }

    #[test]
    fn a_1password_backend_type_parses() {
        let config: Config = toml::from_str("[backend]\ntype = \"1password\"\n").unwrap();
        assert_eq!(config.backend, BackendKind::OnePassword);
    }

    #[test]
    fn an_unrecognised_backend_type_is_rejected() {
        let result: std::result::Result<Config, _> =
            toml::from_str("[backend]\ntype = \"bitwarden\"\n");
        assert!(result.is_err());
    }

    #[test]
    fn an_unknown_top_level_field_is_rejected() {
        let result: std::result::Result<Config, _> = toml::from_str("unknown = true\n");
        assert!(result.is_err());
    }
}
