//! Backend selection configuration.
//!
//! Loads `~/.config/secrets/secretsd.toml` (following the same XDG
//! convention `secrets-cli`'s own `Config` uses, under a different
//! filename so the two never collide in the shared `secrets/` prefix
//! directory). An absent file — today's only supported shape until a
//! second backend is configured — keeps behaving exactly as before this
//! module was wired into [`crate::state::open_default_state`].

use std::path::PathBuf;

use serde::Deserialize;

use crate::error::{DaemonError, Result};

/// The daemon's configuration file contents.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Which backend to activate. Defaults to [`BackendKind::Local`], so
    /// an absent `[backend]` table — today's only supported shape — keeps
    /// behaving exactly as it does today.
    #[serde(default)]
    pub backend: BackendKind,
}

impl Config {
    /// Load `~/.config/secrets/secretsd.toml`, or return the default
    /// (local backend) configuration if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::ConfigUnreadable`] if the file exists but
    /// cannot be read, or is not valid TOML at all. Returns
    /// [`DaemonError::InvalidBackendConfig`] if `[backend] type =
    /// "1password"` is missing its required `account_name` field — a more
    /// actionable diagnostic than the generic TOML error that field's
    /// absence would otherwise produce. Any other shape mismatch (e.g. an
    /// unrecognised `type`) still reports as
    /// [`DaemonError::ConfigUnreadable`].
    pub fn load() -> Result<Self> {
        let Some(path) = config_path() else {
            return Ok(Self::default());
        };
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents =
            std::fs::read_to_string(&path).map_err(|error| DaemonError::ConfigUnreadable {
                path: path.clone(),
                reason: error.to_string(),
            })?;
        Self::parse(&contents, &path)
    }

    /// The file-I/O-free half of [`Config::load`] — kept separate so it's
    /// directly unit-testable against a string, without needing a real
    /// `secretsd.toml` on disk.
    ///
    /// # Errors
    ///
    /// See [`Config::load`].
    fn parse(contents: &str, path: &std::path::Path) -> Result<Self> {
        toml::from_str(contents).map_err(|error| {
            // A missing `account_name` is the one shape mismatch common
            // enough, and specific enough, to diagnose precisely rather
            // than surface as a raw TOML parse error — see
            // `missing_1password_account_name`'s own doc comment.
            match missing_1password_account_name(contents) {
                Some(message) => DaemonError::InvalidBackendConfig(message.to_string()),
                None => DaemonError::ConfigUnreadable {
                    path: path.to_path_buf(),
                    reason: error.to_string(),
                },
            }
        })
    }
}

/// If `contents` selects `[backend] type = "1password"` but omits
/// `account_name`, returns a specific, actionable diagnostic — otherwise
/// `None`, so the caller falls back to the raw TOML parse error. Only
/// called once the strict [`Config`] parse has already failed, so this
/// never masks a config that actually parses fine.
fn missing_1password_account_name(contents: &str) -> Option<&'static str> {
    let raw: toml::Value = toml::from_str(contents).ok()?;
    let backend = raw.get("backend")?;
    if backend.get("type")?.as_str()? != "1password" {
        return None;
    }
    if backend.get("account_name").is_some() {
        return None;
    }
    Some(
        "[backend] type = \"1password\" requires an `account_name` field — \
         the account name or UUID shown in the Desktop app's sidebar",
    )
}

/// The config file's path, if `XDG_CONFIG_HOME` (or its fallback) could be
/// determined at all.
fn config_path() -> Option<PathBuf> {
    let xdg = xdg::BaseDirectories::with_prefix("secrets");
    Some(xdg.get_config_home()?.join("secretsd.toml"))
}

/// Which backend implementation a daemon instance activates.
///
/// Exactly one is active per daemon instance: this project does not do
/// multi-backend or multi-vault routing (see ADR-0008).
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BackendKind {
    /// The local encrypted-file backend — the only one implemented so far.
    #[default]
    Local,
    /// 1Password Desktop, via its native IPC library — see
    /// `docs/architecture/1password-integration.md`.
    #[serde(rename = "1password")]
    OnePassword {
        /// The 1Password account name or account UUID, as shown in the
        /// Desktop app's sidebar — required by the protocol itself, not
        /// an implementation choice (see `protocol::init_client_request`'s
        /// own doc comment).
        account_name: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_config_file_yields_the_default_local_configuration() {
        // Isolated from the developer's/CI runner's *real*
        // `~/.config/secrets/secretsd.toml`, if one exists (e.g. a
        // developer who has already configured a real backend for their
        // own use) — this test is specifically about the *absent-file*
        // fallback, so it must not depend on whatever happens to be on
        // disk outside this temporary directory.
        //
        // SAFETY: this test does not run any other test in the same
        // process — `cargo nextest` isolates each test in its own
        // process, so this does not race with another test's own env
        // (see `backend::onepassword::ffi::tests::load_honors_the_override_env_var`
        // for the same reasoning).
        let empty_config_home = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("XDG_CONFIG_HOME", empty_config_home.path()) };

        let config = Config::load().unwrap();
        assert_eq!(config.backend, BackendKind::Local);
    }

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
    fn a_1password_backend_type_parses_with_its_account_name() {
        let config: Config =
            toml::from_str("[backend]\ntype = \"1password\"\naccount_name = \"MyAccount\"\n")
                .unwrap();
        assert_eq!(
            config.backend,
            BackendKind::OnePassword {
                account_name: "MyAccount".to_string()
            }
        );
    }

    #[test]
    fn a_1password_backend_type_without_an_account_name_is_rejected() {
        let result: std::result::Result<Config, _> =
            toml::from_str("[backend]\ntype = \"1password\"\n");
        assert!(result.is_err());
    }

    #[test]
    fn a_1password_backend_type_without_an_account_name_reports_an_actionable_error() {
        // Regression guard: this must not degrade to the generic
        // `ConfigUnreadable` a raw TOML parse failure would otherwise
        // produce (see `missing_1password_account_name`).
        let error = Config::parse(
            "[backend]\ntype = \"1password\"\n",
            std::path::Path::new("test.toml"),
        )
        .unwrap_err();
        assert!(matches!(error, DaemonError::InvalidBackendConfig(_)));
    }

    #[test]
    fn an_unrecognised_backend_type_still_reports_config_unreadable() {
        // A different shape mismatch must not be misdiagnosed as the
        // 1Password-specific case.
        let error = Config::parse(
            "[backend]\ntype = \"bitwarden\"\n",
            std::path::Path::new("test.toml"),
        )
        .unwrap_err();
        assert!(matches!(error, DaemonError::ConfigUnreadable { .. }));
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
