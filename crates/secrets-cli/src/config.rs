//! CLI configuration, following XDG conventions:
//! `~/.config/secrets/config.toml`.
//!
//! The MVP has nothing that strictly needs configuring — the daemon is
//! discovered on the session bus, not by a path or port this file could
//! override — but the loading machinery exists now so future settings
//! (default vault, output format, ...) have somewhere to land without a
//! breaking change to how the CLI finds its config.

use std::path::PathBuf;

use serde::Deserialize;

use crate::error::{CliError, Result};

/// The CLI's configuration file contents.
///
/// Every field is optional: a missing or absent config file is not an
/// error, just an empty [`Config`].
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The vault `secrets list`/`get` assume when a command's `vault`
    /// argument is omitted. Unused by any MVP command yet, reserved for
    /// `secrets inject`/`secrets run`.
    pub default_vault: Option<String>,
}

impl Config {
    /// Load `~/.config/secrets/config.toml`, or return the default
    /// (empty) configuration if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::ConfigUnreadable`] if the file exists but is not
    /// valid TOML or does not match [`Config`]'s shape.
    pub fn load() -> Result<Self> {
        let Some(path) = config_path() else {
            return Ok(Self::default());
        };
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents =
            std::fs::read_to_string(&path).map_err(|error| CliError::ConfigUnreadable {
                path: path.clone(),
                reason: error.to_string(),
            })?;
        toml::from_str(&contents).map_err(|error| CliError::ConfigUnreadable {
            path,
            reason: error.to_string(),
        })
    }
}

/// The config file's path, if `XDG_CONFIG_HOME` (or its fallback) could be
/// determined at all.
fn config_path() -> Option<PathBuf> {
    let xdg = xdg::BaseDirectories::with_prefix("secrets");
    Some(xdg.get_config_home()?.join("config.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_config_file_yields_the_default_configuration() {
        // XDG_CONFIG_HOME is whatever the test environment has; the
        // meaningful assertion is simply that this never errors, since a
        // config file is optional everywhere it might be looked for.
        let config = Config::load().unwrap();
        assert_eq!(config.default_vault, None);
    }

    #[test]
    fn an_empty_document_parses_to_every_field_absent() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.default_vault, None);
    }
}
