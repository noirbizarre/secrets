//! Store configuration: which backend instances a daemon activates.
//!
//! Loads `~/.config/secrets/secretsd.toml` (following the same XDG
//! convention `secrets-cli`'s own `Config` uses, under a different
//! filename so the two never collide in the shared `secrets/` prefix
//! directory). An absent file, or one with no `[store.*]` table at all,
//! still yields exactly one implicit store (see
//! `crate::state::open_registry`) — today's zero-config behavior is
//! unaffected by ADR-018.

use std::collections::BTreeMap;
use std::path::PathBuf;

use secrets_core::StoreId;
use serde::Deserialize;

use crate::error::{DaemonError, Result};

/// The daemon's configuration file contents.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// `[store.<id>]` tables, one per configured backend instance
    /// (ADR-018). Empty — file absent, or present with no `[store.*]`
    /// table at all — means "use the implicit default store"; resolving
    /// that default is `crate::state::open_registry`'s job, not this
    /// type's, so an empty map here is a valid, fully-parsed `Config`,
    /// not a special case.
    ///
    /// `rename` so the Rust field stays pluralized (`stores`, matching
    /// "a map of stores") while the TOML syntax is the singular
    /// `[store.<id>]` (matching "one store's own table") — the same
    /// singular/plural split TOML's own array-of-tables convention uses.
    #[serde(default, rename = "store")]
    pub stores: BTreeMap<StoreId, BackendKind>,
}

impl Config {
    /// Load `~/.config/secrets/secretsd.toml`, or return the default
    /// (no configured stores) configuration if it does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::ConfigUnreadable`] if the file exists but
    /// cannot be read, or is not valid TOML at all. Returns
    /// [`DaemonError::LegacyBackendConfig`] if the file still has the
    /// pre-ADR-018 `[backend]` table. Returns
    /// [`DaemonError::InvalidBackendConfig`] if some `[store.<id>] type =
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
            // Checked in this order because each is a strictly more
            // specific diagnosis of the same underlying parse failure:
            // "you're still using the removed [backend] table" is worth
            // naming before "a [store.*] table you do have is missing a
            // field", which is worth naming before the generic fallback.
            if let Some(message) = legacy_backend_table(contents) {
                return DaemonError::LegacyBackendConfig(message);
            }
            if let Some(message) = missing_1password_account_name(contents) {
                return DaemonError::InvalidBackendConfig(message);
            }
            match missing_pass_secret_key_path(contents) {
                Some(message) => DaemonError::InvalidBackendConfig(message),
                None => DaemonError::ConfigUnreadable {
                    path: path.to_path_buf(),
                    reason: error.to_string(),
                },
            }
        })
    }
}

/// If `contents` still has a top-level `[backend]` table — the shape
/// ADR-018 replaced with `[store.<id>]` — returns an actionable rewrite
/// message naming the exact fix, instead of letting `deny_unknown_fields`
/// report it as an opaque "unknown field `backend`".
///
/// Only called once the strict [`Config`] parse has already failed, so
/// this never masks a config that actually parses fine (e.g. a `[store]`
/// table that happens to also define an unrelated key coincidentally
/// named `backend` nested somewhere else — `raw.get("backend")` only
/// looks at the top level).
fn legacy_backend_table(contents: &str) -> Option<String> {
    let raw: toml::Value = toml::from_str(contents).ok()?;
    let backend = raw.get("backend")?;
    Some(format!(
        "the [backend] table was removed in favor of [store.<id>] tables (ADR-018) — \
         rewrite [backend] as [store.default] with the same fields (found: {backend})"
    ))
}

/// If `contents` has a `[store.<id>] type = "1password"` table missing
/// `account_name`, returns a specific, actionable diagnostic naming that
/// store — otherwise `None`, so the caller falls back to the raw TOML
/// parse error. Only called once the strict [`Config`] parse has already
/// failed, so this never masks a config that actually parses fine.
fn missing_1password_account_name(contents: &str) -> Option<String> {
    let raw: toml::Value = toml::from_str(contents).ok()?;
    let stores = raw.get("store")?.as_table()?;
    for (id, store) in stores {
        if store.get("type")?.as_str()? != "1password" {
            continue;
        }
        if store.get("account_name").is_some() {
            continue;
        }
        return Some(format!(
            "[store.{id}] type = \"1password\" requires an `account_name` field — \
             the account name or UUID shown in the Desktop app's sidebar"
        ));
    }
    None
}

/// If `contents` has a `[store.<id>] type = "pass"` table missing
/// `secret_key_path`, returns a specific, actionable diagnostic naming
/// that store — otherwise `None`, so the caller falls back to the raw
/// TOML parse error. Only called once the strict [`Config`] parse has
/// already failed, so this never masks a config that actually parses
/// fine. Mirrors [`missing_1password_account_name`] exactly.
fn missing_pass_secret_key_path(contents: &str) -> Option<String> {
    let raw: toml::Value = toml::from_str(contents).ok()?;
    let stores = raw.get("store")?.as_table()?;
    for (id, store) in stores {
        if store.get("type")?.as_str()? != "pass" {
            continue;
        }
        if store.get("secret_key_path").is_some() {
            continue;
        }
        return Some(format!(
            "[store.{id}] type = \"pass\" requires a `secret_key_path` field — \
             the path to an ascii-armored OpenPGP secret key exported via \
             `gpg --export-secret-keys --armor <key-id> > key.asc`"
        ));
    }
    None
}

/// The config file's path, if `XDG_CONFIG_HOME` (or its fallback) could be
/// determined at all.
fn config_path() -> Option<PathBuf> {
    let xdg = xdg::BaseDirectories::with_prefix("secrets");
    Some(xdg.get_config_home()?.join("secretsd.toml"))
}

/// Which backend implementation one configured store activates.
///
/// Distinct from *which* store: several `[store.<id>]` tables may each
/// select the same `BackendKind` (e.g. two `type = "local"` stores backed
/// by different vault files) — see ADR-018.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BackendKind {
    /// The local encrypted-file backend.
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
    /// A `pass`/`gopass`-compatible store directory, decrypted via rPGP
    /// — see [ADR-019](../../../../docs/adr/019-pass-backend.md). A
    /// `gopass` "mount" is just another `[store.<id>]` table of this
    /// same type, pointed at that mount's own directory.
    #[serde(rename = "pass")]
    Pass {
        /// The store's root directory. Defaults to `~/.password-store`
        /// (`pass`'s own default) when omitted.
        #[serde(default)]
        store_dir: Option<PathBuf>,
        /// An ascii-armored OpenPGP secret key, exported via
        /// `gpg --export-secret-keys --armor <key-id> > key.asc`.
        /// Required: `secretsd` never reads GnuPG's own keyring
        /// directly (ADR-019) — rPGP has nothing to parse in
        /// `private-keys-v1.d`'s own S-expression format.
        secret_key_path: PathBuf,
        /// This store's one vault name (`pass` has no native
        /// multi-vault concept). Defaults to `store_dir`'s own basename
        /// with a single leading `.` stripped.
        #[serde(default)]
        vault: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_config_file_yields_no_configured_stores() {
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
        assert!(config.stores.is_empty());
    }

    #[test]
    fn an_empty_config_file_yields_no_configured_stores() {
        let config: Config = toml::from_str("").unwrap();
        assert!(config.stores.is_empty());
    }

    #[test]
    fn a_store_table_parses_into_its_named_entry() {
        let config: Config = toml::from_str("[store.default]\ntype = \"local\"\n").unwrap();
        assert_eq!(
            config.stores.get(&StoreId::new("default").unwrap()),
            Some(&BackendKind::Local)
        );
    }

    #[test]
    fn several_store_tables_parse_into_their_own_named_entries() {
        let config: Config = toml::from_str(
            "[store.personal]\ntype = \"local\"\n\n\
             [store.work]\ntype = \"1password\"\naccount_name = \"Work\"\n",
        )
        .unwrap();
        assert_eq!(config.stores.len(), 2);
        assert_eq!(
            config.stores.get(&StoreId::new("personal").unwrap()),
            Some(&BackendKind::Local)
        );
        assert_eq!(
            config.stores.get(&StoreId::new("work").unwrap()),
            Some(&BackendKind::OnePassword {
                account_name: "Work".to_string()
            })
        );
    }

    #[test]
    fn a_pass_store_table_parses_into_its_named_entry() {
        let config: Config = toml::from_str(
            "[store.default]\ntype = \"pass\"\nsecret_key_path = \"/tmp/key.asc\"\n",
        )
        .unwrap();
        assert_eq!(
            config.stores.get(&StoreId::new("default").unwrap()),
            Some(&BackendKind::Pass {
                store_dir: None,
                secret_key_path: PathBuf::from("/tmp/key.asc"),
                vault: None,
            })
        );
    }

    #[test]
    fn a_pass_store_accepts_an_explicit_store_dir_and_vault_name() {
        let config: Config = toml::from_str(
            "[store.work]\ntype = \"pass\"\nsecret_key_path = \"/tmp/key.asc\"\n\
             store_dir = \"/tmp/work-store\"\nvault = \"Work\"\n",
        )
        .unwrap();
        assert_eq!(
            config.stores.get(&StoreId::new("work").unwrap()),
            Some(&BackendKind::Pass {
                store_dir: Some(PathBuf::from("/tmp/work-store")),
                secret_key_path: PathBuf::from("/tmp/key.asc"),
                vault: Some("Work".to_string()),
            })
        );
    }

    #[test]
    fn a_pass_store_missing_a_secret_key_path_is_rejected() {
        let result: std::result::Result<Config, _> =
            toml::from_str("[store.default]\ntype = \"pass\"\n");
        assert!(result.is_err());
    }

    #[test]
    fn a_pass_store_missing_a_secret_key_path_names_the_specific_store_id() {
        let error = Config::parse(
            "[store.personal]\ntype = \"local\"\n\n[store.work]\ntype = \"pass\"\n",
            std::path::Path::new("test.toml"),
        )
        .unwrap_err();
        match error {
            DaemonError::InvalidBackendConfig(message) => assert!(message.contains("store.work")),
            other => panic!("expected InvalidBackendConfig, got {other:?}"),
        }
    }

    #[test]
    fn a_1password_store_missing_an_account_name_is_rejected() {
        let result: std::result::Result<Config, _> =
            toml::from_str("[store.work]\ntype = \"1password\"\n");
        assert!(result.is_err());
    }

    #[test]
    fn a_1password_store_missing_an_account_name_names_the_specific_store_id() {
        // Regression guard: this must not degrade to the generic
        // `ConfigUnreadable` a raw TOML parse failure would otherwise
        // produce (see `missing_1password_account_name`), and must name
        // *which* store is broken when more than one is configured.
        let error = Config::parse(
            "[store.personal]\ntype = \"local\"\n\n[store.work]\ntype = \"1password\"\n",
            std::path::Path::new("test.toml"),
        )
        .unwrap_err();
        match error {
            DaemonError::InvalidBackendConfig(message) => assert!(message.contains("store.work")),
            other => panic!("expected InvalidBackendConfig, got {other:?}"),
        }
    }

    #[test]
    fn an_unrecognised_store_type_still_reports_config_unreadable() {
        // A different shape mismatch must not be misdiagnosed as the
        // 1Password-specific case.
        let error = Config::parse(
            "[store.default]\ntype = \"bitwarden\"\n",
            std::path::Path::new("test.toml"),
        )
        .unwrap_err();
        assert!(matches!(error, DaemonError::ConfigUnreadable { .. }));
    }

    #[test]
    fn an_unrecognised_store_type_is_rejected() {
        let result: std::result::Result<Config, _> =
            toml::from_str("[store.default]\ntype = \"bitwarden\"\n");
        assert!(result.is_err());
    }

    #[test]
    fn an_unknown_top_level_field_is_rejected() {
        let result: std::result::Result<Config, _> = toml::from_str("unknown = true\n");
        assert!(result.is_err());
    }

    #[test]
    fn an_invalid_store_id_is_rejected() {
        let result: std::result::Result<Config, _> =
            toml::from_str("[store.\"has space\"]\ntype = \"local\"\n");
        assert!(result.is_err());
    }

    #[test]
    fn a_legacy_backend_table_is_rejected_with_an_actionable_migration_message() {
        let error = Config::parse(
            "[backend]\ntype = \"local\"\n",
            std::path::Path::new("test.toml"),
        )
        .unwrap_err();
        match error {
            DaemonError::LegacyBackendConfig(message) => {
                assert!(message.contains("[store.default]"));
                assert!(message.contains("ADR-018"));
            }
            other => panic!("expected LegacyBackendConfig, got {other:?}"),
        }
    }

    #[test]
    fn a_legacy_backend_table_is_rejected_even_with_1password_fields() {
        let error = Config::parse(
            "[backend]\ntype = \"1password\"\naccount_name = \"Work\"\n",
            std::path::Path::new("test.toml"),
        )
        .unwrap_err();
        assert!(matches!(error, DaemonError::LegacyBackendConfig(_)));
    }
}
