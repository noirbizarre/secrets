//! The MVP backend: a single TOML file under `$XDG_DATA_HOME/secrets/`,
//! field values encrypted at rest.
//!
//! Vault, item and field *names* are stored in the clear — they are the
//! metadata `list_vaults`/`list_items` must be able to return even while
//! locked (see `docs/security.md`). Only field *values* are encrypted, each
//! under its own random nonce, with a key derived from the unlock
//! passphrase (see [`crate::crypto`]).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use secrets_core::{
    Backend, CoreError, FieldKind, FieldMeta, Item, ItemPath, Result as CoreResult, SecretValue,
    Vault,
};
use serde::{Deserialize, Serialize};

use crate::crypto::{self, Encrypted, VaultKey};
use crate::error::{DaemonError, Result};

/// A fixed plaintext encrypted alongside the vault key's salt, purely so
/// `unlock` can tell "wrong passphrase" apart from "empty vault" — an
/// empty, freshly-created vault has no field ciphertext to attempt
/// decrypting otherwise.
const CANARY_PLAINTEXT: &str = "secrets-vault-integrity-check";

#[derive(Debug, Serialize, Deserialize)]
struct VaultFile {
    meta: Meta,
    /// Keyed by vault name.
    #[serde(default)]
    vaults: BTreeMap<String, VaultData>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Meta {
    /// Recorded so a future format migration has something to branch on;
    /// the MVP only ever writes `"argon2id"`.
    kdf: String,
    salt: String,
    check_nonce: String,
    check_ciphertext: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct VaultData {
    /// Keyed by item path, segments joined with `/` (e.g.
    /// `"Production/database"`) — a plain join, not the URI-escaped form,
    /// since this key is never re-parsed as a `secret://` reference.
    #[serde(default)]
    items: BTreeMap<String, ItemData>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ItemData {
    /// Keyed by field name.
    #[serde(default)]
    fields: BTreeMap<String, FieldData>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FieldData {
    kind: String,
    nonce: String,
    ciphertext: String,
}

impl FieldData {
    fn encrypt(kind: &FieldKind, key: &VaultKey, plaintext: &str) -> Self {
        let Encrypted { nonce, ciphertext } = crypto::encrypt(key, plaintext);
        Self {
            kind: kind_to_str(kind),
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        }
    }

    fn decrypt(&self, key: &VaultKey) -> std::result::Result<String, ()> {
        let nonce = BASE64.decode(&self.nonce).map_err(|_| ())?;
        let nonce: [u8; 12] = nonce.try_into().map_err(|_| ())?;
        let ciphertext = BASE64.decode(&self.ciphertext).map_err(|_| ())?;
        crypto::decrypt(key, &Encrypted { nonce, ciphertext }).map_err(|_| ())
    }
}

fn kind_to_str(kind: &FieldKind) -> String {
    match kind {
        FieldKind::Username => "username".to_string(),
        FieldKind::Password => "password".to_string(),
        FieldKind::Totp => "totp".to_string(),
        FieldKind::SshKey => "ssh-key".to_string(),
        FieldKind::Certificate => "certificate".to_string(),
        FieldKind::PrivateKey => "private-key".to_string(),
        FieldKind::Note => "note".to_string(),
        FieldKind::Custom(name) => format!("custom:{name}"),
    }
}

fn kind_from_str(raw: &str) -> FieldKind {
    match raw {
        "username" => FieldKind::Username,
        "password" => FieldKind::Password,
        "totp" => FieldKind::Totp,
        "ssh-key" => FieldKind::SshKey,
        "certificate" => FieldKind::Certificate,
        "private-key" => FieldKind::PrivateKey,
        "note" => FieldKind::Note,
        other => FieldKind::Custom(other.strip_prefix("custom:").unwrap_or(other).to_string()),
    }
}

/// The item-path-to-storage-key join used throughout this module. A plain
/// `/`-join, not [`ItemPath`]'s `Display` (which percent-encodes for
/// `secret://` reconstruction) — this key is a TOML map key, never
/// re-parsed as a URI.
fn item_key(item: &ItemPath) -> String {
    item.segments().join("/")
}

/// The single-file, encrypted-at-rest backend used by the MVP.
pub struct LocalBackend {
    path: PathBuf,
    /// Metadata is available even while locked; `None` only before the
    /// first vault file exists on disk.
    file: Mutex<Option<VaultFile>>,
    /// The derived key, present only while unlocked. Zeroized on drop by
    /// [`VaultKey`], so locking (replacing this with `None`) is sufficient
    /// to remove the key from memory.
    key: Mutex<Option<VaultKey>>,
}

impl LocalBackend {
    /// Open (without unlocking) the vault file at `path`, loading its
    /// metadata if it already exists.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::VaultFileUnreadable`] if the file exists but
    /// cannot be parsed.
    pub fn open(path: PathBuf) -> Result<Self> {
        let file = if path.exists() {
            Some(load(&path)?)
        } else {
            None
        };
        Ok(Self {
            path,
            file: Mutex::new(file),
            key: Mutex::new(None),
        })
    }

    /// Whether the backend currently holds a derived key.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.key.lock().expect("poisoned").is_some()
    }

    /// Derive a key from `passphrase` and either verify it against the
    /// existing vault, or — if no vault file exists yet — create one,
    /// seeded with a small demo vault so the MVP is usable immediately.
    ///
    /// See `docs/security.md` for why first-run seeding exists and its
    /// limitations.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::IncorrectPassphrase`] if a vault file exists
    /// and the passphrase does not decrypt its integrity canary, or a
    /// storage error if the file cannot be read or written.
    pub fn unlock(&self, passphrase: &str) -> Result<()> {
        if self.is_unlocked() {
            return Ok(());
        }

        let mut file_guard = self.file.lock().expect("poisoned");
        let (key, file) = match file_guard.take() {
            Some(existing) => {
                let salt = BASE64.decode(&existing.meta.salt).map_err(|error| {
                    DaemonError::VaultFileUnreadable {
                        path: self.path.clone(),
                        reason: error.to_string(),
                    }
                })?;
                let key = crypto::derive_key(passphrase, &salt).map_err(|error| {
                    DaemonError::VaultFileUnreadable {
                        path: self.path.clone(),
                        reason: error.to_string(),
                    }
                })?;
                verify_canary(&key, &existing)?;
                (key, existing)
            }
            None => {
                let (key, file) = seed_demo_vault(passphrase)?;
                save(&self.path, &file)?;
                (key, file)
            }
        };

        *file_guard = Some(file);
        *self.key.lock().expect("poisoned") = Some(key);
        Ok(())
    }

    /// Drop the derived key. The vault file's metadata stays loaded (it was
    /// never secret), but field values become unreachable until the next
    /// [`LocalBackend::unlock`].
    pub fn lock(&self) {
        *self.key.lock().expect("poisoned") = None;
    }
}

fn verify_canary(key: &VaultKey, file: &VaultFile) -> Result<()> {
    let nonce = BASE64
        .decode(&file.meta.check_nonce)
        .ok()
        .and_then(|bytes| <[u8; 12]>::try_from(bytes).ok());
    let ciphertext = BASE64.decode(&file.meta.check_ciphertext).ok();
    let (Some(nonce), Some(ciphertext)) = (nonce, ciphertext) else {
        return Err(DaemonError::IncorrectPassphrase);
    };
    match crypto::decrypt(key, &Encrypted { nonce, ciphertext }) {
        Ok(plaintext) if plaintext == CANARY_PLAINTEXT => Ok(()),
        _ => Err(DaemonError::IncorrectPassphrase),
    }
}

/// Build a fresh vault file, encrypted under a newly-derived key, seeded
/// with a small demo vault so `secrets get secret://Personal/GitHub/password`
/// works right after the very first `secrets unlock`.
fn seed_demo_vault(passphrase: &str) -> Result<(VaultKey, VaultFile)> {
    let salt = crypto::generate_salt();
    let key = crypto::derive_key(passphrase, &salt).map_err(|error| {
        DaemonError::VaultFileUnwritable {
            path: PathBuf::new(),
            reason: error.to_string(),
        }
    })?;

    let Encrypted {
        nonce: check_nonce,
        ciphertext: check_ciphertext,
    } = crypto::encrypt(&key, CANARY_PLAINTEXT);

    let mut personal_github = ItemData::default();
    personal_github.fields.insert(
        "username".to_string(),
        FieldData::encrypt(&FieldKind::Username, &key, "octocat"),
    );
    personal_github.fields.insert(
        "password".to_string(),
        FieldData::encrypt(&FieldKind::Password, &key, "correct horse battery staple"),
    );
    personal_github.fields.insert(
        "totp".to_string(),
        FieldData::encrypt(&FieldKind::Totp, &key, "JBSWY3DPEHPK3PXP"),
    );
    let mut personal = VaultData::default();
    personal.items.insert("GitHub".to_string(), personal_github);

    let mut production = ItemData::default();
    production.fields.insert(
        "ssh-key".to_string(),
        FieldData::encrypt(&FieldKind::SshKey, &key, &generate_demo_ssh_key()?),
    );
    let mut infrastructure = VaultData::default();
    infrastructure
        .items
        .insert("Production".to_string(), production);

    let mut vaults = BTreeMap::new();
    vaults.insert("Personal".to_string(), personal);
    vaults.insert("Infrastructure".to_string(), infrastructure);

    let file = VaultFile {
        meta: Meta {
            kdf: "argon2id".to_string(),
            salt: BASE64.encode(salt),
            check_nonce: BASE64.encode(check_nonce),
            check_ciphertext: BASE64.encode(check_ciphertext),
        },
        vaults,
    };
    Ok((key, file))
}

/// Generate a fresh Ed25519 key pair for the demo `Infrastructure` vault, so
/// the SSH agent has a real identity to present — otherwise `ssh-add -L`
/// would succeed but trivially, with nothing to show.
fn generate_demo_ssh_key() -> Result<String> {
    let private_key =
        ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519).map_err(
            |error| DaemonError::VaultFileUnwritable {
                path: PathBuf::new(),
                reason: error.to_string(),
            },
        )?;
    private_key
        .to_openssh(ssh_key::LineEnding::LF)
        .map(|zeroizing_string| zeroizing_string.to_string())
        .map_err(|error| DaemonError::VaultFileUnwritable {
            path: PathBuf::new(),
            reason: error.to_string(),
        })
}

fn load(path: &std::path::Path) -> Result<VaultFile> {
    let contents =
        std::fs::read_to_string(path).map_err(|error| DaemonError::VaultFileUnreadable {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    toml::from_str(&contents).map_err(|error| DaemonError::VaultFileUnreadable {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })
}

fn save(path: &std::path::Path, file: &VaultFile) -> Result<()> {
    let contents =
        toml::to_string_pretty(file).map_err(|error| DaemonError::VaultFileUnwritable {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
    std::fs::write(path, contents).map_err(|error| DaemonError::VaultFileUnwritable {
        path: path.to_path_buf(),
        reason: error.to_string(),
    })
}

impl Backend for LocalBackend {
    fn list_vaults(&self) -> CoreResult<Vec<Vault>> {
        let guard = self.file.lock().expect("poisoned");
        Ok(guard
            .as_ref()
            .map(|file| {
                file.vaults
                    .keys()
                    .map(|name| Vault::new(name.clone()))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn list_items(&self, vault: &str) -> CoreResult<Vec<Item>> {
        let guard = self.file.lock().expect("poisoned");
        let Some(file) = guard.as_ref() else {
            return Ok(Vec::new());
        };
        let Some(vault_data) = file.vaults.get(vault) else {
            return Err(CoreError::NotFound {
                vault: vault.to_string(),
                item: String::new(),
                field: String::new(),
            });
        };
        Ok(vault_data
            .items
            .iter()
            .map(|(path, item)| Item {
                path: ItemPath::new(path.split('/').map(str::to_string).collect())
                    .expect("stored item keys are never empty"),
                fields: item
                    .fields
                    .iter()
                    .map(|(name, field)| FieldMeta {
                        name: name.clone(),
                        kind: kind_from_str(&field.kind),
                    })
                    .collect(),
            })
            .collect())
    }

    fn get_field(&self, vault: &str, item: &ItemPath, field: &str) -> CoreResult<SecretValue> {
        let key_guard = self.key.lock().expect("poisoned");
        let Some(key) = key_guard.as_ref() else {
            return Err(CoreError::VaultLocked {
                vault: vault.to_string(),
            });
        };

        let file_guard = self.file.lock().expect("poisoned");
        let not_found = || CoreError::NotFound {
            vault: vault.to_string(),
            item: item.to_string(),
            field: field.to_string(),
        };
        let file = file_guard.as_ref().ok_or_else(not_found)?;
        let field_data = file
            .vaults
            .get(vault)
            .and_then(|v| v.items.get(&item_key(item)))
            .and_then(|i| i.fields.get(field))
            .ok_or_else(not_found)?;

        let plaintext = field_data.decrypt(key).map_err(|()| {
            // The key already passed the integrity canary at unlock time,
            // so reaching this means the field's own ciphertext was
            // corrupted independently — report it as unavailable, not as a
            // wrong passphrase (the daemon IS unlocked).
            CoreError::BackendUnavailable(format!(
                "stored value for secret://{vault}/{item}/{field} is corrupted"
            ))
        })?;
        Ok(SecretValue::new(plaintext))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tempfile::tempdir;

    #[test]
    fn unlocking_a_fresh_path_seeds_the_documented_demo_secret() {
        let dir = tempdir().unwrap();
        let backend = LocalBackend::open(dir.path().join("vault.toml")).unwrap();

        backend.unlock("test passphrase").unwrap();

        let item = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
        let value = backend.get_field("Personal", &item, "password").unwrap();
        assert_eq!(value.expose_secret(), "correct horse battery staple");
    }

    #[test]
    fn listing_vaults_and_items_works_before_unlocking() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.toml");
        // First create the file via one backend instance...
        LocalBackend::open(path.clone())
            .unwrap()
            .unlock("test passphrase")
            .unwrap();

        // ...then open a *new*, still-locked instance over the same file.
        let backend = LocalBackend::open(path).unwrap();
        assert!(!backend.is_unlocked());

        let vaults = backend.list_vaults().unwrap();
        assert!(vaults.iter().any(|v| v.name == "Personal"));

        let items = backend.list_items("Personal").unwrap();
        assert!(items[0].has_field("password"));
    }

    #[test]
    fn reading_a_field_while_locked_fails_with_vault_locked() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.toml");
        LocalBackend::open(path.clone())
            .unwrap()
            .unlock("test passphrase")
            .unwrap();

        let backend = LocalBackend::open(path).unwrap();
        let item = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
        let error = backend
            .get_field("Personal", &item, "password")
            .unwrap_err();

        assert!(matches!(error, CoreError::VaultLocked { .. }));
    }

    #[test]
    fn unlocking_with_the_wrong_passphrase_is_rejected() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.toml");
        LocalBackend::open(path.clone())
            .unwrap()
            .unlock("correct passphrase")
            .unwrap();

        let backend = LocalBackend::open(path).unwrap();
        let error = backend.unlock("wrong passphrase").unwrap_err();

        assert!(matches!(error, DaemonError::IncorrectPassphrase));
    }

    #[test]
    fn locking_makes_field_values_unreachable_again() {
        let dir = tempdir().unwrap();
        let backend = LocalBackend::open(dir.path().join("vault.toml")).unwrap();
        backend.unlock("test passphrase").unwrap();
        assert!(backend.is_unlocked());

        backend.lock();

        assert!(!backend.is_unlocked());
        let item = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
        assert!(backend.get_field("Personal", &item, "password").is_err());
    }

    #[test]
    fn the_demo_ssh_key_is_a_valid_ed25519_openssh_private_key() {
        let dir = tempdir().unwrap();
        let backend = LocalBackend::open(dir.path().join("vault.toml")).unwrap();
        backend.unlock("test passphrase").unwrap();

        let item = ItemPath::new(vec!["Production".to_string()]).unwrap();
        let value = backend
            .get_field("Infrastructure", &item, "ssh-key")
            .unwrap();

        let key = ssh_key::PrivateKey::from_openssh(value.expose_secret()).unwrap();
        assert_eq!(key.algorithm(), ssh_key::Algorithm::Ed25519);
    }
}
