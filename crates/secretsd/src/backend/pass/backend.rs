//! `PassBackend`: the `Backend`/`LockController` implementation over a
//! `pass`-compatible store directory (see ADR-019).
//!
//! Decryption is via rPGP (crate `pgp`), never by shelling out to `gpg`
//! or `pass` — ADR-012's rejection of a second, informal IPC surface
//! (subprocess + stdout) alongside D-Bus applies here identically. The
//! private key is a configured, ascii-armored, already-*exported* OpenPGP
//! secret key: `secretsd` never reads GnuPG's own `private-keys-v1.d`
//! keyring (an S-expression protected by gpg-agent's own protocol, not an
//! OpenPGP secret-key packet — rPGP has nothing to parse there). See
//! ADR-019 for the full rationale, including why this backend caches the
//! *passphrase* (zeroized) rather than a persistently-decrypted key.
//!
//! Flat error construction directly into `CoreError`/`DaemonError`,
//! mirroring `LocalBackend`'s style rather than `onepassword`'s two-tier
//! `CallError` design — this backend has few enough distinct failure
//! modes (locked, not found, corrupted/wrong-recipient) that an
//! intermediate enum would add indirection without benefit.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use pgp::composed::{Deserializable, Message, SignedSecretKey};
use pgp::types::Password;
use secrets_core::{
    Backend, CoreError, FieldKind, FieldMeta, Item, ItemPath, Result as CoreResult, SecretValue,
    Vault,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{DaemonError, Result};
use crate::state::LockController;

use super::format;
use super::walk;

/// The cached unlock passphrase, zeroized on lock/drop.
///
/// Not a decrypted key: rPGP's own API (`Message::decrypt(&Password,
/// &SignedSecretKey)`) takes the passphrase on every call and never
/// exposes a "stays unlocked" secret key object — the classic rPGP
/// pattern decrypts key material transiently, inside a closure's scope,
/// and never persists it on the struct. Caching the passphrase instead
/// achieves the same behavioral contract the issue asked for (one
/// prompt per `unlock`, not per read) without ever holding the raw,
/// unprotected private key scalar in memory longer than a single
/// `decrypt_file` call — see ADR-019's "Decision" section.
#[derive(Zeroize, ZeroizeOnDrop)]
struct CachedPassphrase(String);

/// The `Backend`/`LockController` for one `pass`-compatible store
/// directory.
///
/// Exposes exactly one vault: `pass` has no native multi-vault concept,
/// and multi-store support (#25/ADR-018) already covers "several
/// mounts" as separate configured store instances, so there is no need
/// to recover vault-like grouping from top-level directory names within
/// one store.
pub struct PassBackend {
    store_dir: PathBuf,
    vault_name: String,
    /// Always loaded (parsing an armored secret key file never requires
    /// the passphrase — only *using* the key material inside it does),
    /// so this is available even while locked, the same way
    /// `LocalBackend`'s vault-file metadata is.
    secret_key: SignedSecretKey,
    /// `None` while locked.
    passphrase: Mutex<Option<CachedPassphrase>>,
}

impl PassBackend {
    /// Open a `pass`-compatible store, without unlocking it.
    ///
    /// Unlike [`crate::backend::local::LocalBackend::open`], this never
    /// creates anything: a `pass` store is not something `secretsd`
    /// owns the lifecycle of, so a missing directory or an unreadable
    /// key file is a startup misconfiguration, not "not created yet"
    /// (mirrors the 1Password backend's fail-fast-at-startup precedent).
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::BackendUnavailable`] if `store_dir` does
    /// not exist or is not a directory, or
    /// [`DaemonError::SecretKeyUnreadable`] if `secret_key_path` cannot
    /// be read or does not contain a valid OpenPGP secret key.
    pub fn open(
        store_dir: PathBuf,
        secret_key_path: &Path,
        vault_name: Option<String>,
    ) -> Result<Self> {
        if !store_dir.is_dir() {
            return Err(DaemonError::BackendUnavailable(format!(
                "pass store directory does not exist or is not a directory: {}",
                store_dir.display()
            )));
        }
        let (secret_key, _headers) =
            SignedSecretKey::from_armor_file(secret_key_path).map_err(|error| {
                DaemonError::SecretKeyUnreadable {
                    path: secret_key_path.to_path_buf(),
                    reason: error.to_string(),
                }
            })?;
        let vault_name = vault_name.unwrap_or_else(|| default_vault_name(&store_dir));
        Ok(Self {
            store_dir,
            vault_name,
            secret_key,
            passphrase: Mutex::new(None),
        })
    }

    /// Whether the backend currently holds a cached passphrase.
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        self.passphrase.lock().expect("poisoned").is_some()
    }

    /// Verify `passphrase` actually decrypts the configured secret key,
    /// then cache it — a wrong passphrase is reported here, at unlock
    /// time, not deferred to the first read.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::IncorrectKeyPassphrase`] if `passphrase`
    /// does not unlock the primary key's secret material.
    pub fn unlock(&self, passphrase: &str) -> Result<()> {
        if self.is_unlocked() {
            return Ok(());
        }
        let password = Password::from(passphrase);
        // A no-op closure: the only thing this call needs is whether
        // unlocking succeeds at all (checksum/S2K verification), never
        // the plain secret params themselves — those are never touched
        // outside `decrypt_file`, one field read at a time.
        let verified = self
            .secret_key
            .primary_key
            .unlock(&password, |_public_params, _plain_secret_params| Ok(()));
        match verified {
            Ok(Ok(())) => {}
            _ => return Err(DaemonError::IncorrectKeyPassphrase),
        }
        *self.passphrase.lock().expect("poisoned") = Some(CachedPassphrase(passphrase.to_string()));
        Ok(())
    }

    /// Drop the cached passphrase.
    pub fn lock(&self) {
        *self.passphrase.lock().expect("poisoned") = None;
    }

    /// This store's single vault existence check.
    fn check_vault(&self, vault: &str) -> CoreResult<()> {
        if vault == self.vault_name {
            Ok(())
        } else {
            Err(CoreError::NotFound {
                store: None,
                vault: vault.to_string(),
                item: String::new(),
                field: String::new(),
            })
        }
    }
}

impl LockController for PassBackend {
    // Thin delegation, same shape as `LocalBackend`'s own impl: its
    // inherent methods stay directly callable by this module's own
    // tests, while `DaemonState` needs this impl to hold it as
    // `Arc<dyn LockController>`.
    fn is_unlocked(&self) -> bool {
        PassBackend::is_unlocked(self)
    }

    fn unlock(&self, passphrase: &str) -> Result<()> {
        PassBackend::unlock(self, passphrase)
    }

    fn lock(&self) {
        PassBackend::lock(self);
    }
}

impl Backend for PassBackend {
    fn list_vaults(&self) -> CoreResult<Vec<Vault>> {
        Ok(vec![Vault::new(self.vault_name.clone())])
    }

    fn list_items(&self, vault: &str) -> CoreResult<Vec<Item>> {
        self.check_vault(vault)?;
        let entries = walk::items(&self.store_dir).map_err(|error| {
            CoreError::BackendUnavailable(format!(
                "could not read pass store directory {}: {error}",
                self.store_dir.display()
            ))
        })?;

        let passphrase = self.passphrase.lock().expect("poisoned");
        let items = entries
            .into_iter()
            .map(|entry| {
                let fields = passphrase
                    .as_ref()
                    .and_then(|cached| decrypt_file(&entry.file, &self.secret_key, &cached.0))
                    .map(field_metadata_from_plaintext)
                    // Locked, or this specific item doesn't decrypt with
                    // the configured key (wrong recipient, corrupted
                    // ciphertext) — one fallback for both, see this
                    // module's own doc comment and ADR-019. Never fails
                    // the whole listing over one bad item.
                    .unwrap_or_else(default_field_list);
                Item {
                    path: entry.path,
                    fields,
                }
            })
            .collect();
        Ok(items)
    }

    fn get_field(&self, vault: &str, item: &ItemPath, field: &str) -> CoreResult<SecretValue> {
        self.check_vault(vault)?;
        let not_found = || not_found_error(vault, item, field);

        let Some(file) = entry_file(&self.store_dir, item) else {
            return Err(not_found());
        };
        if !file.is_file() {
            return Err(not_found());
        }

        let passphrase_guard = self.passphrase.lock().expect("poisoned");
        let Some(passphrase) = passphrase_guard.as_ref() else {
            return Err(CoreError::VaultLocked {
                store: None,
                vault: vault.to_string(),
            });
        };
        let mut plaintext = decrypt_file(&file, &self.secret_key, &passphrase.0)
            .ok_or_else(|| corrupted_error(vault, item, field))?;
        drop(passphrase_guard);

        let mut fields = format::parse_entry(&plaintext);
        plaintext.zeroize();

        let Some(index) = fields.iter().position(|f| f.name == field) else {
            for f in &mut fields {
                f.value.zeroize();
            }
            return Err(not_found());
        };
        let mut target = fields.swap_remove(index);
        for f in &mut fields {
            f.value.zeroize();
        }
        let value = std::mem::take(&mut target.value);
        Ok(SecretValue::new(value))
    }
}

fn not_found_error(vault: &str, item: &ItemPath, field: &str) -> CoreError {
    CoreError::NotFound {
        store: None,
        vault: vault.to_string(),
        item: item.to_string(),
        field: field.to_string(),
    }
}

/// Never includes plaintext or ciphertext — only names the reference
/// that failed, per AGENTS.md invariant #1, matching `LocalBackend`'s
/// own "stored value ... is corrupted" wording exactly.
fn corrupted_error(vault: &str, item: &ItemPath, field: &str) -> CoreError {
    CoreError::BackendUnavailable(format!(
        "stored value for secret://{vault}/{item}/{field} is corrupted, \
         or was not encrypted to the configured key"
    ))
}

/// The field list reported for an item that cannot currently be
/// decrypted (locked, or this specific file doesn't decrypt with the
/// configured key) — a heuristic derived from `pass`'s own structural
/// convention about line 1, never a peek at actual ciphertext/plaintext.
fn default_field_list() -> Vec<FieldMeta> {
    vec![FieldMeta {
        name: format::PASSWORD_FIELD_NAME.to_string(),
        kind: FieldKind::Password,
    }]
}

/// Parse a decrypted entry into field metadata only, zeroizing every
/// field's value (including ones never returned) and the plaintext
/// itself before this returns — `list_items` never needs values, so
/// none may outlive this call.
fn field_metadata_from_plaintext(mut plaintext: String) -> Vec<FieldMeta> {
    let mut parsed = format::parse_entry(&plaintext);
    let fields = parsed
        .drain(..)
        .map(|mut field| {
            field.value.zeroize();
            FieldMeta {
                name: field.name,
                kind: field.kind,
            }
        })
        .collect();
    plaintext.zeroize();
    fields
}

/// Map an [`ItemPath`] to its `.gpg` file under `store_dir`.
///
/// Rejects any segment that could escape `store_dir` (`..`, or one
/// containing a path separator) — segments ultimately come from a
/// `secret://` URI's percent-decoded path, and unlike `LocalBackend`
/// (where the equivalent join is only ever used as a `BTreeMap` key,
/// never a filesystem path), a crafted segment here would otherwise
/// reach real file I/O. Returns `None` rather than a `CoreError`
/// directly since every caller already has its own not-found variant to
/// construct with full vault/item/field context.
fn entry_file(store_dir: &Path, item: &ItemPath) -> Option<PathBuf> {
    let mut path = store_dir.to_path_buf();
    for segment in item.segments() {
        if segment.is_empty() || segment == ".." || segment.contains('/') || segment.contains('\\')
        {
            return None;
        }
        path.push(segment);
    }
    path.set_extension("gpg");
    Some(path)
}

/// Decrypt one `.gpg` file's full plaintext contents.
///
/// `None` on any failure (I/O, malformed OpenPGP data, wrong passphrase,
/// ciphertext encrypted to a different key) — callers distinguish
/// "locked" (no cached passphrase at all, checked before this is ever
/// called) from "this item won't decrypt" themselves; this function
/// only ever answers the latter question, uniformly, on purpose (see
/// this module's own doc comment on why one fallback covers both a
/// locked store and an undecryptable item in `list_items`).
fn decrypt_file(file: &Path, secret_key: &SignedSecretKey, passphrase: &str) -> Option<String> {
    let bytes = std::fs::read(file).ok()?;
    let message = Message::from_bytes(&bytes[..]).ok()?;
    let password = Password::from(passphrase);
    let mut decrypted = message.decrypt(&password, secret_key).ok()?;
    decrypted.as_data_string().ok()
}

/// The vault name a store exposes when `[store.<id>] type = "pass"` does
/// not set one explicitly: `store_dir`'s own basename, with a single
/// leading `.` stripped (`~/.password-store` -> `"password-store"`) —
/// a friendly zero-config default for the overwhelmingly common case
/// (`pass`'s own default store location starts with a dot).
fn default_vault_name(store_dir: &Path) -> String {
    let base = store_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("pass");
    base.strip_prefix('.').unwrap_or(base).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::composed::{
        EncryptionCaps, KeyType, MessageBuilder, SecretKeyParamsBuilder, SignedPublicKey,
        SubkeyParamsBuilder,
    };
    use pgp::crypto::ecc_curve::ECCCurve;
    use pgp::crypto::sym::SymmetricKeyAlgorithm;
    use pretty_assertions::assert_eq;
    use tempfile::tempdir;

    /// Generate a fresh, passphrase-protected OpenPGP keypair entirely
    /// in-process — no `gpg` binary involved, per the issue's own
    /// testing requirement. Mirrors rPGP's own crate-level doc example
    /// (`https://docs.rs/pgp/latest/pgp/composed/index.html`).
    fn generate_test_key(passphrase: &str) -> SignedSecretKey {
        let mut key_params = SecretKeyParamsBuilder::default();
        key_params
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id("secretsd pass backend test <test@example.invalid>".to_string())
            .passphrase(Some(passphrase.to_string()))
            .subkeys(vec![
                SubkeyParamsBuilder::default()
                    .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
                    .can_encrypt(EncryptionCaps::All)
                    .passphrase(Some(passphrase.to_string()))
                    .build()
                    .expect("subkey params are valid"),
            ]);
        key_params
            .build()
            .expect("secret key params are valid")
            .generate(rand::thread_rng())
            .expect("key generation succeeds")
    }

    /// Encrypt `plaintext` to `public_key`'s first encryption subkey and
    /// write the result as a binary (non-armored) `.gpg` file — matching
    /// real `pass`, which never passes `--armor` to `gpg`.
    fn write_entry(path: &std::path::Path, plaintext: &str, public_key: &SignedPublicKey) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut builder = MessageBuilder::from_bytes("", plaintext.as_bytes().to_vec())
            .seipd_v1(rand::thread_rng(), SymmetricKeyAlgorithm::AES128);
        builder
            .encrypt_to_key(rand::thread_rng(), &public_key.public_subkeys[0])
            .expect("encryption to subkey works");
        let encrypted = builder.to_vec(rand::thread_rng()).expect("serializes");
        std::fs::write(path, encrypted).expect("write fixture file");
    }

    /// A ready-to-use store: one keypair, one `.gpg` entry at
    /// `Personal/GitHub.gpg`, matching the `LocalBackend` test fixtures'
    /// own demo shape closely enough to cross-reference.
    struct Fixture {
        _dir: tempfile::TempDir,
        store_dir: PathBuf,
        secret_key_path: PathBuf,
        passphrase: &'static str,
    }

    fn fixture_with_entry(plaintext: &str) -> Fixture {
        let dir = tempdir().unwrap();
        let store_dir = dir.path().join(".password-store");
        std::fs::create_dir_all(&store_dir).unwrap();
        let passphrase = "test key passphrase";
        let secret_key = generate_test_key(passphrase);
        let public_key = secret_key.to_public_key();
        write_entry(
            &store_dir.join("Personal/GitHub.gpg"),
            plaintext,
            &public_key,
        );

        let secret_key_path = dir.path().join("key.asc");
        std::fs::write(
            &secret_key_path,
            secret_key
                .to_armored_string(Default::default())
                .expect("armors"),
        )
        .unwrap();

        Fixture {
            _dir: dir,
            store_dir,
            secret_key_path,
            passphrase,
        }
    }

    fn open(fixture: &Fixture) -> PassBackend {
        PassBackend::open(fixture.store_dir.clone(), &fixture.secret_key_path, None).unwrap()
    }

    #[test]
    fn unlocking_with_the_correct_passphrase_allows_reading_fields() {
        let fixture = fixture_with_entry("correct horse battery staple\nlogin: octocat");
        let backend = open(&fixture);

        backend.unlock(fixture.passphrase).unwrap();

        let item = ItemPath::new(vec!["Personal".into(), "GitHub".into()]).unwrap();
        let value = backend
            .get_field("password-store", &item, "password")
            .unwrap();
        assert_eq!(value.expose_secret(), "correct horse battery staple");
        let username = backend
            .get_field("password-store", &item, "username")
            .unwrap();
        assert_eq!(username.expose_secret(), "octocat");
    }

    #[test]
    fn unlocking_with_the_wrong_passphrase_is_rejected() {
        let fixture = fixture_with_entry("correct horse battery staple");
        let backend = open(&fixture);

        let error = backend.unlock("wrong passphrase").unwrap_err();

        assert!(matches!(error, DaemonError::IncorrectKeyPassphrase));
        assert!(!backend.is_unlocked());
    }

    #[test]
    fn reading_a_field_while_locked_fails_with_vault_locked() {
        let fixture = fixture_with_entry("correct horse battery staple");
        let backend = open(&fixture);

        let item = ItemPath::new(vec!["Personal".into(), "GitHub".into()]).unwrap();
        let error = backend
            .get_field("password-store", &item, "password")
            .unwrap_err();

        assert!(matches!(error, CoreError::VaultLocked { .. }));
    }

    #[test]
    fn listing_items_while_locked_reports_only_the_guessed_password_field() {
        let fixture = fixture_with_entry("correct horse battery staple\nlogin: octocat");
        let backend = open(&fixture);

        let items = backend.list_items("password-store").unwrap();

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].fields.len(), 1);
        assert_eq!(items[0].fields[0].name, "password");
    }

    #[test]
    fn listing_items_while_unlocked_reports_every_parsed_field() {
        let fixture = fixture_with_entry("correct horse battery staple\nlogin: octocat");
        let backend = open(&fixture);
        backend.unlock(fixture.passphrase).unwrap();

        let items = backend.list_items("password-store").unwrap();

        assert_eq!(items.len(), 1);
        let names: Vec<&str> = items[0].fields.iter().map(|f| f.name.as_str()).collect();
        assert!(names.contains(&"password"));
        assert!(names.contains(&"username"));
    }

    #[test]
    fn an_item_undecryptable_by_the_configured_key_degrades_gracefully_in_listing() {
        let fixture = fixture_with_entry("correct horse battery staple");
        let backend = open(&fixture);
        backend.unlock(fixture.passphrase).unwrap();

        // A second entry, encrypted to an *unrelated* keypair — this
        // store's own `.gpg-id` override is purely cosmetic (ADR-019),
        // so this simulates a real gopass "mount" scoped to a recipient
        // this store's configured key was never meant to read.
        let other_key = generate_test_key("other passphrase");
        std::fs::create_dir_all(fixture.store_dir.join("Nested")).unwrap();
        std::fs::write(
            fixture.store_dir.join("Nested/.gpg-id"),
            "other@example.invalid",
        )
        .unwrap();
        write_entry(
            &fixture.store_dir.join("Nested/secret.gpg"),
            "unreadable by our key",
            &other_key.to_public_key(),
        );

        let items = backend.list_items("password-store").unwrap();

        let nested = items
            .iter()
            .find(|item| item.path.segments() == ["Nested", "secret"])
            .expect("nested item is still listed");
        assert_eq!(nested.fields.len(), 1);
        assert_eq!(nested.fields[0].name, "password");
    }

    #[test]
    fn getting_a_field_on_an_undecryptable_item_reports_backend_unavailable_not_wrong_passphrase() {
        let fixture = fixture_with_entry("correct horse battery staple");
        let backend = open(&fixture);
        backend.unlock(fixture.passphrase).unwrap();

        let other_key = generate_test_key("other passphrase");
        write_entry(
            &fixture.store_dir.join("Other.gpg"),
            "unreadable by our key",
            &other_key.to_public_key(),
        );

        let item = ItemPath::new(vec!["Other".into()]).unwrap();
        let error = backend
            .get_field("password-store", &item, "password")
            .unwrap_err();

        assert!(matches!(error, CoreError::BackendUnavailable(_)));
    }

    #[test]
    fn an_otp_only_entry_reports_a_totp_field_not_a_password_field() {
        let fixture = fixture_with_entry("otpauth://totp/Example:octocat?secret=JBSWY3DPEHPK3PXP");
        let backend = open(&fixture);
        backend.unlock(fixture.passphrase).unwrap();

        let item = ItemPath::new(vec!["Personal".into(), "GitHub".into()]).unwrap();
        let value = backend.get_field("password-store", &item, "totp").unwrap();
        assert!(value.expose_secret().starts_with("otpauth://"));
        assert!(
            backend
                .get_field("password-store", &item, "password")
                .is_err()
        );
    }

    #[test]
    fn the_vault_name_defaults_to_the_store_directory_basename_with_leading_dot_stripped() {
        let fixture = fixture_with_entry("correct horse battery staple");
        let backend = open(&fixture);

        let vaults = backend.list_vaults().unwrap();

        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].name, "password-store");
    }

    #[test]
    fn opening_a_missing_store_directory_fails_at_open_not_silently() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let fixture = fixture_with_entry("correct horse battery staple");

        match PassBackend::open(missing, &fixture.secret_key_path, None) {
            Ok(_) => panic!("expected BackendUnavailable, got Ok"),
            Err(error) => assert!(matches!(error, DaemonError::BackendUnavailable(_))),
        }
    }

    #[test]
    fn a_wrong_vault_name_is_reported_as_not_found() {
        let fixture = fixture_with_entry("correct horse battery staple");
        let backend = open(&fixture);

        let error = backend.list_items("some-other-vault").unwrap_err();

        assert!(matches!(error, CoreError::NotFound { .. }));
    }

    /// Reads `testdata/gopass-fixture/` — a store generated once with the
    /// real `gpg`/`gopass` binaries (see that directory's own `README.md`
    /// for exact provenance and regeneration steps), checked in so this
    /// runs in CI without either binary installed. Proves on-disk-format
    /// compatibility beyond what the in-process-generated fixtures above
    /// already assume.
    #[test]
    fn reads_a_real_gopass_initialized_store_without_modification() {
        let fixture_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/backend/pass/testdata/gopass-fixture");
        let backend = PassBackend::open(
            fixture_dir.join("store"),
            &fixture_dir.join("key.asc"),
            None,
        )
        .unwrap();
        backend.unlock("fixture passphrase").unwrap();

        let vaults = backend.list_vaults().unwrap();
        assert_eq!(vaults.len(), 1);
        let vault = vaults[0].name.clone();

        let item = ItemPath::new(vec!["Personal".into(), "GitHub".into()]).unwrap();
        assert_eq!(
            backend
                .get_field(&vault, &item, "password")
                .unwrap()
                .expose_secret(),
            "correct horse battery staple"
        );
        assert_eq!(
            backend
                .get_field(&vault, &item, "username")
                .unwrap()
                .expose_secret(),
            "octocat"
        );
        assert_eq!(
            backend
                .get_field(&vault, &item, "url")
                .unwrap()
                .expose_secret(),
            "github.com"
        );

        let otp_item = ItemPath::new(vec!["Personal".into(), "OtpOnly".into()]).unwrap();
        assert!(
            backend
                .get_field(&vault, &otp_item, "totp")
                .unwrap()
                .expose_secret()
                .starts_with("otpauth://")
        );

        // The nested `.gpg-id` override under `Servers/` is encrypted to
        // a different, unrelated, discarded key — walked (still listed)
        // but never decryptable by this fixture's own configured key,
        // per ADR-019's "cosmetic for reads" decision.
        let items = backend.list_items(&vault).unwrap();
        let nested = items
            .iter()
            .find(|item| item.path.segments() == ["Servers", "db"])
            .expect("the nested-.gpg-id item is still listed");
        assert_eq!(nested.fields.len(), 1);
        assert_eq!(nested.fields[0].name, "password");

        let nested_item = ItemPath::new(vec!["Servers".into(), "db".into()]).unwrap();
        let error = backend
            .get_field(&vault, &nested_item, "password")
            .unwrap_err();
        assert!(matches!(error, CoreError::BackendUnavailable(_)));
    }

    #[test]
    fn a_path_traversal_attempt_in_an_item_segment_is_rejected_not_resolved() {
        let fixture = fixture_with_entry("correct horse battery staple");
        let backend = open(&fixture);
        backend.unlock(fixture.passphrase).unwrap();

        let item = ItemPath::new(vec!["..".into(), "etc".into(), "passwd".into()]).unwrap();
        let error = backend
            .get_field("password-store", &item, "password")
            .unwrap_err();

        assert!(matches!(error, CoreError::NotFound { .. }));
    }
}
