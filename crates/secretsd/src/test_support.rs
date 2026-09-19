//! Shared test-only fixtures for building a [`DaemonState`] over one or
//! more throwaway local vaults, with or without a fixture backend
//! session — used by unit tests across this crate (`state`,
//! `secret_service::*`, `ssh_agent`) that need to exercise lock/session
//! gating without a real external backend.
//!
//! Kept in one place so every module's tests build `DaemonState` the exact
//! same way production code does (a registry of [`StoreEntry`] values),
//! rather than each reinventing a slightly different fixture.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use secrets_core::{Backend, BackendSession, BackendStatus, StoreId};
use tempfile::TempDir;

use crate::backend::local::LocalBackend;
use crate::state::{DaemonState, LockController, StoreEntry};

/// A fixture [`BackendSession`] whose reported status is set by the
/// caller, so session-gating logic can be exercised without a real
/// external backend.
pub(crate) struct FixedSession(pub BackendStatus);

impl BackendSession for FixedSession {
    fn backend_status(&self) -> BackendStatus {
        self.0
    }
}

/// The store id every single-store fixture in this module uses — matches
/// [`crate::state::open_registry`]'s implicit zero-config store id, so a
/// test exercising the default/zero-config path uses the exact same id
/// production code would.
pub(crate) fn default_store_id() -> StoreId {
    StoreId::new("default").expect("literal \"default\" is always a valid id")
}

/// Builds a `DaemonState` the same way `open_registry` does for a
/// zero-config, single local store, against a throwaway vault file — no
/// backend session (matches the local backend, which has none).
pub(crate) fn state_over_fresh_vault() -> (TempDir, DaemonState) {
    let dir = tempfile::tempdir().expect("create a temporary directory");
    let local =
        Arc::new(LocalBackend::open(dir.path().join("vault.toml")).expect("open a fresh vault"));
    let backend: Arc<dyn Backend> = local.clone();
    let lock_controller: Arc<dyn LockController> = local;
    let mut stores = BTreeMap::new();
    stores.insert(
        default_store_id(),
        StoreEntry {
            backend,
            lock_controller,
            has_real_lock: true,
            session: None,
        },
    );
    (dir, DaemonState::new(stores))
}

/// Same as [`state_over_fresh_vault`], but with a fixture backend session
/// attached, reporting `status`.
pub(crate) fn state_with_backend_session(status: BackendStatus) -> (TempDir, DaemonState) {
    let dir = tempfile::tempdir().expect("create a temporary directory");
    let local =
        Arc::new(LocalBackend::open(dir.path().join("vault.toml")).expect("open a fresh vault"));
    let backend: Arc<dyn Backend> = local.clone();
    let lock_controller: Arc<dyn LockController> = local;
    let session: Arc<dyn BackendSession> = Arc::new(FixedSession(status));
    let mut stores = BTreeMap::new();
    stores.insert(
        default_store_id(),
        StoreEntry {
            backend,
            lock_controller,
            // This fixture exists to exercise `BackendSession` gating in
            // isolation from a real passphrase lock, so its
            // `LockController` is still a real one — the local backend's
            // own — deliberately, not `AlwaysUnlocked`: every call site
            // still calls `.unlock(...)` first, exactly as production
            // code's local-backend stores require.
            has_real_lock: true,
            session: Some(session),
        },
    );
    (dir, DaemonState::new(stores))
}

/// One field to seed via [`seed_local_vault_file`]: `(vault, item, field,
/// kind, plaintext)`.
type SeedField<'a> = (&'a str, &'a str, &'a str, &'a str, &'a str);

/// Write a minimal, valid local-backend vault file directly to disk,
/// bypassing [`LocalBackend::unlock`]'s hardcoded demo-vault seeding —
/// used to build vault files with custom vault/item/field names, kinds
/// and known plaintext values for multi-store fixtures.
///
/// Deliberately duplicates just enough of `backend::local`'s own on-disk
/// shape (`meta`/`vaults.<name>.items.<name>.fields.<name>`) to round-trip
/// through its private `VaultFile`/serde types without needing to expose
/// them outside that module — `toml::Value` doesn't care about Rust
/// visibility, only about matching field names.
fn seed_local_vault_file(path: &std::path::Path, passphrase: &str, fields: &[SeedField<'_>]) {
    let salt = crate::crypto::generate_salt();
    let key = crate::crypto::derive_key(passphrase, &salt).expect("valid salt/output length");
    let canary = crate::crypto::encrypt(&key, "secrets-vault-integrity-check");

    let mut vaults_table = toml::map::Map::new();
    for (vault, item, field, kind, plaintext) in fields {
        let encrypted = crate::crypto::encrypt(&key, plaintext);
        let mut field_table = toml::map::Map::new();
        field_table.insert("kind".to_string(), toml::Value::String((*kind).to_string()));
        field_table.insert(
            "nonce".to_string(),
            toml::Value::String(BASE64.encode(encrypted.nonce)),
        );
        field_table.insert(
            "ciphertext".to_string(),
            toml::Value::String(BASE64.encode(encrypted.ciphertext)),
        );

        let vault_table = vaults_table
            .entry((*vault).to_string())
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
            .as_table_mut()
            .expect("just inserted as a table");
        let items_table = vault_table
            .entry("items".to_string())
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
            .as_table_mut()
            .expect("just inserted as a table");
        let item_table = items_table
            .entry((*item).to_string())
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
            .as_table_mut()
            .expect("just inserted as a table");
        let fields_table = item_table
            .entry("fields".to_string())
            .or_insert_with(|| toml::Value::Table(toml::map::Map::new()))
            .as_table_mut()
            .expect("just inserted as a table");
        fields_table.insert((*field).to_string(), toml::Value::Table(field_table));
    }

    let mut meta_table = toml::map::Map::new();
    meta_table.insert(
        "kdf".to_string(),
        toml::Value::String("argon2id".to_string()),
    );
    meta_table.insert("salt".to_string(), toml::Value::String(BASE64.encode(salt)));
    meta_table.insert(
        "check_nonce".to_string(),
        toml::Value::String(BASE64.encode(canary.nonce)),
    );
    meta_table.insert(
        "check_ciphertext".to_string(),
        toml::Value::String(BASE64.encode(canary.ciphertext)),
    );

    let mut root = toml::map::Map::new();
    root.insert("meta".to_string(), toml::Value::Table(meta_table));
    root.insert("vaults".to_string(), toml::Value::Table(vaults_table));

    let contents = toml::to_string(&toml::Value::Table(root)).expect("valid TOML document");
    std::fs::write(path, contents).expect("write the fixture vault file");
}

/// A fresh, valid OpenSSH-formatted Ed25519 private key, for fixtures that
/// need a real `FieldKind::SshKey`-shaped value (matches
/// `backend::local`'s own demo-vault key generation).
fn generate_ssh_private_key() -> String {
    let private_key =
        ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519)
            .expect("Ed25519 key generation always succeeds");
    private_key
        .to_openssh(ssh_key::LineEnding::LF)
        .expect("a freshly generated key always serializes")
        .to_string()
}

/// Two local stores, `"a"` and `"b"`, each with their own passphrase and
/// vault file, both defining a vault literally named `"Shared"` with an
/// `"Item"`/`"password"` field of a different value, and their own
/// `"ssh-key"` field with a distinct generated key — the exact collision
/// scenario ADR-018's ambiguity-resolution rule exists for, plus enough to
/// exercise the SSH agent's cross-store aggregation. Store `"a"`
/// additionally has a vault named `"OnlyInA"`, unique across both stores,
/// used to test that an unqualified-but-unique name still resolves
/// without a `store@` qualifier.
///
/// Returns the temp directories (keep them alive for the fixture's
/// lifetime), the built `DaemonState`, and both stores' ids.
pub(crate) fn state_over_two_local_stores_with_a_colliding_vault()
-> (Vec<TempDir>, DaemonState, StoreId, StoreId) {
    let dir_a = tempfile::tempdir().expect("create a temporary directory");
    let dir_b = tempfile::tempdir().expect("create a temporary directory");
    let path_a = dir_a.path().join("a.toml");
    let path_b = dir_b.path().join("b.toml");
    let ssh_key_a = generate_ssh_private_key();
    let ssh_key_b = generate_ssh_private_key();

    seed_local_vault_file(
        &path_a,
        "a passphrase",
        &[
            ("Shared", "Item", "password", "password", "a-value"),
            ("Shared", "Item", "ssh-key", "ssh-key", ssh_key_a.as_str()),
            ("OnlyInA", "Item", "password", "password", "only-in-a-value"),
        ],
    );
    seed_local_vault_file(
        &path_b,
        "b passphrase",
        &[
            ("Shared", "Item", "password", "password", "b-value"),
            ("Shared", "Item", "ssh-key", "ssh-key", ssh_key_b.as_str()),
        ],
    );

    let store_a = StoreId::new("a").expect("literal \"a\" is always a valid id");
    let store_b = StoreId::new("b").expect("literal \"b\" is always a valid id");

    let local_a = Arc::new(LocalBackend::open(path_a).expect("open the seeded vault"));
    let local_b = Arc::new(LocalBackend::open(path_b).expect("open the seeded vault"));

    let mut stores = BTreeMap::new();
    stores.insert(
        store_a.clone(),
        StoreEntry {
            backend: local_a.clone(),
            lock_controller: local_a,
            has_real_lock: true,
            session: None,
        },
    );
    stores.insert(
        store_b.clone(),
        StoreEntry {
            backend: local_b.clone(),
            lock_controller: local_b,
            has_real_lock: true,
            session: None,
        },
    );

    (
        vec![dir_a, dir_b],
        DaemonState::new(stores),
        store_a,
        store_b,
    )
}
