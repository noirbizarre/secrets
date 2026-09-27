//! The daemon's shared, authoritative state.
//!
//! One [`DaemonState`], held behind an `Arc` and shared by every D-Bus
//! interface (`org.secrets.Manager`, the Secret Service compatibility
//! objects) and the SSH agent. `DaemonState` holds a registry of every
//! configured *store* (ADR-018) — a store is one backend instance, which
//! may itself expose several named vaults — each with its own lock/session
//! state, so the three surfaces can never disagree about a given store's
//! accessibility, even though different stores may disagree with each
//! other.

use std::collections::BTreeMap;
use std::sync::Arc;

use secrets_core::dbus::{FieldDisplay, OBFUSCATED_FIELD_PLACEHOLDER};
use secrets_core::{
    Backend, BackendSession, BackendStatus, CoreError, Item, ItemPath, ItemUri, Resolver,
    SecretUri, SecretValue, StoreId, Vault,
};

use crate::backend::local::LocalBackend;
use crate::error::{DaemonError, Result};

/// The daemon-wide lock/unlock mechanism (ADR-0009) — distinct from a
/// backend's own session (ADR-0011, [`BackendSession`]). `LocalBackend`
/// implements this over its passphrase-derived key (its "unlock" *is*
/// the daemon lock — see ADR-0006/0009). A backend with no local secret
/// of its own to protect this way (1Password Desktop, which gates access
/// through its own [`BackendSession`] instead) uses
/// [`AlwaysUnlocked`] — there is nothing for a daemon-wide passphrase
/// lock to mean in that case, so it is a deliberate, documented no-op,
/// not an oversight.
///
/// Per-store, not daemon-wide (ADR-018 supersedes ADR-0009's original
/// "daemon-wide, not per-vault" framing on this specific point): each
/// [`StoreEntry`] holds its own `Arc<dyn LockController>`, so two local
/// stores may have different passphrases and independent lock states.
/// `Manager.Unlock`/`Lock`/`Status`'s zero-argument wire methods remain,
/// redefined as [`DaemonState`]'s own explicit composition over every
/// store ([`DaemonState::unlock_default`]/[`DaemonState::lock_all`]/
/// [`DaemonState::status_summary`]) — not a second lock beside the
/// per-store ones.
///
/// Kept `secretsd`-internal (not in `secrets-core`): unlike `Backend`/
/// `BackendSession`, no other crate needs to know this trait's shape —
/// `secrets-cli` only ever reaches lock state through `DaemonState` via
/// D-Bus, never this trait directly.
pub trait LockController: Send + Sync {
    /// Whether the store is currently unlocked.
    fn is_unlocked(&self) -> bool;

    /// Unlock (or, for `LocalBackend`, on first run, initialize) the
    /// store.
    ///
    /// # Errors
    ///
    /// Backend-specific; see the implementing type.
    fn unlock(&self, passphrase: &str) -> Result<()>;

    /// Lock the store, dropping any derived key from memory.
    fn lock(&self);
}

/// The trivial [`LockController`] for backends with no daemon-wide
/// passphrase lock of their own — see the trait's own doc comment for
/// why this is correct, not a missing feature. `unlock`/`lock` are
/// deliberate no-ops; `is_unlocked` always reports `true`, so the
/// per-store lock check in [`DaemonState::get`]/
/// [`DaemonState::validate_reference`] always passes, leaving the
/// *real* gating to that store's own [`BackendSession`].
pub struct AlwaysUnlocked;

impl LockController for AlwaysUnlocked {
    fn is_unlocked(&self) -> bool {
        true
    }

    fn unlock(&self, _passphrase: &str) -> Result<()> {
        Ok(())
    }

    fn lock(&self) {}
}

/// One configured store: its backend (read path), its lock controller,
/// and its optional external session — exactly the three things
/// `DaemonState` held once, pre-ADR-018, now held once per store.
pub struct StoreEntry {
    /// The read path (`list_vaults`/`list_items`/resolution) — held as
    /// `Arc<dyn Backend>` so it works against any backend, per ADR-0008.
    pub backend: Arc<dyn Backend>,
    /// This store's own lock/unlock/status — not part of the `Backend`
    /// trait (it varies too much between backend shapes to force into
    /// one signature) — see [`LockController`].
    pub lock_controller: Arc<dyn LockController>,
    /// Whether `lock_controller` is a real, passphrase-backed lock, as
    /// opposed to [`AlwaysUnlocked`]. Set once at construction time
    /// (`build_store_entry`), never inferred by downcasting the trait
    /// object — [`DaemonState::unlock_default`]/
    /// [`DaemonState::status_summary`] need to know which stores have a
    /// real lock to compose over, and a boolean recorded at the one
    /// place that already knows is simpler than runtime introspection.
    pub has_real_lock: bool,
    /// This store's own *external* authentication/session state (see
    /// [`BackendSession`], ADR-0011), distinct from `lock_controller`'s
    /// lock/unlock. `None` for stores with no such concept — the local
    /// backend never sets this, since its "unlock" already is its lock.
    pub session: Option<Arc<dyn BackendSession>>,
}

/// Shared daemon state: a registry of every configured store (ADR-018).
pub struct DaemonState {
    stores: BTreeMap<StoreId, StoreEntry>,
}

impl DaemonState {
    /// Wrap a registry of configured stores as shared daemon state.
    #[must_use]
    pub fn new(stores: BTreeMap<StoreId, StoreEntry>) -> Self {
        Self { stores }
    }

    /// Every configured store's id, in a stable (`StoreId`) order.
    pub fn store_ids(&self) -> impl Iterator<Item = &StoreId> {
        self.stores.keys()
    }

    /// Look up one store's entry.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::StoreNotFound`] if no store with this id is
    /// configured.
    fn entry(&self, store: &StoreId) -> std::result::Result<&StoreEntry, CoreError> {
        self.stores
            .get(store)
            .ok_or_else(|| CoreError::StoreNotFound {
                store: store.clone(),
            })
    }

    /// Check one store's own session state, if it has one.
    ///
    /// Called in addition to (never instead of) that store's lock check
    /// in [`DaemonState::get`]/[`DaemonState::validate_reference`] — the
    /// two answer different questions and neither substitutes for the
    /// other. `BackendUnavailable`/`BackendRequiresAuthentication` carry
    /// no dedicated store field (ADR-018 keeps them as plain
    /// descriptions, since a [`Backend`] impl also constructs them
    /// directly and never knows its own store id) — the store is folded
    /// into the message text here instead, at the one place that does
    /// know it.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::BackendRequiresAuthentication`] if the store
    /// reports [`BackendStatus::RequiresAuthentication`] or
    /// [`BackendStatus::SessionExpired`], or
    /// [`CoreError::BackendUnavailable`] if it reports
    /// [`BackendStatus::Unavailable`]. `None` (no session concept) and
    /// [`BackendStatus::Available`]/[`BackendStatus::Authenticated`] both
    /// pass.
    fn check_backend_session(
        store: &StoreId,
        entry: &StoreEntry,
    ) -> std::result::Result<(), CoreError> {
        let Some(session) = &entry.session else {
            return Ok(());
        };
        match session.backend_status() {
            BackendStatus::Available | BackendStatus::Authenticated => Ok(()),
            BackendStatus::RequiresAuthentication => {
                Err(CoreError::BackendRequiresAuthentication(format!(
                    "store '{store}' has no active session; it must be authenticated before secrets can be read"
                )))
            }
            BackendStatus::SessionExpired => Err(CoreError::BackendRequiresAuthentication(
                format!("store '{store}' session has expired and needs renewal"),
            )),
            BackendStatus::Unavailable => Err(CoreError::BackendUnavailable(format!(
                "store '{store}' is not reachable"
            ))),
        }
    }

    /// Resolve an optional store qualifier and a bare vault name to
    /// exactly one configured store — the ambiguity-resolution rule
    /// ADR-018 defines for every unqualified `secret://` reference and
    /// `Manager.list_items` call.
    ///
    /// With exactly one configured store, an unqualified `vault` always
    /// resolves to it directly, without ever asking whether that store
    /// currently lists a vault by that name — a single-store deployment
    /// has nothing to disambiguate, so this preserves single-backend
    /// behavior byte-for-byte, *including* a never-unlocked (and so
    /// vault-file-less) store still reporting [`CoreError::VaultLocked`]
    /// (checked by the caller, after this returns) rather than
    /// [`CoreError::NotFound`] for a reference that would exist once
    /// unlocked (ADR-0009: locked is reported before existence is even
    /// checked). With two or more configured stores, that same "trust it
    /// blindly" shortcut is not available — genuine ambiguity is
    /// possible, so this actually asks each one.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::StoreNotFound`] if `store` names an
    /// unconfigured store. With `store: None` and two or more configured
    /// stores: [`CoreError::NotFound`] if none of them has a vault named
    /// `vault`, [`CoreError::AmbiguousVault`] if more than one does. A
    /// store that fails to list its own vaults during this scan is
    /// logged and treated as "no match from this store", never as a
    /// reason to fail the whole resolution — a broken store must not
    /// make an unrelated store's unambiguous vault suddenly unresolvable.
    fn resolve_store(
        &self,
        store: Option<&StoreId>,
        vault: &str,
    ) -> std::result::Result<StoreId, CoreError> {
        if let Some(id) = store {
            return self.entry(id).map(|_| id.clone());
        }
        let mut ids = self.stores.keys();
        if let (Some(only), None) = (ids.next(), ids.next()) {
            return Ok(only.clone());
        }
        let mut candidates = Vec::new();
        for (id, entry) in &self.stores {
            match Resolver::new(entry.backend.as_ref()).list_vaults() {
                Ok(vaults) => {
                    if vaults.iter().any(|found| found.name == vault) {
                        candidates.push(id.clone());
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        store = %id,
                        %error,
                        "store failed to list its vaults while resolving an unqualified vault name"
                    );
                }
            }
        }
        match candidates.len() {
            0 => Err(CoreError::NotFound {
                store: None,
                vault: vault.to_string(),
                item: String::new(),
                field: String::new(),
            }),
            1 => Ok(candidates.remove(0)),
            _ => Err(CoreError::AmbiguousVault {
                vault: vault.to_string(),
                candidates,
            }),
        }
    }

    /// `"locked"` or `"unlocked"`, matching
    /// [`secrets_core::dbus::STATUS_LOCKED`] /
    /// [`secrets_core::dbus::STATUS_UNLOCKED`], for one store.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::StoreNotFound`] if no store with this id is
    /// configured.
    pub fn status(&self, store: &StoreId) -> std::result::Result<&'static str, CoreError> {
        let entry = self.entry(store)?;
        Ok(if entry.lock_controller.is_unlocked() {
            secrets_core::dbus::STATUS_UNLOCKED
        } else {
            secrets_core::dbus::STATUS_LOCKED
        })
    }

    /// Whether one store is currently unlocked. `false` (not an error) if
    /// no store with this id is configured — a defensive default for
    /// callers (the Secret Service layer, the SSH agent) that already
    /// enumerate configured stores via [`DaemonState::store_ids`] and
    /// treat "not accessible" and "doesn't exist" the same way.
    #[must_use]
    pub fn is_unlocked(&self, store: &StoreId) -> bool {
        self.stores
            .get(store)
            .is_some_and(|entry| entry.lock_controller.is_unlocked())
    }

    /// Unlock one store with its master passphrase.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::StoreNotFound`] if no store with this id is
    /// configured, or propagates that store's own [`LockController`]
    /// error otherwise.
    pub fn unlock(&self, store: &StoreId, passphrase: &str) -> Result<()> {
        let entry = self
            .stores
            .get(store)
            .ok_or_else(|| DaemonError::StoreNotFound(store.to_string()))?;
        entry.lock_controller.unlock(passphrase)
    }

    /// Lock one store, dropping any derived key from memory.
    ///
    /// # Errors
    ///
    /// Returns [`DaemonError::StoreNotFound`] if no store with this id is
    /// configured.
    pub fn lock(&self, store: &StoreId) -> Result<()> {
        let entry = self
            .stores
            .get(store)
            .ok_or_else(|| DaemonError::StoreNotFound(store.to_string()))?;
        entry.lock_controller.lock();
        Ok(())
    }

    /// Unlock the single store that has a real passphrase lock — the
    /// composite behind `Manager.Unlock`'s zero-argument wire method
    /// (ADR-018).
    ///
    /// # Errors
    ///
    /// A no-op (`Ok(())`) if no configured store has a real lock.
    /// Returns [`DaemonError::StoreSelectionRequired`] if more than one
    /// does — applying one passphrase to every real-locked store would
    /// silently be wrong the moment two stores have different
    /// passphrases, so this never guesses. Otherwise propagates that one
    /// store's own [`LockController`] error.
    pub fn unlock_default(&self, passphrase: &str) -> Result<()> {
        let mut real_locks = self.stores.iter().filter(|(_, entry)| entry.has_real_lock);
        let Some((id, entry)) = real_locks.next() else {
            return Ok(());
        };
        if let Some((second, _)) = real_locks.next() {
            let mut candidates: Vec<&StoreId> = vec![id, second];
            candidates.extend(real_locks.map(|(id, _)| id));
            return Err(DaemonError::StoreSelectionRequired(join_store_ids(
                candidates,
            )));
        }
        entry.lock_controller.unlock(passphrase)
    }

    /// Lock every configured store unconditionally, including stores
    /// with no real lock of their own (a harmless no-op for those) — the
    /// composite behind `Manager.Lock`'s zero-argument wire method
    /// (ADR-018). Locking, unlike unlocking, carries no per-store secret
    /// to misapply, so there is nothing to disambiguate.
    pub fn lock_all(&self) {
        for entry in self.stores.values() {
            entry.lock_controller.lock();
        }
    }

    /// `"unlocked"` iff every store with a real passphrase lock reports
    /// unlocked (vacuously true if none has one) — the composite behind
    /// `Manager.Status`'s zero-argument wire method (ADR-018).
    #[must_use]
    pub fn status_summary(&self) -> &'static str {
        let all_unlocked = self
            .stores
            .values()
            .filter(|entry| entry.has_real_lock)
            .all(|entry| entry.lock_controller.is_unlocked());
        if all_unlocked {
            secrets_core::dbus::STATUS_UNLOCKED
        } else {
            secrets_core::dbus::STATUS_LOCKED
        }
    }

    /// List one store's vault names. Available regardless of lock state.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::StoreNotFound`] if no store with this id is
    /// configured, or propagates that store's backend error otherwise.
    pub fn list_vaults(&self, store: &StoreId) -> std::result::Result<Vec<Vault>, CoreError> {
        let entry = self.entry(store)?;
        Resolver::new(entry.backend.as_ref())
            .list_vaults()
            .map_err(|error| error.with_store(store))
    }

    /// List every configured store's vaults, paired with the store each
    /// came from. Used by `Manager.ListVaults` and the Secret Service
    /// topology scan (`secret_service::discover`) — both need every
    /// vault across every store, not one store at a time.
    ///
    /// # Errors
    ///
    /// Propagates the first store's backend error, if any — matching
    /// today's single-backend behavior of failing the whole scan on one
    /// backend error; `secret_service::refresh`'s caller already treats
    /// a failed scan as "keep the previous topology", never fatal
    /// (ADR-015).
    pub fn list_all_vaults(&self) -> std::result::Result<Vec<(StoreId, Vault)>, CoreError> {
        let mut all = Vec::new();
        for (id, entry) in &self.stores {
            let vaults = Resolver::new(entry.backend.as_ref())
                .list_vaults()
                .map_err(|error| error.with_store(id))?;
            all.extend(vaults.into_iter().map(|vault| (id.clone(), vault)));
        }
        Ok(all)
    }

    /// List a vault's items, with field metadata but not values. Available
    /// regardless of lock state.
    ///
    /// `store: None` resolves `vault` via [`DaemonState::resolve_store`]'s
    /// ambiguity rule (ADR-018) — this is what keeps every
    /// single-store deployment, and every multi-store deployment where
    /// the name happens to be unique, working exactly as before.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::StoreNotFound`]/[`CoreError::NotFound`]/
    /// [`CoreError::AmbiguousVault`] per [`DaemonState::resolve_store`],
    /// or propagates the backend's error otherwise.
    pub fn list_items(
        &self,
        store: Option<&StoreId>,
        vault: &str,
    ) -> std::result::Result<Vec<Item>, CoreError> {
        let id = self.resolve_store(store, vault)?;
        let entry = self.entry(&id)?;
        Resolver::new(entry.backend.as_ref())
            .list_items(vault)
            .map_err(|error| error.with_store(&id))
    }

    /// Validate that a `secret://` reference names an existing store
    /// (implicitly or explicitly), vault, item and field, without
    /// reading the field's value.
    ///
    /// Named `validate_reference`, not `resolve`, on purpose: this is an
    /// existence check only, exposed over D-Bus as `Manager.Resolve` (see
    /// `docs/dbus/secrets-manager.md` — the *wire* method name stays
    /// `Resolve` for compatibility with existing clients; only this
    /// internal Rust name changes). Deliberately distinct from
    /// [`secrets_core::Resolver::resolve`], which *does* return the
    /// value. A backend's own native reference format (e.g. a future
    /// `op://...` internal encoding a 1Password backend might use) never
    /// appears in this method's output or errors — only the `secret://`
    /// form the caller supplied, echoed back canonicalised.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::VaultLocked`] if the resolved store is
    /// locked, or [`CoreError::NotFound`] if the reference does not
    /// resolve — see [`DaemonState::resolve_store`] for the store
    /// resolution errors an unqualified `uri.store()` may also produce.
    pub fn validate_reference(&self, uri: &SecretUri) -> std::result::Result<(), CoreError> {
        let id = self.resolve_store(uri.store(), uri.vault())?;
        let entry = self.entry(&id)?;
        if !entry.lock_controller.is_unlocked() {
            return Err(CoreError::VaultLocked {
                store: Some(id.clone()),
                vault: uri.vault().to_string(),
            });
        }
        Self::check_backend_session(&id, entry)?;
        let items = Resolver::new(entry.backend.as_ref())
            .list_items(uri.vault())
            .map_err(|error| error.with_store(&id))?;
        let exists = items.iter().any(|item| {
            item.path.segments() == uri.item().segments() && item.has_field(uri.field())
        });
        if exists {
            Ok(())
        } else {
            Err(CoreError::NotFound {
                store: Some(id),
                vault: uri.vault().to_string(),
                item: uri.item().to_string(),
                field: uri.field().to_string(),
            })
        }
    }

    /// Fetch a field's value.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::VaultLocked`] if the resolved store is
    /// locked, or propagates the backend's error otherwise — see
    /// [`DaemonState::resolve_store`] for the store resolution errors an
    /// unqualified `uri.store()` may also produce.
    pub fn get(&self, uri: &SecretUri) -> std::result::Result<SecretValue, CoreError> {
        let id = self.resolve_store(uri.store(), uri.vault())?;
        let entry = self.entry(&id)?;
        if !entry.lock_controller.is_unlocked() {
            return Err(CoreError::VaultLocked {
                store: Some(id.clone()),
                vault: uri.vault().to_string(),
            });
        }
        Self::check_backend_session(&id, entry)?;
        Resolver::new(entry.backend.as_ref())
            .resolve(uri)
            .map_err(|error| error.with_store(&id))
    }

    /// Show every field of one item, with secret-shaped fields' values
    /// replaced by [`OBFUSCATED_FIELD_PLACEHOLDER`] — that substitution
    /// happens here, before this ever calls [`DaemonState::read_field`],
    /// so a secret-shaped field's real value is never fetched from the
    /// backend at all, not merely masked after the fact. See ADR-016.
    ///
    /// The lock/session check happens up front, even though
    /// [`DaemonState::list_items`] itself doesn't need it: an item made
    /// entirely of secret-shaped fields would otherwise never call
    /// [`DaemonState::read_field`] (and so never hit *its* gate),
    /// letting a locked store answer with placeholders alone — this
    /// command must fail the same way [`DaemonState::get`] does when
    /// locked, regardless of which fields the item happens to have.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::VaultLocked`] if the resolved store is
    /// locked, [`CoreError::ItemNotFound`] if no item exists at this
    /// path, or propagates the backend's error otherwise — see
    /// [`DaemonState::resolve_store`] for the store resolution errors an
    /// unqualified `uri.store()` may also produce.
    pub fn show_item(&self, uri: &ItemUri) -> std::result::Result<Vec<FieldDisplay>, CoreError> {
        let id = self.resolve_store(uri.store(), uri.vault())?;
        let entry = self.entry(&id)?;
        if !entry.lock_controller.is_unlocked() {
            return Err(CoreError::VaultLocked {
                store: Some(id.clone()),
                vault: uri.vault().to_string(),
            });
        }
        Self::check_backend_session(&id, entry)?;
        let items = Resolver::new(entry.backend.as_ref())
            .list_items(uri.vault())
            .map_err(|error| error.with_store(&id))?;
        let item = items
            .into_iter()
            .find(|item| item.path.segments() == uri.item().segments())
            .ok_or_else(|| CoreError::ItemNotFound {
                store: Some(id.clone()),
                vault: uri.vault().to_string(),
                item: uri.item().to_string(),
            })?;
        item.fields
            .into_iter()
            .map(|field| {
                let value = if field.kind.is_secret() {
                    // Never asks the backend for this field at all — the
                    // placeholder is not a display-time mask over a real
                    // value that was fetched anyway.
                    OBFUSCATED_FIELD_PLACEHOLDER.to_string()
                } else {
                    self.read_field(&id, uri.vault(), &item.path, &field.name)?
                        .expose_secret()
                        .to_string()
                };
                Ok(FieldDisplay {
                    name: field.name,
                    kind: field.kind.to_string(),
                    value,
                })
            })
            .collect()
    }

    /// Whether a read can happen right now against one store: both that
    /// store's own lock ([`LockController::is_unlocked`]) and its own
    /// session ([`check_backend_session`](Self::check_backend_session)),
    /// if it has one. `false` (not an error) if no store with this id is
    /// configured — see [`DaemonState::is_unlocked`]'s doc comment for
    /// why.
    ///
    /// The single answer to "is this store readable", shared by every
    /// surface that needs it (the Secret Service compatibility layer,
    /// the SSH agent) so none of them can drift from `get`/
    /// `validate_reference`'s own gating — see the invariant this
    /// module's own doc comment describes.
    #[must_use]
    pub fn is_accessible(&self, store: &StoreId) -> bool {
        let Some(entry) = self.stores.get(store) else {
            return false;
        };
        entry.lock_controller.is_unlocked() && Self::check_backend_session(store, entry).is_ok()
    }

    /// Fetch one (vault, item, field) triple's value directly from a
    /// specific store, applying the same lock/session gating as
    /// [`DaemonState::get`].
    ///
    /// Used by callers that already have a (store, vault, item, field)
    /// tuple in hand rather than a `secret://` URI — the Secret Service
    /// compatibility layer (one Secret Service `Item` per triple) and the
    /// SSH agent (iterating `SshKey` fields directly, per store).
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::StoreNotFound`] if no store with this id is
    /// configured, [`CoreError::VaultLocked`] if it is locked,
    /// [`CoreError::BackendRequiresAuthentication`] or
    /// [`CoreError::BackendUnavailable`] if the store's own session
    /// blocks it (see [`check_backend_session`](Self::check_backend_session)),
    /// or propagates the backend's error otherwise.
    pub fn read_field(
        &self,
        store: &StoreId,
        vault: &str,
        item: &ItemPath,
        field: &str,
    ) -> std::result::Result<SecretValue, CoreError> {
        let entry = self.entry(store)?;
        if !entry.lock_controller.is_unlocked() {
            return Err(CoreError::VaultLocked {
                store: Some(store.clone()),
                vault: vault.to_string(),
            });
        }
        Self::check_backend_session(store, entry)?;
        entry
            .backend
            .get_field(vault, item, field)
            .map_err(|error| error.with_store(store))
    }
}

/// Join store ids for a human-readable list, e.g. in a
/// `StoreSelectionRequired` message.
fn join_store_ids<'a>(ids: impl IntoIterator<Item = &'a StoreId>) -> String {
    ids.into_iter()
        .map(StoreId::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// One `(StoreId, BackendKind)` pair's construction — run once per
/// configured store by [`open_registry`].
///
/// # Errors
///
/// Returns [`DaemonError`] if the local vault file's path cannot be
/// resolved or it cannot be parsed, or if the configured backend fails
/// to start (e.g. 1Password Desktop's native library cannot be loaded).
fn build_store_entry(id: &StoreId, kind: crate::config::BackendKind) -> Result<StoreEntry> {
    match kind {
        crate::config::BackendKind::Local => {
            let path = crate::paths::vault_file(id)?;
            let local = Arc::new(LocalBackend::open(path)?);
            let backend: Arc<dyn Backend> = local.clone();
            let lock_controller: Arc<dyn LockController> = local;
            // The local backend has no session concept of its own — its
            // "unlock" already is this store's lock, so there is
            // nothing for `check_backend_session` to consult here.
            Ok(StoreEntry {
                backend,
                lock_controller,
                has_real_lock: true,
                session: None,
            })
        }
        crate::config::BackendKind::Pass {
            store_dir,
            secret_key_path,
            vault,
        } => {
            let store_dir = match store_dir {
                Some(store_dir) => store_dir,
                None => crate::paths::default_pass_store_dir()?,
            };
            let pass = Arc::new(crate::backend::pass::PassBackend::open(
                store_dir,
                &secret_key_path,
                vault,
            )?);
            let backend: Arc<dyn Backend> = pass.clone();
            let lock_controller: Arc<dyn LockController> = pass;
            // A real, passphrase-backed lock — the configured secret
            // key's passphrase, cached until `lock()`/drop (ADR-019),
            // mirroring `LocalBackend`'s own precedent for a backend
            // whose "unlock" is a real daemon-owned secret, not an
            // external session (contrast the 1Password arm below).
            Ok(StoreEntry {
                backend,
                lock_controller,
                has_real_lock: true,
                session: None,
            })
        }
        crate::config::BackendKind::OnePassword { account_name } => {
            let one_password = Arc::new(
                crate::backend::onepassword::OnePasswordBackend::open(account_name).map_err(
                    |error| DaemonError::BackendUnavailable(format!("store '{id}': {error}")),
                )?,
            );
            let backend: Arc<dyn Backend> = one_password.clone();
            let session: Arc<dyn BackendSession> = one_password;
            // 1Password Desktop has no daemon-wide passphrase lock of its
            // own — its own approval/session flow (`BackendSession`,
            // ADR-0011) does the real gating instead. See
            // `LockController`/`AlwaysUnlocked`'s own doc comments.
            Ok(StoreEntry {
                backend,
                lock_controller: Arc::new(AlwaysUnlocked),
                has_real_lock: false,
                session: Some(session),
            })
        }
    }
}

/// The store id an empty/absent config implicitly yields (ADR-018) —
/// zero-config behavior is unaffected by multi-store support.
const IMPLICIT_STORE_ID: &str = "default";

/// Open every configured store (see [`crate::config::Config`]) and wrap
/// them as shared daemon state (ADR-018). An empty configuration (no
/// file, or a file with no `[store.*]` table at all) yields exactly one
/// implicit store, id `"default"`, type local — today's zero-config
/// behavior, unaffected by multi-store support.
///
/// # Errors
///
/// Returns [`DaemonError`] if the config file exists but cannot be
/// parsed, if some `[store.<id>] type = "1password"` is missing a
/// required field, or if [`build_store_entry`] fails for any configured
/// store.
pub fn open_registry() -> Result<DaemonState> {
    let mut store_configs = crate::config::Config::load()?.stores;
    if store_configs.is_empty() {
        store_configs.insert(
            StoreId::new(IMPLICIT_STORE_ID).expect("literal \"default\" is always a valid id"),
            crate::config::BackendKind::Local,
        );
    }
    let mut stores = BTreeMap::new();
    for (id, kind) in store_configs {
        let entry = build_store_entry(&id, kind)?;
        stores.insert(id, entry);
    }
    Ok(DaemonState::new(stores))
}

#[cfg(test)]
mod tests {
    use crate::test_support::{
        default_store_id, state_over_fresh_vault,
        state_over_two_local_stores_with_a_colliding_vault, state_with_backend_session,
    };

    use super::*;

    #[test]
    fn always_unlocked_reports_unlocked_and_ignores_lock_unlock_calls() {
        // Confirms the documented contract directly: AlwaysUnlocked is a
        // deliberate no-op, not a bug waiting to be noticed.
        let controller = AlwaysUnlocked;
        assert!(controller.is_unlocked());
        controller.unlock("anything").unwrap();
        assert!(controller.is_unlocked());
        controller.lock();
        assert!(controller.is_unlocked());
    }

    #[test]
    fn a_fresh_state_reports_locked_before_unlocking() {
        let (_dir, state) = state_over_fresh_vault();
        let id = default_store_id();
        assert_eq!(
            state.status(&id).unwrap(),
            secrets_core::dbus::STATUS_LOCKED
        );
        assert!(!state.is_unlocked(&id));
    }

    #[test]
    fn unlocking_through_daemon_state_reaches_the_backend_trait_object() {
        let (_dir, state) = state_over_fresh_vault();
        let id = default_store_id();
        state.unlock(&id, "test passphrase").unwrap();
        assert_eq!(
            state.status(&id).unwrap(),
            secrets_core::dbus::STATUS_UNLOCKED
        );

        // Exercises the `Arc<dyn Backend>` path end to end, not just the
        // concrete `LocalBackend` (already covered by
        // `backend::local::tests`).
        let vaults = state.list_vaults(&id).unwrap();
        assert!(vaults.iter().any(|v| v.name == "Personal"));

        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        let value = state.get(&uri).unwrap();
        assert_eq!(value.expose_secret(), "correct horse battery staple");
    }

    #[test]
    fn validate_reference_confirms_existence_without_returning_the_value() {
        let (_dir, state) = state_over_fresh_vault();
        state
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();

        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        // Succeeds but its `Ok` carries no value to expose — unlike `get`.
        state.validate_reference(&uri).unwrap();

        let missing = SecretUri::parse("secret://Personal/GitHub/does-not-exist").unwrap();
        let error = state.validate_reference(&missing).unwrap_err();
        assert!(matches!(error, CoreError::NotFound { .. }));
    }

    #[test]
    fn locked_state_rejects_get_through_the_backend_trait_object() {
        let (_dir, state) = state_over_fresh_vault();
        // Never unlocked: the demo vault does not exist on disk yet either.
        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        let error = state.get(&uri).unwrap_err();
        assert!(matches!(error, CoreError::VaultLocked { .. }));
    }

    #[test]
    fn a_backend_requiring_authentication_blocks_get_even_when_the_store_is_unlocked() {
        // The store's own lock and its own session are different
        // questions (ADR-0011): being unlocked must not be enough on its
        // own when the store also has an unmet session requirement.
        let (_dir, state) = state_with_backend_session(BackendStatus::RequiresAuthentication);
        let id = default_store_id();
        state.unlock(&id, "test passphrase").unwrap();
        assert!(state.is_unlocked(&id));

        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        let error = state.get(&uri).unwrap_err();
        assert!(matches!(error, CoreError::BackendRequiresAuthentication(_)));
    }

    #[test]
    fn an_expired_backend_session_blocks_resolve_with_a_distinct_error_from_vault_locked() {
        let (_dir, state) = state_with_backend_session(BackendStatus::SessionExpired);
        state
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();

        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        let error = state.validate_reference(&uri).unwrap_err();
        assert!(matches!(error, CoreError::BackendRequiresAuthentication(_)));
    }

    #[test]
    fn an_unavailable_backend_blocks_get_with_backend_unavailable() {
        let (_dir, state) = state_with_backend_session(BackendStatus::Unavailable);
        state
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();

        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        let error = state.get(&uri).unwrap_err();
        assert!(matches!(error, CoreError::BackendUnavailable(_)));
    }

    #[test]
    fn an_authenticated_backend_session_does_not_block_get() {
        let (_dir, state) = state_with_backend_session(BackendStatus::Authenticated);
        state
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();

        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        let value = state.get(&uri).unwrap();
        assert_eq!(value.expose_secret(), "correct horse battery staple");
    }

    #[test]
    fn no_backend_session_at_all_behaves_exactly_as_before_step_2() {
        // Regression guard for the local backend: `session` is `None`, so
        // `check_backend_session` must be a no-op, never blocking a
        // request the store's own lock alone already allows.
        let (_dir, state) = state_over_fresh_vault();
        state
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();

        let uri = SecretUri::parse("secret://Personal/GitHub/password").unwrap();
        assert!(state.get(&uri).is_ok());
        assert!(state.validate_reference(&uri).is_ok());
    }

    #[test]
    fn is_accessible_reflects_both_the_store_lock_and_its_backend_session() {
        // Regression guard for #7: `is_accessible` is what the Secret
        // Service layer and the SSH agent now consult instead of the
        // store's lock alone — it must answer "no" for every reason a
        // read could fail, not just a locked store.
        let (_dir, locked) = state_over_fresh_vault();
        assert!(
            !locked.is_accessible(&default_store_id()),
            "a fresh, never-unlocked store"
        );

        let (_dir, unlocked) = state_over_fresh_vault();
        unlocked
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();
        assert!(
            unlocked.is_accessible(&default_store_id()),
            "unlocked, no backend session"
        );

        let (_dir, needs_auth) = state_with_backend_session(BackendStatus::RequiresAuthentication);
        needs_auth
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();
        assert!(
            !needs_auth.is_accessible(&default_store_id()),
            "store unlocked but backend session requires authentication"
        );

        let (_dir, authenticated) = state_with_backend_session(BackendStatus::Authenticated);
        authenticated
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();
        assert!(authenticated.is_accessible(&default_store_id()));
    }

    #[test]
    fn is_accessible_is_false_for_an_unconfigured_store() {
        let (_dir, state) = state_over_fresh_vault();
        assert!(!state.is_accessible(&StoreId::new("ghost").unwrap()));
    }

    #[test]
    fn show_item_obfuscates_secret_fields_and_reveals_safe_ones() {
        let (_dir, state) = state_over_fresh_vault();
        state
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();

        let uri = ItemUri::parse("secret://Personal/GitHub").unwrap();
        let fields = state.show_item(&uri).unwrap();

        let by_name = |name: &str| fields.iter().find(|f| f.name == name).unwrap();
        assert_eq!(by_name("username").value, "octocat");
        assert_eq!(by_name("password").value, OBFUSCATED_FIELD_PLACEHOLDER);
        assert_eq!(by_name("totp").value, OBFUSCATED_FIELD_PLACEHOLDER);

        // The actual invariant this feature exists for: not just equal to
        // the placeholder, but the real secret values never appear
        // anywhere in the response at all.
        for field in &fields {
            assert_ne!(field.value, "correct horse battery staple");
            assert_ne!(field.value, "JBSWY3DPEHPK3PXP");
        }
    }

    #[test]
    fn show_item_requires_unlock() {
        let (_dir, state) = state_over_fresh_vault();
        let uri = ItemUri::parse("secret://Personal/GitHub").unwrap();
        let error = state.show_item(&uri).unwrap_err();
        assert!(matches!(error, CoreError::VaultLocked { .. }));
    }

    #[test]
    fn show_item_reports_item_not_found_for_an_unknown_item() {
        let (_dir, state) = state_over_fresh_vault();
        state
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();

        let uri = ItemUri::parse("secret://Personal/does-not-exist").unwrap();
        let error = state.show_item(&uri).unwrap_err();
        assert!(matches!(error, CoreError::ItemNotFound { .. }));
    }

    #[test]
    fn read_field_applies_the_same_gating_as_get() {
        let item = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
        let id = default_store_id();

        let (_dir, locked) = state_over_fresh_vault();
        let error = locked
            .read_field(&id, "Personal", &item, "password")
            .unwrap_err();
        assert!(matches!(error, CoreError::VaultLocked { .. }));

        let (_dir, needs_auth) = state_with_backend_session(BackendStatus::RequiresAuthentication);
        needs_auth.unlock(&id, "test passphrase").unwrap();
        let error = needs_auth
            .read_field(&id, "Personal", &item, "password")
            .unwrap_err();
        assert!(matches!(error, CoreError::BackendRequiresAuthentication(_)));

        let (_dir, unlocked) = state_over_fresh_vault();
        unlocked.unlock(&id, "test passphrase").unwrap();
        let value = unlocked
            .read_field(&id, "Personal", &item, "password")
            .unwrap();
        assert_eq!(value.expose_secret(), "correct horse battery staple");
    }

    #[test]
    fn read_field_reports_store_not_found_for_an_unconfigured_store() {
        let (_dir, state) = state_over_fresh_vault();
        let item = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
        let error = state
            .read_field(
                &StoreId::new("ghost").unwrap(),
                "Personal",
                &item,
                "password",
            )
            .unwrap_err();
        assert!(matches!(error, CoreError::StoreNotFound { .. }));
    }

    #[test]
    fn an_unqualified_vault_present_in_two_stores_is_ambiguous() {
        let (_dirs, state, store_a, store_b) = state_over_two_local_stores_with_a_colliding_vault();
        state.unlock(&store_a, "a passphrase").unwrap();
        state.unlock(&store_b, "b passphrase").unwrap();

        let uri = SecretUri::parse("secret://Shared/Item/password").unwrap();
        let error = state.get(&uri).unwrap_err();
        match error {
            CoreError::AmbiguousVault { vault, candidates } => {
                assert_eq!(vault, "Shared");
                assert_eq!(candidates.len(), 2);
                assert!(candidates.contains(&store_a));
                assert!(candidates.contains(&store_b));
            }
            other => panic!("expected AmbiguousVault, got {other:?}"),
        }
    }

    #[test]
    fn a_store_qualified_vault_resolves_to_exactly_that_store_even_when_ambiguous_unqualified() {
        let (_dirs, state, store_a, store_b) = state_over_two_local_stores_with_a_colliding_vault();
        state.unlock(&store_a, "a passphrase").unwrap();
        state.unlock(&store_b, "b passphrase").unwrap();

        let uri = SecretUri::parse(&format!("secret://{store_a}@Shared/Item/password")).unwrap();
        let value = state.get(&uri).unwrap();
        assert_eq!(value.expose_secret(), "a-value");

        let uri = SecretUri::parse(&format!("secret://{store_b}@Shared/Item/password")).unwrap();
        let value = state.get(&uri).unwrap();
        assert_eq!(value.expose_secret(), "b-value");
    }

    #[test]
    fn an_unqualified_vault_unique_to_one_store_still_resolves_without_qualification() {
        let (_dirs, state, store_a, _store_b) =
            state_over_two_local_stores_with_a_colliding_vault();
        state.unlock(&store_a, "a passphrase").unwrap();

        // "OnlyInA" only exists in store_a's vault file (see the fixture's
        // own doc comment) — the core backward-compatibility guarantee:
        // an unqualified name that happens to be unique still just works.
        let uri = SecretUri::parse("secret://OnlyInA/Item/password").unwrap();
        let value = state.get(&uri).unwrap();
        assert_eq!(value.expose_secret(), "only-in-a-value");
    }

    #[test]
    fn locking_one_store_does_not_affect_another() {
        let (_dirs, state, store_a, store_b) = state_over_two_local_stores_with_a_colliding_vault();
        state.unlock(&store_a, "a passphrase").unwrap();
        state.unlock(&store_b, "b passphrase").unwrap();

        state.lock(&store_a).unwrap();

        assert!(!state.is_unlocked(&store_a));
        assert!(state.is_unlocked(&store_b));
    }

    #[test]
    fn unlock_default_succeeds_directly_with_exactly_one_real_lock_controller() {
        let (_dir, state) = state_over_fresh_vault();
        state.unlock_default("test passphrase").unwrap();
        assert!(state.is_unlocked(&default_store_id()));
    }

    #[test]
    fn unlock_default_fails_with_store_selection_required_when_two_real_locks_exist() {
        let (_dirs, state, _store_a, _store_b) =
            state_over_two_local_stores_with_a_colliding_vault();
        let error = state.unlock_default("either passphrase").unwrap_err();
        assert!(matches!(error, DaemonError::StoreSelectionRequired(_)));
    }

    #[test]
    fn unlock_default_is_a_no_op_with_zero_real_lock_controllers() {
        let (_dir, state) = state_with_backend_session(BackendStatus::Available);
        // This fixture's only store is `AlwaysUnlocked` — nothing to
        // apply a passphrase to, so this must succeed trivially.
        state.unlock_default("unused").unwrap();
    }

    #[test]
    fn lock_all_locks_every_store_unconditionally_including_always_unlocked_ones() {
        let (_dirs, state, store_a, store_b) = state_over_two_local_stores_with_a_colliding_vault();
        state.unlock(&store_a, "a passphrase").unwrap();
        state.unlock(&store_b, "b passphrase").unwrap();

        state.lock_all();

        assert!(!state.is_unlocked(&store_a));
        assert!(!state.is_unlocked(&store_b));
    }

    #[test]
    fn status_summary_is_unlocked_only_when_every_real_lock_controller_is_unlocked() {
        let (_dirs, state, store_a, store_b) = state_over_two_local_stores_with_a_colliding_vault();
        assert_eq!(state.status_summary(), secrets_core::dbus::STATUS_LOCKED);

        state.unlock(&store_a, "a passphrase").unwrap();
        assert_eq!(
            state.status_summary(),
            secrets_core::dbus::STATUS_LOCKED,
            "one of two real locks is still locked"
        );

        state.unlock(&store_b, "b passphrase").unwrap();
        assert_eq!(state.status_summary(), secrets_core::dbus::STATUS_UNLOCKED);
    }
}
