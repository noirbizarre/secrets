//! The standard [freedesktop Secret
//! Service](https://specifications.freedesktop.org/secret-service/latest/)
//! interfaces — the primary, interoperable contract `secretsd` exposes, so
//! existing clients (`secret-tool`, `libsecret` consumers, browsers'
//! native password managers) work against it unmodified. `org.secrets.*`
//! (`crate::manager`) is the extension namespace layered on top, for
//! `secret://`-shaped operations this standard has no way to express — see
//! [ADR-013](../../../../docs/adr/013-standard-secret-service-and-extension-namespace.md).
//!
//! See `docs/dbus/secret-service.md` for the full scope. The object
//! topology (which collections and items exist) is *live*, not fixed at
//! startup (see [ADR-015](../../../../docs/adr/015-live-secret-service-topology.md)):
//! [`refresh`] runs a background scan on a fixed interval, plus
//! reactively whenever `org.secrets.Manager`'s `Unlock`/`Lock` is called,
//! reconciling the registered `Collection`/`Item` objects and emitting the
//! standard `CollectionCreated`/`CollectionDeleted`/`ItemCreated`/
//! `ItemDeleted` signals. A backend error during any one scan never
//! crashes the daemon or blocks startup — it just leaves the topology
//! unchanged until the next scan succeeds.
//!
//! Read-only for now: `CreateCollection`/`CreateItem`/`SetSecret`/
//! `Delete`/`SetAlias` all return `NotSupported` — tracked as follow-up
//! work, not silently missing (see `PLAN.md` and the linked issue).
//!
//! Two more deliberate simplifications, both because the "plain" algorithm
//! carries no per-session cryptographic state to keep distinct:
//! - One shared [`session::SessionIface`] object answers every
//!   `OpenSession`, rather than minting one per call.
//! - One shared [`prompt::PromptIface`] object answers every operation that
//!   would need a real interactive prompt (`CreateCollection`, an `Unlock`
//!   of an object that is actually locked), and immediately reports itself
//!   dismissed — there is no GUI agent in the MVP to prompt with. See
//!   ADR-0004.

pub mod collection;
pub mod item;
pub mod prompt;
pub mod refresh;
pub mod service;
pub mod session;

use std::sync::{Arc, Mutex};

use secrets_core::{ItemPath, StoreId};
use zbus::zvariant::OwnedObjectPath;

/// The root `org.freedesktop.Secret.Service` object path.
pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";

/// The well-known bus name every standard Secret Service client (
/// `secret-tool`, `libsecret`'s `SECRET_SERVICE_BUS_NAME`, GNOME
/// Keyring/KWallet-compatible consumers) addresses directly, distinct
/// from `secrets_core::dbus::SERVICE_NAME` (`org.secrets.Daemon`, which
/// `secretsd` always owns).
///
/// Requested **best-effort**, after startup, not through
/// `zbus::blocking::connection::Builder::name` — a desktop session may
/// already run another Secret Service provider (GNOME Keyring, KWallet's
/// `ksecretsd`) that owns this name first, and `secretsd` must keep
/// serving `org.secrets.Daemon` and every object path regardless. See
/// `main.rs` for the request and its fallback logging, and
/// [ADR-013](../../../../docs/adr/013-standard-secret-service-and-extension-namespace.md).
pub const BUS_NAME: &str = "org.freedesktop.secrets";

/// The one shared, always-dismissed prompt object's path.
pub const PROMPT_PATH: &str = "/org/freedesktop/secrets/prompt/unsupported";

/// The one shared "plain"-algorithm session object's path.
pub const SESSION_PATH: &str = "/org/freedesktop/secrets/session/shared";

/// The literal well-known object path for the `"default"` alias's
/// collection, in addition to its real `collection_path()` — see the
/// specification's "Aliases" and "Object Paths" chapters. A client that
/// hardcodes this path (rather than calling `ReadAlias("default")`) still
/// reaches the same collection.
pub const ALIAS_DEFAULT_PATH: &str = "/org/freedesktop/secrets/aliases/default";

/// Turn an arbitrary name into a D-Bus object path segment: ASCII
/// alphanumerics and underscore only, lowercased, never empty.
///
/// Lossy by design — this only needs to be a *stable*, *valid* path
/// segment, not a reversible encoding; the vault/item/field's real name
/// lives in the object's `Label`/`Attributes`, not in its path.
pub fn slug(input: &str) -> String {
    let mut out: String = input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() {
        out.push('_');
    }
    out
}

/// The object path for a vault's `Collection`, nested under its store
/// (ADR-018): `/collection/<store_slug>/<vault_slug>`, real path segments
/// rather than a concatenated single one, so two stores can never collide
/// at the same path even if they happen to share a vault name — string
/// concatenation (`slug(store) + slug(vault)`) could not make that
/// guarantee (`"ab"`+`"c"` and `"a"`+`"bc"` collide; distinct path
/// segments cannot). Reshapes today's single-store path too — Secret
/// Service object paths are already documented (ADR-013/015) as
/// dynamically discovered, never persisted, by well-behaved clients.
#[must_use]
pub fn collection_path(store: &StoreId, vault: &str) -> OwnedObjectPath {
    format!(
        "{SERVICE_PATH}/collection/{}/{}",
        slug(store.as_str()),
        slug(vault)
    )
    .try_into()
    .expect("slug() always produces a valid object path segment")
}

/// The object path for one (store, vault, item, field) triple's `Item`.
#[must_use]
pub fn item_path(store: &StoreId, vault: &str, item: &ItemPath, field: &str) -> OwnedObjectPath {
    let mut segments: Vec<String> = item.segments().iter().map(|s| slug(s)).collect();
    segments.push(slug(field));
    format!("{}/{}", collection_path(store, vault), segments.join("_"))
        .try_into()
        .expect("slug() always produces a valid object path segment")
}

/// One (store, vault, item, field) quadruple, and the object path it is
/// currently registered at. Part of a [`Topology`] snapshot — the D-Bus
/// object this describes can be added or removed by
/// [`refresh::reconcile`] as a store's own contents change, so this is a
/// point-in-time fact, not a permanent one.
#[derive(Debug, Clone)]
pub struct KnownItem {
    /// The store this field's vault lives in (ADR-018).
    pub store: StoreId,
    /// The vault this field belongs to.
    pub vault: String,
    /// The item path this field belongs to.
    pub item: ItemPath,
    /// The field's name.
    pub field: String,
    /// The `Item` object path this triple was registered at.
    pub path: OwnedObjectPath,
}

/// A snapshot of every (store, vault) pair and (store, vault, item, field)
/// quadruple every configured store reported the last time it was
/// scanned — see [`LiveTopology`] for the shared, mutable handle every
/// Secret Service interface object actually reads from.
#[derive(Debug, Clone, Default)]
pub struct Topology {
    /// Every `(store, vault name)` pair, as of the last scan — sorted by
    /// `(StoreId, vault name)` explicitly in [`discover`], not left to
    /// whatever order stores/backends happen to report: this ordering is
    /// what defines "the first vault" for the `"default"` alias
    /// (ADR-018 redefines ADR-013's "the first vault", singular, to "the
    /// first `(store, vault)` pair" over this same deterministic order).
    pub vaults: Vec<(StoreId, String)>,
    /// Every (store, vault, item, field) quadruple, as of the last scan.
    pub items: Vec<KnownItem>,
}

/// A [`Topology`] shared between every Secret Service interface object
/// (`ServiceIface`, every `CollectionIface`) and the background refresher
/// that keeps it current ([`refresh::spawn`]) — see
/// [ADR-015](../../../../docs/adr/015-live-secret-service-topology.md).
/// Replaces each interface holding its own frozen, construction-time
/// snapshot. Cloning is cheap (an `Arc` clone); every clone observes the
/// same underlying topology.
#[derive(Clone)]
pub struct LiveTopology(Arc<Mutex<Topology>>);

impl LiveTopology {
    /// Wrap an initial topology as shared, mutable state.
    #[must_use]
    pub fn new(initial: Topology) -> Self {
        Self(Arc::new(Mutex::new(initial)))
    }

    /// A cloned snapshot of the topology as it stands right now — safe to
    /// read from without holding the lock for the rest of a D-Bus method
    /// call (which may itself take a while, e.g. decrypting a field).
    #[must_use]
    pub fn snapshot(&self) -> Topology {
        self.0.lock().expect("poisoned").clone()
    }

    /// Replace the topology wholesale. Called only by
    /// [`refresh::reconcile`], after the D-Bus object set has already been
    /// updated to match — never by a Secret Service interface method
    /// itself, which only ever reads via [`snapshot`](Self::snapshot).
    pub(crate) fn replace(&self, new: Topology) {
        *self.0.lock().expect("poisoned") = new;
    }
}

/// Discover the current topology by walking every vault and item every
/// configured store reports (ADR-018). Available regardless of lock state
/// (see [`crate::state::DaemonState::list_all_vaults`]).
///
/// # Errors
///
/// Propagates the first store's backend error, if any — matching
/// [`crate::state::DaemonState::list_all_vaults`]'s own "fail the whole
/// scan" behavior; [`refresh::reconcile`]'s caller already treats a
/// failed scan as "keep the previous topology", never fatal (ADR-015).
pub fn discover(state: &crate::state::DaemonState) -> secrets_core::Result<Topology> {
    let mut topology = Topology::default();
    let mut all_vaults = state.list_all_vaults()?;
    // Deterministic order, independent of any backend's own iteration
    // order — this is what "the first vault" (the `"default"` alias,
    // ADR-013/ADR-018) actually means.
    all_vaults.sort_by(|(store_a, vault_a), (store_b, vault_b)| {
        (store_a, &vault_a.name).cmp(&(store_b, &vault_b.name))
    });
    for (store, vault) in all_vaults {
        topology.vaults.push((store.clone(), vault.name.clone()));
        for item in state.list_items(Some(&store), &vault.name)? {
            for field in &item.fields {
                topology.items.push(KnownItem {
                    store: store.clone(),
                    vault: vault.name.clone(),
                    item: item.path.clone(),
                    field: field.name.clone(),
                    path: item_path(&store, &vault.name, &item.path, &field.name),
                });
            }
        }
    }
    Ok(topology)
}

/// The `Secret` struct from the Secret Service spec: a value plus which
/// session it was negotiated under.
///
/// `parameters` is always empty and `content_type` always `"text/plain"` —
/// both exist in the spec for the encrypted algorithm's IV and for
/// non-text secrets, neither of which the MVP's "plain"-only, string-typed
/// fields need.
#[derive(Debug, zbus::zvariant::Type, serde::Serialize, serde::Deserialize)]
pub struct Secret {
    /// The session this secret was retrieved under.
    pub session: OwnedObjectPath,
    /// Algorithm-specific parameters (unused by "plain").
    pub parameters: Vec<u8>,
    /// The secret's value, as bytes.
    pub value: Vec<u8>,
    /// The value's MIME type.
    pub content_type: String,
}
