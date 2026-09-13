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

use secrets_core::ItemPath;
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

/// The object path for a vault's `Collection`.
#[must_use]
pub fn collection_path(vault: &str) -> OwnedObjectPath {
    format!("{SERVICE_PATH}/collection/{}", slug(vault))
        .try_into()
        .expect("slug() always produces a valid object path segment")
}

/// The object path for one (vault, item, field) triple's `Item`.
#[must_use]
pub fn item_path(vault: &str, item: &ItemPath, field: &str) -> OwnedObjectPath {
    let mut segments: Vec<String> = item.segments().iter().map(|s| slug(s)).collect();
    segments.push(slug(field));
    format!("{}/{}", collection_path(vault), segments.join("_"))
        .try_into()
        .expect("slug() always produces a valid object path segment")
}

/// One (vault, item, field) triple, and the object path it is currently
/// registered at. Part of a [`Topology`] snapshot — the D-Bus object this
/// describes can be added or removed by [`refresh::reconcile`] as the
/// backend's own contents change, so this is a point-in-time fact, not a
/// permanent one.
#[derive(Debug, Clone)]
pub struct KnownItem {
    /// The vault this field belongs to.
    pub vault: String,
    /// The item path this field belongs to.
    pub item: ItemPath,
    /// The field's name.
    pub field: String,
    /// The `Item` object path this triple was registered at.
    pub path: OwnedObjectPath,
}

/// A snapshot of every vault and (vault, item, field) triple the backend
/// reported the last time it was scanned — see [`LiveTopology`] for the
/// shared, mutable handle every Secret Service interface object actually
/// reads from.
#[derive(Debug, Clone, Default)]
pub struct Topology {
    /// Every vault name, as of the last scan.
    pub vaults: Vec<String>,
    /// Every (vault, item, field) triple, as of the last scan.
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

/// Discover the current topology by walking every vault and item the
/// backend reports. Available regardless of lock state (see
/// [`crate::state::DaemonState::list_vaults`]).
///
/// # Errors
///
/// Propagates a backend error, if any.
pub fn discover(state: &crate::state::DaemonState) -> secrets_core::Result<Topology> {
    let mut topology = Topology::default();
    for vault in state.list_vaults()? {
        topology.vaults.push(vault.name.clone());
        for item in state.list_items(&vault.name)? {
            for field in &item.fields {
                topology.items.push(KnownItem {
                    vault: vault.name.clone(),
                    item: item.path.clone(),
                    field: field.name.clone(),
                    path: item_path(&vault.name, &item.path, &field.name),
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
