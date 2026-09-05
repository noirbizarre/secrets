//! `org.freedesktop.Secret.*` compatibility: a read-only view of the same
//! vaults/items/fields the native `org.secrets.Manager` API exposes, shaped
//! to satisfy existing Secret Service clients (`secret-tool`, `libsecret`
//! consumers, browsers' native password managers).
//!
//! This is a compatibility API, not the primary one — see
//! `docs/dbus/secret-service.md` for the full scope and its limitations,
//! the most important being: **the object topology (which collections and
//! items exist) is fixed at daemon startup.** If the vault file is created
//! for the first time by `secrets unlock` while `secretsd` is already
//! running, restart the daemon to pick up the new collections. The native
//! `org.secrets.Manager` API (what `secrets-cli` uses) has no such
//! limitation, since it reads live state on every call.
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
pub mod service;
pub mod session;

use secrets_core::ItemPath;
use zbus::zvariant::OwnedObjectPath;

/// The root `org.freedesktop.Secret.Service` object path.
pub const SERVICE_PATH: &str = "/org/freedesktop/secrets";

/// The one shared, always-dismissed prompt object's path.
pub const PROMPT_PATH: &str = "/org/freedesktop/secrets/prompt/unsupported";

/// The one shared "plain"-algorithm session object's path.
pub const SESSION_PATH: &str = "/org/freedesktop/secrets/session/shared";

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

/// One (vault, item, field) triple, and the fixed object path it was
/// registered at — computed once at startup, since the object topology
/// cannot change without a restart (see the module-level limitation note).
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

/// A snapshot of every vault and (vault, item, field) triple that exists
/// at daemon startup — the full set of objects registered on the bus.
#[derive(Debug, Clone, Default)]
pub struct Topology {
    /// Every vault name, at startup.
    pub vaults: Vec<String>,
    /// Every (vault, item, field) triple, at startup.
    pub items: Vec<KnownItem>,
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
