//! Client-side proxies for the standard Secret Service D-Bus interfaces.
//!
//! `secretsd::secret_service` only defines the *server*-side
//! `#[zbus::interface]` implementations — nothing in the workspace
//! generates a client proxy for them (unlike `org.secrets.Manager`, which
//! `secrets_core::dbus` defines once for both ends). These traits are
//! this test harness's only copy, so a signature drift between them and
//! `secretsd::secret_service::*` would surface as a `zbus::Error` at call
//! time (wrong argument/return shape), not silently — the standard
//! interfaces' shapes are also fixed by the spec, not free to drift on
//! either end.
//!
//! `gen_async = false` throughout: the harness is deliberately blocking
//! (matching `secretsd` itself, see `main.rs`'s own doc comment), so there
//! is no call site that would ever construct the async variant these
//! macros can also generate.

use std::collections::HashMap;

use secretsd::secret_service::Secret;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

/// `org.freedesktop.Secret.Service`, at its well-known object path.
#[zbus::proxy(
    interface = "org.freedesktop.Secret.Service",
    default_service = "org.secrets.Daemon",
    default_path = "/org/freedesktop/secrets",
    gen_async = false
)]
pub trait SecretService {
    /// Every known vault, as its `Collection` object path.
    #[zbus(property)]
    fn collections(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Negotiate a session. `secretsd` only accepts `"plain"`.
    fn open_session(
        &self,
        algorithm: &str,
        input: &Value<'_>,
    ) -> zbus::Result<(OwnedValue, OwnedObjectPath)>;

    /// Always rejected in this MVP (`NotSupported`).
    fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: &str,
    ) -> zbus::Result<(OwnedObjectPath, OwnedObjectPath)>;

    /// Search every known item by attribute, split into (unlocked, locked).
    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> zbus::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)>;

    /// Reflects current lock state; cannot itself unlock (see
    /// `docs/dbus/secret-service.md`).
    fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> zbus::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)>;

    /// Locks the whole daemon, regardless of which objects are named.
    fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> zbus::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)>;

    /// Batch-fetch secrets for several items at once.
    fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
    ) -> zbus::Result<HashMap<OwnedObjectPath, Secret>>;

    /// Resolve the `"default"` alias to a collection path.
    fn read_alias(&self, name: &str) -> zbus::Result<OwnedObjectPath>;

    /// Always rejected in this MVP (`NotSupported`).
    fn set_alias(&self, name: &str, collection: OwnedObjectPath) -> zbus::Result<()>;

    /// Signalled by `secret_service::refresh::reconcile` when a new vault
    /// is registered — see ADR-015.
    #[zbus(signal)]
    fn collection_created(&self, collection: OwnedObjectPath) -> zbus::Result<()>;

    /// Signalled when a vault is unregistered — see ADR-015.
    #[zbus(signal)]
    fn collection_deleted(&self, collection: OwnedObjectPath) -> zbus::Result<()>;
}

/// `org.freedesktop.Secret.Collection`, one per vault — constructed with an
/// explicit `path()` per call site, since the object path varies per
/// vault.
#[zbus::proxy(
    interface = "org.freedesktop.Secret.Collection",
    default_service = "org.secrets.Daemon",
    gen_async = false
)]
pub trait Collection {
    /// This vault's items, as `Item` object paths.
    #[zbus(property)]
    fn items(&self) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// The vault's name.
    #[zbus(property)]
    fn label(&self) -> zbus::Result<String>;

    /// Whether the daemon (and so every vault) is currently locked.
    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;

    /// Search this vault's items by attribute.
    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> zbus::Result<Vec<OwnedObjectPath>>;

    /// Always rejected in this MVP (`NotSupported`).
    fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: Secret,
        replace: bool,
    ) -> zbus::Result<(OwnedObjectPath, OwnedObjectPath)>;

    /// Always rejected in this MVP (`NotSupported`).
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;

    /// Signalled by `secret_service::refresh::reconcile` when a new field
    /// is registered in this vault — see ADR-015.
    #[zbus(signal)]
    fn item_created(&self, item: OwnedObjectPath) -> zbus::Result<()>;

    /// Signalled when a field is unregistered from this vault — see
    /// ADR-015.
    #[zbus(signal)]
    fn item_deleted(&self, item: OwnedObjectPath) -> zbus::Result<()>;
}

/// `org.freedesktop.Secret.Item`, one per (vault, item, field) triple —
/// constructed with an explicit `path()` per call site.
#[zbus::proxy(
    interface = "org.freedesktop.Secret.Item",
    default_service = "org.secrets.Daemon",
    gen_async = false
)]
pub trait Item {
    /// Whether the daemon is currently locked.
    #[zbus(property)]
    fn locked(&self) -> zbus::Result<bool>;

    /// The synthetic `{vault, item, field}` attribute map.
    #[zbus(property)]
    fn attributes(&self) -> zbus::Result<HashMap<String, String>>;

    /// `"<item> (<field>)"`.
    #[zbus(property)]
    fn label(&self) -> zbus::Result<String>;

    /// Fetch this field's value. Fails while locked.
    fn get_secret(&self, session: OwnedObjectPath) -> zbus::Result<Secret>;

    /// Always rejected in this MVP (`NotSupported`).
    fn set_secret(&self, secret: Secret) -> zbus::Result<()>;

    /// Always rejected in this MVP (`NotSupported`).
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;
}

/// `org.freedesktop.Secret.Session` — one shared instance answers every
/// `Service.OpenSession` call, at the fixed path
/// `secretsd::secret_service::SESSION_PATH`.
#[zbus::proxy(
    interface = "org.freedesktop.Secret.Session",
    default_service = "org.secrets.Daemon",
    default_path = "/org/freedesktop/secrets/session/shared",
    gen_async = false
)]
pub trait Session {
    /// Close the session. A no-op — see `secretsd::secret_service::session`.
    fn close(&self) -> zbus::Result<()>;
}

/// `org.freedesktop.Secret.Prompt` — one shared, always-dismissed
/// instance, at the fixed path
/// `secretsd::secret_service::PROMPT_PATH`.
#[zbus::proxy(
    interface = "org.freedesktop.Secret.Prompt",
    default_service = "org.secrets.Daemon",
    default_path = "/org/freedesktop/secrets/prompt/unsupported",
    gen_async = false
)]
pub trait Prompt {
    /// Immediately emits `Completed(dismissed = true, "")` — there is no
    /// GUI agent in this MVP to actually show anything.
    fn prompt(&self, window_id: &str) -> zbus::Result<()>;

    /// Dismiss the prompt. Also a no-op: nothing was ever shown.
    fn dismiss(&self) -> zbus::Result<()>;

    /// Signalled once a prompt concludes. Always `dismissed = true` here.
    #[zbus(signal)]
    fn completed(&self, dismissed: bool, result: OwnedValue) -> zbus::Result<()>;
}
