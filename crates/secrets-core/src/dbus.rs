//! Shared D-Bus surface: names, the `org.secrets.Manager` proxy trait, and
//! error mapping.
//!
//! `secret://` is the resource-reference scheme; D-Bus is the transport.
//! This module owns the second half — the parts that must be identical in
//! `secretsd` (which implements the interface) and every client (which
//! proxies it), so the two can never drift apart.
//!
//! `org.secrets.Manager` is the `org.secrets.*` **extension namespace**,
//! not a replacement for the standard [freedesktop Secret
//! Service](https://specifications.freedesktop.org/secret-service/latest/)
//! that `secretsd` also implements (`secretsd::secret_service`) — it
//! exists only for what that standard cannot express: resolving/fetching
//! a `secret://` URI directly, and a single-passphrase unlock/status
//! model. Prefer the standard interfaces for anything they already cover.
//! See `docs/dbus/secrets-manager.md` and
//! [ADR-013](../../../docs/adr/013-standard-secret-service-and-extension-namespace.md)
//! for the full contract and rationale.

use crate::error::CoreError;

/// The well-known bus name `secretsd` registers on the session bus.
pub const SERVICE_NAME: &str = "org.secrets.Daemon";

/// The object path the `Manager` interface is served at.
pub const MANAGER_PATH: &str = "/org/secrets/Manager";

/// The daemon's session/lock state, as returned by
/// [`ManagerProxyBlocking::status`].
pub const STATUS_LOCKED: &str = "locked";

/// The daemon's session/lock state, as returned by
/// [`ManagerProxyBlocking::status`].
pub const STATUS_UNLOCKED: &str = "unlocked";

/// The fixed string `secretsd` substitutes for a secret-shaped field's
/// value in [`ManagerProxyBlocking::show_item`]'s response
/// (`FieldKind::is_secret`, ADR-016).
///
/// Never derived from the real value in any way — constant content and
/// length — so it leaks nothing about it, not even how long it is. A
/// client receiving this exact string knows only "this field's kind is
/// secret-shaped"; it is not a hint about the value underneath.
pub const OBFUSCATED_FIELD_PLACEHOLDER: &str = "••••••••";

/// One field of an item, as [`ManagerProxyBlocking::show_item`] reports
/// it.
///
/// Always safe to display verbatim: a secret-shaped field's `value` is
/// already [`OBFUSCATED_FIELD_PLACEHOLDER`] by the time this crosses the
/// bus, substituted server-side — `secretsd` never even asks the backend
/// for that field's real value (see `secretsd::state::DaemonState::show_item`).
/// A struct, not a bare tuple, so both ends of the wire name each part.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, zbus::zvariant::Type,
)]
pub struct FieldDisplay {
    /// The field's name, as it appears as the last segment of a
    /// `secret://` URI.
    pub name: String,
    /// The field's kind, in [`crate::model::FieldKind`]'s canonical
    /// string form (its `Display` impl).
    pub kind: String,
    /// The field's real value if its kind is not secret-shaped, or
    /// [`OBFUSCATED_FIELD_PLACEHOLDER`] otherwise.
    pub value: String,
}

/// The `org.secrets.*` extension namespace's `Manager` interface:
/// `secret://`-shaped operations the standard Secret Service interfaces
/// cannot express, layered on top of them — not a replacement API.
///
/// Defined once here and consumed on both ends: `secretsd` implements it
/// (`#[zbus::interface(name = "org.secrets.Manager")]` over the same method
/// set) and every client uses the generated `ManagerProxyBlocking` /
/// `ManagerProxy` to call it. Method names are plain (non-`async`) on
/// purpose — the `#[zbus::proxy]` macro generates both a blocking and an
/// async proxy from the same trait, so `secrets-client` (and `secrets-cli`
/// through it) never needs an async runtime just to talk to the daemon.
///
/// Additions are additive: new methods or properties can be appended
/// without breaking existing clients, since D-Bus dispatches by name. Do
/// not change an existing method's signature; add a new one instead.
#[zbus::proxy(
    interface = "org.secrets.Manager",
    default_service = "org.secrets.Daemon",
    default_path = "/org/secrets/Manager"
)]
pub trait Manager {
    /// Current session state: `"locked"` or `"unlocked"`
    /// ([`STATUS_LOCKED`] / [`STATUS_UNLOCKED`]).
    ///
    /// A daemon-wide composite over every configured store with a real
    /// passphrase lock (ADR-018): `"unlocked"` iff every one of them
    /// reports unlocked, vacuously true if none has a real lock at all.
    /// See [`ManagerProxyBlocking::status_store`] for one store's own
    /// status.
    fn status(&self) -> zbus::Result<String>;

    /// Unlock the store with the master passphrase.
    ///
    /// A daemon-wide composite (ADR-018): a no-op if no configured store
    /// has a real passphrase lock, unlocks it directly if exactly one
    /// does, and fails with `org.secrets.Error.StoreSelectionRequired` if
    /// more than one does — see [`ManagerProxyBlocking::unlock_store`] to
    /// target one store explicitly.
    fn unlock(&self, passphrase: &str) -> zbus::Result<()>;

    /// Lock the store, dropping any decrypted material from memory.
    ///
    /// A daemon-wide composite (ADR-018): locks every configured store
    /// unconditionally, including ones with no real lock of their own
    /// (a harmless no-op for those). See
    /// [`ManagerProxyBlocking::lock_store`] to target one store.
    fn lock(&self) -> zbus::Result<()>;

    /// List the names of every vault every configured store exposes, as
    /// `"<store>@<vault>"` strings (ADR-018) — always qualified, even
    /// when only one store is configured, so this method's output is
    /// always a valid `store@` prefix for [`ManagerProxyBlocking::
    /// list_items`] or a `secret://` reference.
    ///
    /// Available while locked: vault names are not secret material.
    fn list_vaults(&self) -> zbus::Result<Vec<String>>;

    /// List the item paths within a vault (e.g. `"GitHub"`,
    /// `"Production/database"`), joined the same way they appear in a
    /// `secret://` URI's item segment.
    ///
    /// `vault` accepts the same optional `"<store>@"` prefix as a
    /// `secret://` URI's vault segment (ADR-018): unqualified resolves
    /// via the same ambiguity rule as [`crate::uri::SecretUri`] (exactly
    /// one match resolves silently; more than one fails with
    /// `org.secrets.Error.AmbiguousVault`).
    ///
    /// Available while locked: item paths are not secret material.
    fn list_items(&self, vault: &str) -> zbus::Result<Vec<String>>;

    /// List every configured store's id (ADR-018).
    fn list_stores(&self) -> zbus::Result<Vec<String>>;

    /// One store's own session state: `"locked"` or `"unlocked"`
    /// (ADR-018) — unlike [`ManagerProxyBlocking::status`], never a
    /// composite.
    fn status_store(&self, store: &str) -> zbus::Result<String>;

    /// Unlock exactly one store with its master passphrase (ADR-018).
    fn unlock_store(&self, store: &str, passphrase: &str) -> zbus::Result<()>;

    /// Lock exactly one store, dropping any decrypted material from
    /// memory (ADR-018).
    fn lock_store(&self, store: &str) -> zbus::Result<()>;

    /// Validate and canonicalise a `secret://` reference, confirming the
    /// vault, item and field exist, without returning the field's value.
    ///
    /// Requires the store to be unlocked, since confirming a field exists
    /// is itself information about the unlocked contents.
    fn resolve(&self, uri: &str) -> zbus::Result<String>;

    /// Fetch a field's value.
    ///
    /// The only method that returns secret material — the plaintext
    /// crosses the bus here and nowhere else. Requires the store to be
    /// unlocked.
    fn get(&self, uri: &str) -> zbus::Result<String>;

    /// Show every field of one item: name, kind, and either the real
    /// value (kinds `Username`/`Certificate`) or
    /// [`OBFUSCATED_FIELD_PLACEHOLDER`] (every other kind) — see
    /// [`crate::model::FieldKind::is_secret`], ADR-016.
    ///
    /// `item_uri` is a `secret://<vault>/<item...>` reference with **no**
    /// field segment (see [`crate::uri::ItemUri`]) — distinct from every
    /// other method on this interface, which take a full
    /// `secret://<vault>/<item>/<field>` reference. Requires the store to
    /// be unlocked. Fails with `ItemNotFound` if no such item exists.
    fn show_item(&self, item_uri: &str) -> zbus::Result<Vec<FieldDisplay>>;
}

/// The `org.secrets.Error.*` D-Bus error names.
///
/// One variant per [`CoreError`] case, so a client can match on a specific
/// failure (`org.secrets.Error.VaultLocked`) rather than parsing a message
/// string. Diagnostic codes are public identifiers — renaming one is a
/// breaking change to every client.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.secrets.Error")]
pub enum ManagerError {
    /// Wraps a transport-level D-Bus failure (connection lost, timeout,
    /// ...), distinct from every application-level error below.
    #[zbus(error)]
    Zbus(zbus::Error),

    /// The `secret://` reference itself was malformed.
    InvalidUri(String),

    /// The referenced vault exists but the store is locked.
    VaultLocked(String),

    /// The vault, item or field does not exist.
    NotFound(String),

    /// The vault exists but no item at this path does — distinct from
    /// `NotFound`, which always names a specific field.
    ItemNotFound(String),

    /// The caller is not allowed to read this secret.
    PermissionDenied(String),

    /// The requested operation does not make sense in this context.
    InvalidOperation(String),

    /// The backend could not be reached.
    BackendUnavailable(String),

    /// The active backend has its own session/authentication concept
    /// (see [`crate::backend::BackendSession`]) and it is missing,
    /// expired, or otherwise unsatisfied.
    BackendRequiresAuthentication(String),

    /// An unqualified vault name (ADR-018) exists in more than one
    /// configured store; the message names every candidate.
    AmbiguousVault(String),

    /// A `store@` qualifier, or an explicit store argument, named a
    /// store that is not configured (ADR-018).
    StoreNotFound(String),

    /// A daemon-wide operation with no store argument (ADR-018) has more
    /// than one candidate store and cannot guess which; the message
    /// names every candidate and the caller should use the store-scoped
    /// method instead.
    StoreSelectionRequired(String),
}

impl From<CoreError> for ManagerError {
    /// `CoreError`'s `Display` never includes a secret value (see its own
    /// doc comment), so it is always safe to forward as the D-Bus error's
    /// description here.
    fn from(error: CoreError) -> Self {
        let message = error.to_string();
        match error {
            CoreError::InvalidUri(_) => Self::InvalidUri(message),
            CoreError::VaultLocked { .. } => Self::VaultLocked(message),
            CoreError::NotFound { .. } => Self::NotFound(message),
            CoreError::ItemNotFound { .. } => Self::ItemNotFound(message),
            CoreError::PermissionDenied { .. } => Self::PermissionDenied(message),
            CoreError::InvalidOperation(_) => Self::InvalidOperation(message),
            CoreError::BackendUnavailable(_) => Self::BackendUnavailable(message),
            CoreError::BackendRequiresAuthentication(_) => {
                Self::BackendRequiresAuthentication(message)
            }
            CoreError::AmbiguousVault { .. } => Self::AmbiguousVault(message),
            CoreError::StoreNotFound { .. } => Self::StoreNotFound(message),
            CoreError::StoreSelectionRequired { .. } => Self::StoreSelectionRequired(message),
        }
    }
}

/// The object path `secretsd` serves [`PromptBroker1`] at — fixed and
/// well-known, like [`MANAGER_PATH`].
pub const PROMPT_BROKER_PATH: &str = "/org/secrets/PromptBroker";

/// The interface name providers call to register/unregister themselves.
pub const PROMPT_BROKER_INTERFACE: &str = "org.secrets.PromptBroker1";

/// The interface name `secretsd` calls on a registered provider to hand
/// it a new request.
pub const PROMPT_PROVIDER_INTERFACE: &str = "org.secrets.PromptProvider1";

/// The interface name of each per-request object `secretsd` creates while
/// a prompt is pending (see [`PROMPT_REQUEST_PATH_PREFIX`]).
pub const PROMPT_REQUEST_INTERFACE: &str = "org.secrets.PromptRequest1";

/// The object path prefix every [`PromptRequest1`] object is registered
/// under — `secretsd` appends a per-request numeric id
/// (`{PROMPT_REQUEST_PATH_PREFIX}/<id>`).
pub const PROMPT_REQUEST_PATH_PREFIX: &str = "/org/secrets/PromptBroker/Request";

/// The provider protocol's version, returned by
/// [`PromptBroker1Proxy::register_provider`]. Bumped (with a new,
/// distinctly named interface — `PromptBroker2`, and so on) on any
/// breaking change, rather than assumed additive-forever like
/// [`Manager`] — see
/// [ADR-017](../../../docs/adr/017-prompt-broker-and-provider-protocol.md)
/// for why: unlike `org.secrets.Manager`, a provider is a separate
/// process this project does not release in lockstep with.
pub const PROMPT_PROTOCOL_VERSION: u32 = 1;

/// `org.secrets.PromptBroker1`: how an external prompt provider registers
/// itself with `secretsd`. Implemented by `secretsd`
/// (`secretsd::prompt::broker_iface`); a provider is the caller here.
///
/// A caller's identity comes from the D-Bus message's own sender field
/// (its unique connection name), never a self-reported argument — a
/// provider cannot register or unregister on another provider's behalf.
/// See ADR-017.
#[zbus::proxy(
    interface = "org.secrets.PromptBroker1",
    default_service = "org.secrets.Daemon",
    default_path = "/org/secrets/PromptBroker"
)]
pub trait PromptBroker1 {
    /// Register as a prompt provider, offering `capabilities` (a subset
    /// of the [`crate::prompt::kind`] tags) at the given priority (higher
    /// wins when more than one registered provider supports the same
    /// kind; ties favour whichever registered first). `object_path` is
    /// where `secretsd` will call [`PromptProvider1::handle_request`] on
    /// this same connection.
    ///
    /// Returns the broker's [`PROMPT_PROTOCOL_VERSION`] so the caller can
    /// verify compatibility before relying on any capability.
    fn register_provider(
        &self,
        object_path: zbus::zvariant::ObjectPath<'_>,
        capabilities: Vec<String>,
        priority: i32,
    ) -> zbus::Result<u32>;

    /// Unregister. A no-op if the caller (by its own connection's unique
    /// name) was never registered.
    fn unregister_provider(&self) -> zbus::Result<()>;
}

/// `org.secrets.PromptProvider1`: how `secretsd` hands a registered
/// provider a new request. Implemented by the provider; `secretsd` is the
/// caller here.
///
/// `request` is a [`PromptRequest1`] object living on `secretsd`'s own
/// connection — the provider reads its `Kind`/`Title`/`Description`/
/// `Options` properties, then eventually calls exactly one of
/// `respond`/`decline`/`cancel` on it. This method itself should return
/// quickly (e.g. once a window is scheduled to open); it is not expected
/// to block until the user answers — see ADR-017 on why nothing in this
/// protocol blocks a caller waiting for human interaction.
#[zbus::proxy(interface = "org.secrets.PromptProvider1")]
pub trait PromptProvider1 {
    /// Handle one new prompt request.
    fn handle_request(&self, request: zbus::zvariant::ObjectPath<'_>) -> zbus::Result<()>;
}

/// `org.secrets.PromptRequest1`: one pending prompt. Implemented by
/// `secretsd`, one object per in-flight request, at
/// `{PROMPT_REQUEST_PATH_PREFIX}/<id>`; a provider is the caller here.
/// `secretsd` always owns these objects, so only the per-request `path`
/// needs to be supplied when building a proxy — the destination defaults
/// to `secretsd` itself.
#[zbus::proxy(
    interface = "org.secrets.PromptRequest1",
    default_service = "org.secrets.Daemon"
)]
pub trait PromptRequest1 {
    /// The request's kind — one of the [`crate::prompt::kind`] tags.
    #[zbus(property)]
    fn kind(&self) -> zbus::Result<String>;

    /// A short, human-readable title.
    #[zbus(property)]
    fn title(&self) -> zbus::Result<String>;

    /// A longer, human-readable description.
    #[zbus(property)]
    fn description(&self) -> zbus::Result<String>;

    /// The offered options, non-empty only for a `"choice"` request.
    #[zbus(property)]
    fn options(&self) -> zbus::Result<Vec<String>>;

    /// Answer the request. `answer`'s shape depends on `Kind`: a string
    /// passphrase for `"unlock"`, one of `Options` verbatim for
    /// `"choice"`, or an empty string (ignored) for `"confirmation"`/
    /// `"security-key"`, which need no payload beyond calling this method
    /// at all. Fails with `org.secrets.Prompt.Error.RequestNotFound` if
    /// the request already concluded (answered, timed out, or the daemon
    /// otherwise resolved it) — this method is not guaranteed to win a
    /// race against the request's own timeout.
    fn respond(&self, answer: zbus::zvariant::Value<'_>) -> zbus::Result<()>;

    /// Explicitly decline (e.g. "No" on a confirmation).
    fn decline(&self) -> zbus::Result<()>;

    /// Dismiss without answering.
    fn cancel(&self) -> zbus::Result<()>;
}

/// The `org.secrets.Prompt.Error.*` D-Bus error names — a distinct
/// namespace from [`ManagerError`]'s `org.secrets.Error.*`, since these
/// describe failures of an entirely different interface family (the
/// prompt broker/provider protocol, not `Manager`'s vault operations).
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.secrets.Prompt.Error")]
pub enum PromptError {
    /// Wraps a transport-level D-Bus failure.
    #[zbus(error)]
    Zbus(zbus::Error),

    /// No provider is registered for the requested kind (or the one
    /// selected could not be reached in time).
    NoProviderAvailable(String),

    /// A method was called against a request id that is no longer
    /// pending — already answered, timed out, cancelled, or the caller's
    /// provider vanished. Distinct from a transport error: the request
    /// existed, it just isn't live anymore.
    RequestNotFound(String),

    /// The answer's shape didn't match the request's kind (e.g. a
    /// `"choice"` answer that names an option that was never offered).
    KindMismatch(String),

    /// The caller (by D-Bus unique name) already has a provider
    /// registered — call `unregister_provider` first to replace it.
    AlreadyRegistered(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uri::UriError;

    #[test]
    fn a_core_error_never_carries_its_own_variant_name_only_context() {
        // Regression guard: mapping must preserve the message, not just the
        // discriminant, so a client's error report is still actionable.
        let error = CoreError::NotFound {
            store: None,
            vault: "Personal".to_string(),
            item: "GitHub".to_string(),
            field: "password".to_string(),
        };
        let mapped: ManagerError = error.into();
        assert!(matches!(mapped, ManagerError::NotFound(msg) if msg.contains("Personal")));
    }

    #[test]
    fn an_item_not_found_error_maps_to_its_own_dbus_error_not_not_found() {
        // Regression guard: an item-level lookup (`Manager::show_item`)
        // must stay distinguishable from a field-level `NotFound` — a
        // client that only knows to match `NotFound` would otherwise
        // treat "no such item" the same as "no such field on an item
        // that does exist".
        let error = CoreError::ItemNotFound {
            store: None,
            vault: "Personal".to_string(),
            item: "GitHub".to_string(),
        };
        let mapped: ManagerError = error.into();
        assert!(matches!(mapped, ManagerError::ItemNotFound(msg) if msg.contains("Personal")));
    }

    #[test]
    fn an_invalid_uri_maps_to_the_invalid_uri_dbus_error() {
        let error = CoreError::InvalidUri(UriError::EmptyVault);
        let mapped: ManagerError = error.into();
        assert!(matches!(mapped, ManagerError::InvalidUri(_)));
    }

    #[test]
    fn a_backend_auth_requirement_maps_to_its_own_dbus_error_not_vault_locked() {
        // Regression guard: a backend's own session requirement must stay
        // distinguishable from the daemon's lock (ADR-0009) — a client
        // that only knows to retry "unlock" would otherwise loop forever
        // against a backend problem "unlock" cannot fix.
        let error = CoreError::BackendRequiresAuthentication(
            "1Password Desktop session expired".to_string(),
        );
        let mapped: ManagerError = error.into();
        assert!(matches!(
            mapped,
            ManagerError::BackendRequiresAuthentication(msg) if msg.contains("1Password")
        ));
    }

    #[test]
    fn an_ambiguous_vault_maps_to_its_own_dbus_error() {
        let error = CoreError::AmbiguousVault {
            vault: "Personal".to_string(),
            candidates: vec![
                crate::store_id::StoreId::new("work").unwrap(),
                crate::store_id::StoreId::new("home").unwrap(),
            ],
        };
        let mapped: ManagerError = error.into();
        assert!(matches!(mapped, ManagerError::AmbiguousVault(msg) if msg.contains("work")));
    }

    #[test]
    fn a_store_not_found_maps_to_its_own_dbus_error() {
        let error = CoreError::StoreNotFound {
            store: crate::store_id::StoreId::new("ghost").unwrap(),
        };
        let mapped: ManagerError = error.into();
        assert!(matches!(mapped, ManagerError::StoreNotFound(msg) if msg.contains("ghost")));
    }

    #[test]
    fn a_store_selection_requirement_maps_to_its_own_dbus_error() {
        let error = CoreError::StoreSelectionRequired {
            candidates: vec![
                crate::store_id::StoreId::new("work").unwrap(),
                crate::store_id::StoreId::new("home").unwrap(),
            ],
        };
        let mapped: ManagerError = error.into();
        assert!(matches!(
            mapped,
            ManagerError::StoreSelectionRequired(msg) if msg.contains("work") && msg.contains("home")
        ));
    }

    #[test]
    fn prompt_error_variants_never_echo_a_secret_shaped_fixture_value() {
        // `PromptError` is built from names/descriptions only (mirroring
        // `CoreError`'s own discipline) — never from a `PromptAnswer`.
        let errors = [
            PromptError::NoProviderAvailable("no provider for \"unlock\"".to_string()),
            PromptError::RequestNotFound("request 7 already concluded".to_string()),
            PromptError::KindMismatch("\"choice\" answer named an unlisted option".to_string()),
            PromptError::AlreadyRegistered(":1.42 is already registered".to_string()),
        ];
        for error in errors {
            assert!(!error.to_string().contains("hunter2"));
        }
    }
}
