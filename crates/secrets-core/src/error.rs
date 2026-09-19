//! The crate's error type.
//!
//! Every variant here is safe to display to a user, log, or send back over
//! D-Bus as an error message: none of them may ever be constructed with a
//! secret *value* inside them. Vault/item/field *names* are fine — they are
//! identifiers, not secrets — but the field's content never is.

use crate::store_id::StoreId;
use crate::uri::UriError;

/// Format an optional store id as a `store@` prefix, or nothing.
///
/// Shared by every `Display` impl below that folds store context into its
/// message, so `Some(store)` always renders the same way as the URI
/// grammar's own `store@vault` shape (ADR-018).
fn store_prefix(store: Option<&StoreId>) -> String {
    match store {
        Some(store) => format!("{store}@"),
        None => String::new(),
    }
}

/// Join a list of store ids for display, e.g. in an ambiguity error.
fn join_stores(stores: &[StoreId]) -> String {
    stores
        .iter()
        .map(StoreId::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Everything that can go wrong resolving or managing secrets.
///
/// Library-only: no `miette::Diagnostic` here (see AGENTS.md's "thiserror
/// for the library, miette at the binary edge"). Each variant maps to a
/// named `org.secrets.Error.*` D-Bus error in [`crate::dbus::ManagerError`]
/// instead — that mapping is this type's public, grep-able identifier.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// The `secret://` reference itself was malformed.
    #[error("invalid secret:// URI: {0}")]
    InvalidUri(#[from] UriError),

    /// The vault exists but the daemon is locked, so its contents are
    /// unreadable. Distinct from `NotFound` so a client can tell "try
    /// unlocking" apart from "this doesn't exist".
    #[error("vault '{}{vault}' is locked", store_prefix(store.as_ref()))]
    VaultLocked {
        /// The store the vault lives in, if already known at the point
        /// this error was constructed (ADR-018) — `None` when a
        /// [`crate::backend::Backend`] impl constructs this directly,
        /// since a backend never knows its own store id.
        store: Option<StoreId>,
        /// The vault that is locked.
        vault: String,
    },

    /// The vault, item or field named in the URI does not exist.
    #[error("secret not found: secret://{}{vault}/{item}/{field}", store_prefix(store.as_ref()))]
    NotFound {
        /// See [`CoreError::VaultLocked`]'s `store` field.
        store: Option<StoreId>,
        /// The vault that was searched.
        vault: String,
        /// The item path that was searched, already joined for display.
        item: String,
        /// The field that was requested.
        field: String,
    },

    /// The vault exists but no item at this path does.
    ///
    /// Distinct from [`CoreError::NotFound`], which always names a
    /// specific field: an item-level lookup (`secrets show`,
    /// `Manager::show_item`) has no field to name, so it needs its own
    /// variant rather than a `NotFound` with an empty/placeholder field.
    #[error("item not found: secret://{}{vault}/{item}", store_prefix(store.as_ref()))]
    ItemNotFound {
        /// See [`CoreError::VaultLocked`]'s `store` field.
        store: Option<StoreId>,
        /// The vault that was searched.
        vault: String,
        /// The item path that was searched, already joined for display.
        item: String,
    },

    /// The caller is not allowed to read this secret.
    ///
    /// Reserved for a future access-control layer; the MVP backend never
    /// returns this, but the error shape exists so callers can already match
    /// on it without a breaking change later.
    #[error("permission denied for secret://{}{vault}/{item}/{field}", store_prefix(store.as_ref()))]
    PermissionDenied {
        /// See [`CoreError::VaultLocked`]'s `store` field.
        store: Option<StoreId>,
        /// The vault involved.
        vault: String,
        /// The item path involved, already joined for display.
        item: String,
        /// The field involved.
        field: String,
    },

    /// The operation itself does not make sense (e.g. writing to a
    /// read-only backend), independent of locking or permissions.
    #[error("invalid operation: {0}")]
    InvalidOperation(String),

    /// The backend could not be reached or is misconfigured.
    ///
    /// Carries only a description, never the underlying data — a backend
    /// error might otherwise leak a file path containing a passphrase, for
    /// instance. Never carries a store id: a [`crate::backend::Backend`]
    /// impl constructs this directly and never knows its own store id
    /// (ADR-018) — a caller that needs to name the store attaches it to
    /// the description itself (e.g. `secretsd::state::open_registry`,
    /// which already knows which store failed to start).
    #[error("backend unavailable: {0}")]
    BackendUnavailable(String),

    /// The daemon is unlocked, but the active backend has its own,
    /// separate authentication/session concept (see
    /// [`crate::backend::BackendSession`]) and that session is missing,
    /// expired, or otherwise requires the caller — or an out-of-band flow
    /// — to authenticate before this request can proceed.
    ///
    /// Distinct from [`CoreError::VaultLocked`], which is about the
    /// daemon's own lock, not a backend's session; never carries a
    /// credential or session token, only a description.
    #[error("backend requires authentication: {0}")]
    BackendRequiresAuthentication(String),

    /// A vault name was given without a `store@` qualifier and exists in
    /// more than one configured store (ADR-018) — the caller must qualify
    /// it. `candidates` names every store the vault was found in, since
    /// store ids are configuration identifiers, not secrets, and listing
    /// them is strictly more actionable than a bare "ambiguous" message.
    #[error(
        "vault {vault:?} exists in more than one store ({}); qualify it, e.g. \"{}@{vault}\"",
        join_stores(candidates),
        candidates.first().map_or("<store>", StoreId::as_str)
    )]
    AmbiguousVault {
        /// The unqualified vault name that was searched.
        vault: String,
        /// Every store it was found in.
        candidates: Vec<StoreId>,
    },

    /// A `store@` qualifier, or an explicit `--store`/store argument,
    /// named a store that is not configured.
    #[error("no such store: {store}")]
    StoreNotFound {
        /// The store id that was not found.
        store: StoreId,
    },

    /// A daemon-wide operation with no store argument (e.g.
    /// `Manager.Unlock`) has more than one candidate store it could apply
    /// to and cannot guess which — the caller must use the store-scoped
    /// method instead (ADR-018).
    #[error(
        "more than one store needs this operation ({}); use the store-scoped method",
        join_stores(candidates)
    )]
    StoreSelectionRequired {
        /// Every store the daemon-wide operation could have applied to.
        candidates: Vec<StoreId>,
    },
}

impl CoreError {
    /// Attach store context to an error a [`crate::backend::Backend`]
    /// returned — a backend never knows its own store id (ADR-018), so a
    /// multi-store registry (`secretsd::state::DaemonState`) calls this
    /// exactly once, right after a routed call returns, to fill it in.
    ///
    /// A no-op on every variant with no `store` field (including one that
    /// already carries a store, which is left untouched rather than
    /// overwritten — a `Backend` impl never sets one, so this only
    /// happens if a caller already enriched the error itself).
    #[must_use]
    pub fn with_store(self, store: &StoreId) -> Self {
        match self {
            Self::VaultLocked { store: None, vault } => Self::VaultLocked {
                store: Some(store.clone()),
                vault,
            },
            Self::NotFound {
                store: None,
                vault,
                item,
                field,
            } => Self::NotFound {
                store: Some(store.clone()),
                vault,
                item,
                field,
            },
            Self::ItemNotFound {
                store: None,
                vault,
                item,
            } => Self::ItemNotFound {
                store: Some(store.clone()),
                vault,
                item,
            },
            Self::PermissionDenied {
                store: None,
                vault,
                item,
                field,
            } => Self::PermissionDenied {
                store: Some(store.clone()),
                vault,
                item,
                field,
            },
            other => other,
        }
    }
}

/// The crate's result alias.
pub type Result<T> = std::result::Result<T, CoreError>;

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// The value `hunter2` stands in for "any secret value" across these
    /// tests — see invariant #1 (AGENTS.md): a `CoreError`'s `Display`
    /// must never contain it, only names and ids.
    const SECRET_VALUE: &str = "hunter2";

    #[test]
    fn ambiguous_vault_names_every_candidate_store_without_leaking_a_value() {
        let error = CoreError::AmbiguousVault {
            vault: "Personal".to_string(),
            candidates: vec![StoreId::new("work").unwrap(), StoreId::new("home").unwrap()],
        };
        let message = error.to_string();
        assert!(message.contains("work"));
        assert!(message.contains("home"));
        assert!(message.contains("Personal"));
        assert!(!message.contains(SECRET_VALUE));
    }

    #[test]
    fn store_selection_required_names_every_candidate_without_leaking_a_value() {
        let error = CoreError::StoreSelectionRequired {
            candidates: vec![StoreId::new("work").unwrap(), StoreId::new("home").unwrap()],
        };
        let message = error.to_string();
        assert!(message.contains("work"));
        assert!(message.contains("home"));
        assert!(!message.contains(SECRET_VALUE));
    }

    #[test]
    fn store_not_found_names_the_store_without_leaking_a_value() {
        let error = CoreError::StoreNotFound {
            store: StoreId::new("ghost").unwrap(),
        };
        let message = error.to_string();
        assert!(message.contains("ghost"));
        assert!(!message.contains(SECRET_VALUE));
    }

    #[test]
    fn with_store_fills_in_a_missing_store_on_an_enrichable_variant() {
        let error = CoreError::NotFound {
            store: None,
            vault: "Personal".to_string(),
            item: "GitHub".to_string(),
            field: "password".to_string(),
        };
        let enriched = error.with_store(&StoreId::new("work").unwrap());
        assert!(enriched.to_string().contains("work@Personal"));
    }

    #[test]
    fn with_store_is_a_no_op_on_a_variant_with_no_store_field() {
        let error = CoreError::InvalidOperation("writes are not supported".to_string());
        let message_before = error.to_string();
        let unchanged = error.with_store(&StoreId::new("work").unwrap());
        assert_eq!(unchanged.to_string(), message_before);
    }

    #[test]
    fn vault_locked_displays_the_store_qualifier_when_known() {
        let error = CoreError::VaultLocked {
            store: Some(StoreId::new("work").unwrap()),
            vault: "Personal".to_string(),
        };
        assert_eq!(error.to_string(), "vault 'work@Personal' is locked");
    }

    #[test]
    fn vault_locked_omits_the_store_qualifier_when_unknown() {
        let error = CoreError::VaultLocked {
            store: None,
            vault: "Personal".to_string(),
        };
        assert_eq!(error.to_string(), "vault 'Personal' is locked");
    }
}
