//! Confirmed 1Password SDK response shapes this backend actually reads —
//! not a full mirror of the Go SDK's `types.go`, only the fields needed.
//!
//! Field names/nesting confirmed against
//! `github.com/1Password/onepassword-sdk-go`'s `types.go` (see
//! `docs/architecture/1password-integration.md`). Struct fields this
//! module does not declare are simply ignored by `serde_json` on
//! deserialization, not read into memory as a named value — this
//! matters for [`Item`]/[`ItemField`] below, which deliberately never
//! declare 1Password's own `value` field (see their doc comments).

use serde::Deserialize;

/// One vault, as returned by `VaultsList`.
#[derive(Debug, Deserialize)]
pub struct VaultOverview {
    /// The vault's ID — opaque to `secrets-core`; used only to resolve a
    /// `secret://` vault *name* to the ID `ItemsList`/`ItemsGetAll`
    /// require (see `backend.rs::vault_id`). `SecretsResolve` needs no
    /// such lookup — it accepts the human-readable name directly.
    pub id: String,
    /// The vault's title — this backend's `Vault::name`.
    pub title: String,
}

/// One item's identity, as returned by `ItemsList` — deliberately not
/// modeled with fields: `ItemsList`'s response never includes them
/// (1Password's own API shape, not a choice made here), which is exactly
/// why `list_items` needs a second call (`ItemsGetAll`) to get them.
#[derive(Debug, Deserialize)]
pub struct ItemOverview {
    /// The item's ID — opaque to `secrets-core`, used only to build the
    /// `ItemsGetAll` request that follows.
    pub id: String,
}

/// One field within an item, as returned by `ItemsGetAll`/`ItemsGet`.
///
/// Deliberately does **not** declare 1Password's own `value` field: this
/// project's `list_items` must never read a field's *value* (see
/// `secrets_core::model::FieldMeta`'s own doc comment) — 1Password's API
/// has no "metadata only" variant of this call, so the real, decrypted
/// value *is* present in the raw response bytes this struct is
/// deserialized from, but never becomes a named value in this program:
/// `serde_json` ignores JSON object keys a struct doesn't declare,
/// they are never copied into anything this module holds onto.
#[derive(Debug, Deserialize)]
pub struct ItemField {
    /// The field's title — used, alongside `field_type`, to guess a
    /// [`secrets_core::FieldKind`] (see `backend.rs::field_kind`).
    pub title: String,
    /// The field's 1Password type (`"Concealed"`, `"Totp"`, `"SshKey"`,
    /// ...). Confirmed against `types.go`'s `ItemFieldType`.
    #[serde(rename = "fieldType")]
    pub field_type: String,
}

/// One item's full detail, as returned by `ItemsGetAll`/`ItemsGet`.
#[derive(Debug, Deserialize)]
pub struct Item {
    /// The item's title — this backend's `ItemPath`'s (single) segment.
    pub title: String,
    /// The item's fields, metadata only (see [`ItemField`]'s doc).
    pub fields: Vec<ItemField>,
}

/// One entry in `ItemsGetAll`'s batch response — either a successful
/// [`Item`] or an error, confirmed against `types.go`'s
/// `Response<Item, ItemsGetAllError>`.
#[derive(Debug, Deserialize)]
pub struct IndividualItemResponse {
    /// Present on success.
    pub content: Option<Item>,
    // `error` is intentionally not modeled: a failed individual response
    // is skipped (see `backend.rs`), not surfaced field-by-field — an
    // item this backend cannot fetch details for is simply omitted from
    // `list_items`'s result, the same way a corrupted `LocalBackend`
    // field is (see its own `get_field` doc), rather than failing the
    // entire vault listing over one bad item.
}

/// `ItemsGetAll`'s response envelope.
#[derive(Debug, Deserialize)]
pub struct ItemsGetAllResponse {
    /// One response per requested item ID, same order as requested.
    #[serde(rename = "individualResponses")]
    pub individual_responses: Vec<IndividualItemResponse>,
}

/// The structured shape confirmed for `SecretsResolve`/other `invoke`
/// failures — distinct from `init_client`'s own failure shape (see
/// `docs/architecture/1password-poc-results.md`'s "Root cause found"
/// section). No structured per-case error code beyond this one shared
/// `name` — callers match on `message`'s text (see `backend.rs`).
#[derive(Debug, Deserialize)]
pub struct InvokeErrorPayload {
    /// Always `"ResolvingSecretReference"` for every case confirmed so
    /// far; kept as a field (not asserted) in case other operations use
    /// a different value.
    #[allow(dead_code)]
    pub name: String,
    /// The human-readable detail distinguishing missing vault/item/field
    /// — see `backend.rs`'s exact matched substrings.
    pub message: String,
}
