//! `OnePasswordBackend`: the `Backend`/`BackendSession` implementation
//! over 1Password Desktop's native IPC channel.
//!
//! This is the one file in the `onepassword` module tree that depends on
//! `secrets_core` — everything below it (`ffi`, `ipc`, `protocol`,
//! `session`, `types`) stays isolated from it, per this project's own
//! constraint (see `docs/architecture/1password-integration.md`). Confirmed
//! end-to-end against a real account and a real secret — see
//! `docs/architecture/1password-poc-results.md`.
//!
//! Does not implement TOTP generation or SSH-specific signing behavior:
//! those stay Secrets-level concerns built on top of the plain
//! [`FieldKind::Totp`]/[`FieldKind::SshKey`] metadata this backend
//! reports, the same way `secretsd::ssh_agent` already consumes it from
//! `LocalBackend` today.

use std::sync::Arc;

use secrets_core::{
    Backend, BackendSession, BackendStatus, CoreError, FieldKind, FieldMeta, Item, ItemPath,
    Result as CoreResult, SecretValue, Vault,
};
use zeroize::Zeroize;

use super::ffi::IpcLibrary;
use super::ipc::IpcClient;
use super::protocol;
use super::session::{Authenticator, SessionError, SessionManager, SessionSnapshot};
use super::types;

/// Performs the confirmed `init_client` handshake (see
/// `protocol::init_client_request`) to establish or renew a session.
struct OnePasswordAuthenticator {
    account_name: String,
}

impl Authenticator for OnePasswordAuthenticator {
    fn authenticate(&self, client: &IpcClient) -> Result<u64, SessionError> {
        let request = protocol::init_client_request(
            &self.account_name,
            "secretsd",
            env!("CARGO_PKG_VERSION"),
        );
        let response = client.invoke(&request)?;
        protocol::parse_client_id(response.as_bytes())
            .map_err(|error| SessionError::AuthenticationFailed(error.to_string()))
    }
}

/// The largest `item_ids` list 1Password Desktop's own `ItemsGetAll`
/// operation accepts in one call — an undocumented constraint (nothing in
/// `docs/architecture/1password-integration.md` or 1Password's own SDK
/// docs states it), discovered empirically against a real account whose
/// vault held more than this many items. Its own IPC error text, verbatim:
/// `"invalid user input: encountered the following errors: you can only
/// retrieve up to 50 items at once"`. `list_items` chunks around this
/// transparently — every other `Backend` implementation, and every caller
/// of this one, is unaffected by it.
const ITEMS_GET_ALL_BATCH_LIMIT: usize = 50;

/// The `Backend`/`BackendSession` implementation over 1Password Desktop.
pub struct OnePasswordBackend {
    session: SessionManager,
    account_name: String,
}

impl OnePasswordBackend {
    /// Load the native library and prepare a backend for `account_name`
    /// (the 1Password account name or account UUID shown in the Desktop
    /// app's sidebar — required by the protocol itself).
    ///
    /// Performs no round trip itself: the first `Backend`/
    /// `BackendSession` call triggers the actual `init_client` handshake,
    /// same as every other backend operation here going through
    /// [`SessionManager::execute`].
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::BackendUnavailable`] if the native IPC
    /// library cannot be loaded (1Password Desktop not installed, or an
    /// incompatible version — see [`super::ffi::LoadError`]).
    pub fn open(account_name: impl Into<String>) -> CoreResult<Self> {
        let library =
            IpcLibrary::load().map_err(|error| CoreError::BackendUnavailable(error.to_string()))?;
        let client = IpcClient::init_client(library);
        let account_name = account_name.into();
        let authenticator = Arc::new(OnePasswordAuthenticator {
            account_name: account_name.clone(),
        });
        Ok(Self {
            session: SessionManager::new(client, authenticator),
            account_name,
        })
    }

    /// Call `method_name` with `parameters` and parse the response as
    /// `T` — the one seam every operation below goes through.
    fn invoke<T: serde::de::DeserializeOwned>(
        &self,
        method_name: &'static str,
        parameters: serde_json::Value,
    ) -> Result<T, CallError> {
        let response = self.session.execute(|client, client_id| {
            let request =
                protocol::invoke_request(&self.account_name, client_id, method_name, parameters);
            client.invoke(&request)
        })?;
        Ok(protocol::parse_invoke_response(response.as_bytes())?)
    }

    /// Resolve `vault`'s name to 1Password's own vault ID — required by
    /// `ItemsList`/`ItemsGetAll` (unlike `SecretsResolve`, which accepts
    /// human-readable names directly). One extra call, not one per item;
    /// still well within "the minimum number of calls" for `list_items`.
    fn vault_id(&self, vault: &str) -> Result<String, CallError> {
        let vaults: Vec<types::VaultOverview> =
            self.invoke("VaultsList", serde_json::json!({ "params": null }))?;
        vaults
            .into_iter()
            .find(|candidate| candidate.title == vault)
            .map(|candidate| candidate.id)
            .ok_or(CallError::VaultNotFound)
    }
}

/// Everything that can go wrong on one backend call, before it is mapped
/// to a [`CoreError`] with the right vault/item/field context (only the
/// call site knows that context — this type does not).
enum CallError {
    Session(SessionError),
    Protocol(protocol::ProtocolError),
    /// This backend's own `vault_id` lookup found no matching vault —
    /// distinct from a 1Password-reported failure.
    VaultNotFound,
}

impl From<SessionError> for CallError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

impl From<protocol::ProtocolError> for CallError {
    fn from(error: protocol::ProtocolError) -> Self {
        Self::Protocol(error)
    }
}

/// Text confirmed (against a real account — see
/// `docs/architecture/1password-poc-results.md`) to appear in
/// `SecretsResolve`'s structured failure `message` for each missing
/// part of an `op://` reference. Matched as substrings since 1Password
/// reports no structured per-case code beyond one shared `"name"`.
const VAULT_NOT_FOUND_TEXT: &str = "no vault matched";
const ITEM_NOT_FOUND_TEXT: &str = "no item matched";
const FIELD_NOT_FOUND_TEXT: &str = "cannot be found within the item";

/// Extracts the human-readable `message` from a `{"name":...,
/// "message":...}` failure payload (see [`types::InvokeErrorPayload`]),
/// falling back to the raw text if it is not that shape (defensive: a
/// future 1Password Desktop release could change this without notice —
/// see "Compatibility risk" in `docs/architecture/1password-integration.md`).
fn failure_detail(raw: &str) -> String {
    serde_json::from_str::<types::InvokeErrorPayload>(raw)
        .map(|payload| payload.message)
        .unwrap_or_else(|_| raw.to_string())
}

/// Maps a [`CallError`] with no specific NotFound context (e.g.
/// `list_vaults`, or the `vault_id` lookup succeeding but a later,
/// unrelated failure) — never leaks a resolved value, since none of
/// these paths ever carry one.
fn map_generic_error(error: CallError) -> CoreError {
    match error {
        CallError::VaultNotFound => {
            CoreError::BackendUnavailable("vault lookup found no matching vault".to_string())
        }
        CallError::Protocol(protocol::ProtocolError::Failure(message)) => {
            CoreError::BackendUnavailable(failure_detail(&message))
        }
        CallError::Protocol(other) => CoreError::BackendUnavailable(other.to_string()),
        CallError::Session(SessionError::Unavailable) => {
            CoreError::BackendUnavailable("1Password Desktop is unavailable".to_string())
        }
        CallError::Session(SessionError::Timeout) => {
            CoreError::BackendUnavailable("1Password Desktop did not respond in time".to_string())
        }
        CallError::Session(SessionError::AuthenticationFailed(message)) => {
            CoreError::BackendRequiresAuthentication(message)
        }
        CallError::Session(SessionError::Ipc(error)) => {
            CoreError::BackendUnavailable(error.to_string())
        }
        CallError::Session(SessionError::Internal(message)) => {
            CoreError::BackendUnavailable(message)
        }
    }
}

/// Maps a [`CallError`] from a `get_field`-shaped call, where a
/// vault/item/field-not-found failure has somewhere to go
/// ([`CoreError::NotFound`]) instead of the generic
/// [`CoreError::BackendUnavailable`] fallback.
fn map_resolve_error(vault: &str, item: &ItemPath, field: &str, error: CallError) -> CoreError {
    let not_found = || CoreError::NotFound {
        store: None,
        vault: vault.to_string(),
        item: item.to_string(),
        field: field.to_string(),
    };
    match error {
        CallError::VaultNotFound => not_found(),
        CallError::Protocol(protocol::ProtocolError::Failure(message)) => {
            let detail = failure_detail(&message);
            if detail.contains(VAULT_NOT_FOUND_TEXT)
                || detail.contains(ITEM_NOT_FOUND_TEXT)
                || detail.contains(FIELD_NOT_FOUND_TEXT)
            {
                not_found()
            } else {
                CoreError::BackendUnavailable(detail)
            }
        }
        other => map_generic_error(other),
    }
}

/// Guesses a [`FieldKind`] from 1Password's own `(fieldType, title)` —
/// not a clean 1:1 mapping, since 1Password's `ItemFieldType` doesn't
/// distinguish "username" from generic text, or "password" from a
/// generic concealed value; that distinction lives in the field's
/// `title`, by convention, not its type. Never fails: an
/// unrecognized combination becomes [`FieldKind::Custom`], the same as
/// `LocalBackend` does for anything it does not know either.
///
/// SSH key field *values*' exact format (OpenSSH text, as
/// `secretsd::ssh_agent` expects, or something else) is not confirmed
/// against a real 1Password SSH item — this backend reports the
/// metadata kind honestly, but a real SSH item has not been tested
/// end-to-end (see `docs/architecture/1password-poc-results.md`).
fn field_kind(field_type: &str, title: &str) -> FieldKind {
    let lower_title = title.to_ascii_lowercase();
    match field_type {
        "Totp" => FieldKind::Totp,
        "SshKey" => FieldKind::SshKey,
        _ if lower_title == "username" => FieldKind::Username,
        _ if lower_title == "password" => FieldKind::Password,
        _ if lower_title == "notesplain" || lower_title == "notes" => FieldKind::Note,
        _ => FieldKind::Custom(title.to_string()),
    }
}

impl Backend for OnePasswordBackend {
    fn list_vaults(&self) -> CoreResult<Vec<Vault>> {
        let vaults: Vec<types::VaultOverview> = self
            .invoke("VaultsList", serde_json::json!({ "params": null }))
            .map_err(map_generic_error)?;
        Ok(vaults.into_iter().map(|v| Vault::new(v.title)).collect())
    }

    fn list_items(&self, vault: &str) -> CoreResult<Vec<Item>> {
        let vault_id = self.vault_id(vault).map_err(|error| match error {
            CallError::VaultNotFound => CoreError::NotFound {
                store: None,
                vault: vault.to_string(),
                item: String::new(),
                field: String::new(),
            },
            other => map_generic_error(other),
        })?;

        let overviews: Vec<types::ItemOverview> = self
            .invoke(
                "ItemsList",
                serde_json::json!({ "vault_id": vault_id, "filters": [] }),
            )
            .map_err(map_generic_error)?;
        let item_ids: Vec<String> = overviews.into_iter().map(|overview| overview.id).collect();
        if item_ids.is_empty() {
            return Ok(Vec::new());
        }

        // One `ItemsGetAll` call per chunk of at most `ITEMS_GET_ALL_BATCH_LIMIT`
        // IDs, not one per item (see this module's own doc comment and the
        // task's own constraint) — but also never all of them in a single
        // call: 1Password Desktop's own IPC rejects a request whose
        // `item_ids` list has more than that many entries (see the
        // constant's own doc comment), discovered against a real account
        // with a vault larger than that. Each chunk's response is parsed
        // and its raw bytes zeroized immediately (see below), and every
        // chunk's already-parsed, non-secret metadata is accumulated
        // before mapping to `secrets_core::Item`s once, at the end.
        let mut individual_responses = Vec::with_capacity(item_ids.len());
        for chunk in item_ids.chunks(ITEMS_GET_ALL_BATCH_LIMIT) {
            // The response's raw bytes carry 1Password's real, decrypted
            // field *values* alongside their metadata — this project's own
            // `ItemField` type (see `types.rs`) never declares a `value`
            // field, so none of it is copied into anything this backend
            // holds onto beyond this call, but the raw buffer itself briefly
            // holds plaintext in memory. Best-effort mitigation: zeroize the
            // local copy immediately after parsing (`ipc::Response`'s own
            // backing buffer is not zeroized on drop today — a known
            // limitation, documented in docs/security.md).
            let response = self
                .session
                .execute(|client, client_id| {
                    let request = protocol::invoke_request(
                        &self.account_name,
                        client_id,
                        "ItemsGetAll",
                        serde_json::json!({ "vault_id": vault_id, "item_ids": chunk }),
                    );
                    client.invoke(&request)
                })
                .map_err(CallError::from)
                .map_err(map_generic_error)?;
            let mut raw_bytes = response.as_bytes().to_vec();
            let parsed: Result<types::ItemsGetAllResponse, _> =
                protocol::parse_invoke_response(&raw_bytes);
            raw_bytes.zeroize();
            let batch = parsed.map_err(CallError::from).map_err(map_generic_error)?;
            individual_responses.extend(batch.individual_responses);
        }

        Ok(individual_responses
            .into_iter()
            .filter_map(|entry| entry.content)
            .map(|item| Item {
                path: ItemPath::new(vec![item.title]).expect("1Password item titles are non-empty"),
                fields: item
                    .fields
                    .into_iter()
                    .map(|field| FieldMeta {
                        kind: field_kind(&field.field_type, &field.title),
                        name: field.title,
                    })
                    .collect(),
            })
            .collect())
    }

    fn get_field(&self, vault: &str, item: &ItemPath, field: &str) -> CoreResult<SecretValue> {
        let reference = format!("op://{vault}/{}/{field}", item.segments().join("/"));
        let response = self
            .session
            .execute(|client, client_id| {
                let request =
                    protocol::resolve_secret_request(&self.account_name, client_id, &reference);
                client.invoke(&request)
            })
            .map_err(CallError::from)
            .map_err(|error| map_resolve_error(vault, item, field, error))?;

        // This response's raw bytes carry the actual secret value being
        // requested — the single most sensitive payload this backend ever
        // handles, more so than the metadata batch in `list_items` above.
        // Same best-effort mitigation applies: zeroize the local copy
        // immediately after parsing (`ipc::Response`'s own backing buffer
        // is not zeroized on drop today — a known limitation, documented
        // in docs/security.md).
        let mut raw_bytes = response.as_bytes().to_vec();
        let parsed = protocol::parse_resolved_secret(&raw_bytes);
        raw_bytes.zeroize();
        let secret = parsed
            .map_err(CallError::from)
            .map_err(|error| map_resolve_error(vault, item, field, error))?;
        Ok(SecretValue::new(secret.expose_secret().to_string()))
    }
}

impl BackendSession for OnePasswordBackend {
    fn backend_status(&self) -> BackendStatus {
        match self.session.snapshot() {
            SessionSnapshot::Valid => BackendStatus::Authenticated,
            SessionSnapshot::Missing | SessionSnapshot::Authenticating => {
                BackendStatus::RequiresAuthentication
            }
            SessionSnapshot::Expired => BackendStatus::SessionExpired,
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64;

    use super::*;
    use crate::backend::onepassword::test_support::compile_sequenced_fixture;

    fn success_envelope(payload: &impl serde::Serialize) -> Vec<u8> {
        let payload_json = serde_json::to_vec(payload).unwrap();
        let envelope = serde_json::json!({
            "success": true,
            "payload": BASE64.encode(payload_json),
        });
        serde_json::to_vec(&envelope).unwrap()
    }

    fn failure_envelope(name: &str, message: &str) -> Vec<u8> {
        let inner = serde_json::json!({ "name": name, "message": message });
        let inner_bytes = serde_json::to_vec(&inner).unwrap();
        let envelope = serde_json::json!({
            "success": false,
            "payload": BASE64.encode(inner_bytes),
        });
        serde_json::to_vec(&envelope).unwrap()
    }

    /// A backend whose native calls, in order, return `responses` —
    /// bypasses `OnePasswordBackend::open` (which loads the real
    /// library) since these tests exercise mapping/error logic, not
    /// library discovery (already covered by `ffi`'s own tests).
    fn backend_over(dir: &std::path::Path, responses: Vec<Vec<u8>>) -> Option<OnePasswordBackend> {
        let path = compile_sequenced_fixture(dir, &responses)?;
        let library = IpcLibrary::try_load(&path).unwrap();
        let client = IpcClient::init_client(library);
        let account_name = "ExampleAccount".to_string();
        let authenticator = Arc::new(OnePasswordAuthenticator {
            account_name: account_name.clone(),
        });
        Some(OnePasswordBackend {
            session: SessionManager::new(client, authenticator),
            account_name,
        })
    }

    #[test]
    fn list_vaults_maps_vault_overviews() {
        let dir = tempfile::tempdir().unwrap();
        let responses = vec![
            success_envelope(&1u64), // init_client -> client id 1
            success_envelope(&serde_json::json!([{"id": "v1", "title": "Personal"}])),
        ];
        let Some(backend) = backend_over(dir.path(), responses) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        let vaults = backend.list_vaults().unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].name, "Personal");
    }

    #[test]
    fn list_items_maps_fields_via_two_extra_calls_not_one_per_item() {
        let dir = tempfile::tempdir().unwrap();
        let responses = vec![
            success_envelope(&1u64), // init_client
            success_envelope(&serde_json::json!([{"id": "v1", "title": "Personal"}])), // VaultsList
            success_envelope(&serde_json::json!([{"id": "i1"}])), // ItemsList
            success_envelope(&serde_json::json!({ // ItemsGetAll
                "individualResponses": [{
                    "content": {
                        "title": "GitHub",
                        "fields": [
                            {"title": "username", "fieldType": "Text"},
                            {"title": "password", "fieldType": "Concealed"},
                            {"title": "one-time password", "fieldType": "Totp"},
                        ],
                    },
                    "error": null,
                }],
            })),
        ];
        let Some(backend) = backend_over(dir.path(), responses) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        let items = backend.list_items("Personal").unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].path.segments(), ["GitHub"]);
        assert!(items[0].has_field("username"));
        assert!(items[0].has_field("password"));
        assert!(items[0].has_field("one-time password"));
        let kinds: Vec<&FieldKind> = items[0].fields.iter().map(|f| &f.kind).collect();
        assert!(kinds.contains(&&FieldKind::Username));
        assert!(kinds.contains(&&FieldKind::Password));
        assert!(kinds.contains(&&FieldKind::Totp));
    }

    #[test]
    fn list_items_chunks_items_get_all_across_more_than_fifty_items() {
        // Regression guard: a vault with more items than
        // `ITEMS_GET_ALL_BATCH_LIMIT` used to send every item ID in one
        // `ItemsGetAll` call, which 1Password Desktop's own IPC rejects
        // above 50 — discovered against a real account. 51 items forces
        // exactly two chunked calls (50, then 1).
        let dir = tempfile::tempdir().unwrap();
        let item_count = ITEMS_GET_ALL_BATCH_LIMIT + 1;

        let overviews: Vec<_> = (0..item_count)
            .map(|index| serde_json::json!({ "id": format!("item-{index}") }))
            .collect();

        let mut individual_responses: Vec<_> = (0..item_count)
            .map(|index| {
                serde_json::json!({
                    "content": {
                        "title": format!("Item {index}"),
                        "fields": [{"title": "password", "fieldType": "Concealed"}],
                    },
                    "error": null,
                })
            })
            .collect();
        let second_chunk = individual_responses.split_off(ITEMS_GET_ALL_BATCH_LIMIT);
        assert_eq!(individual_responses.len(), ITEMS_GET_ALL_BATCH_LIMIT);
        assert_eq!(second_chunk.len(), 1);

        let responses = vec![
            success_envelope(&1u64), // init_client
            success_envelope(&serde_json::json!([{"id": "v1", "title": "Personal"}])), // VaultsList
            success_envelope(&serde_json::json!(overviews)), // ItemsList
            success_envelope(&serde_json::json!({ "individualResponses": individual_responses })), // ItemsGetAll #1 (50)
            success_envelope(&serde_json::json!({ "individualResponses": second_chunk })), // ItemsGetAll #2 (1)
        ];
        let Some(backend) = backend_over(dir.path(), responses) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        let items = backend.list_items("Personal").unwrap();
        assert_eq!(
            items.len(),
            item_count,
            "every item across both chunked ItemsGetAll calls must be present"
        );
    }

    #[test]
    fn list_items_reports_not_found_for_an_unknown_vault() {
        let dir = tempfile::tempdir().unwrap();
        let responses = vec![
            success_envelope(&1u64),
            success_envelope(&serde_json::json!([{"id": "v1", "title": "Personal"}])),
        ];
        let Some(backend) = backend_over(dir.path(), responses) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        let error = backend.list_items("NoSuchVault").unwrap_err();
        assert!(matches!(error, CoreError::NotFound { .. }));
    }

    #[test]
    fn get_field_resolves_a_value_successfully() {
        let dir = tempfile::tempdir().unwrap();
        let responses = vec![success_envelope(&1u64), success_envelope(&"hunter2")];
        let Some(backend) = backend_over(dir.path(), responses) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        let item = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
        let value = backend.get_field("Personal", &item, "password").unwrap();
        assert_eq!(value.expose_secret(), "hunter2");
    }

    #[test]
    fn get_field_maps_each_confirmed_not_found_message_to_core_error_not_found() {
        for message in [
            "error resolving secret reference: no vault matched the secret reference query",
            "error resolving secret reference: no item matched the secret reference query",
            "error resolving secret reference: the specified field cannot be found within the item",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let responses = vec![
                success_envelope(&1u64),
                failure_envelope("ResolvingSecretReference", message),
            ];
            let Some(backend) = backend_over(dir.path(), responses) else {
                eprintln!("skipping: no C compiler available");
                return;
            };

            let item = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
            let error = backend
                .get_field("Personal", &item, "password")
                .unwrap_err();
            assert!(
                matches!(error, CoreError::NotFound { .. }),
                "message {message:?} should map to NotFound, got {error:?}"
            );
        }
    }

    #[test]
    fn get_field_never_leaks_a_value_into_an_unrelated_failure() {
        let dir = tempfile::tempdir().unwrap();
        let responses = vec![
            success_envelope(&1u64),
            failure_envelope("Internal", "an unrelated internal error occurred"),
        ];
        let Some(backend) = backend_over(dir.path(), responses) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        let item = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
        let error = backend
            .get_field("Personal", &item, "password")
            .unwrap_err();
        assert!(matches!(error, CoreError::BackendUnavailable(_)));
        assert!(!error.to_string().contains("hunter2"));
    }

    #[test]
    fn field_kind_falls_back_to_custom_for_anything_unrecognized() {
        assert_eq!(field_kind("Totp", "one-time password"), FieldKind::Totp);
        assert_eq!(field_kind("SshKey", "private key"), FieldKind::SshKey);
        assert_eq!(field_kind("Text", "username"), FieldKind::Username);
        assert_eq!(field_kind("Concealed", "password"), FieldKind::Password);
        assert_eq!(
            field_kind("Text", "recovery codes"),
            FieldKind::Custom("recovery codes".to_string())
        );
    }

    #[test]
    fn backend_status_reflects_the_session_before_any_call_is_made() {
        let dir = tempfile::tempdir().unwrap();
        // No responses needed: `backend_status` never triggers a call.
        let Some(backend) = backend_over(dir.path(), Vec::new()) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        assert_eq!(
            backend.backend_status(),
            BackendStatus::RequiresAuthentication
        );
    }

    #[test]
    fn backend_status_reflects_an_authenticated_session_after_a_call() {
        let dir = tempfile::tempdir().unwrap();
        let responses = vec![success_envelope(&1u64), success_envelope(&"hunter2")];
        let Some(backend) = backend_over(dir.path(), responses) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        let item = ItemPath::new(vec!["GitHub".to_string()]).unwrap();
        backend.get_field("Personal", &item, "password").unwrap();

        assert_eq!(backend.backend_status(), BackendStatus::Authenticated);
    }

    /// Opt-in, local-only: exercises `OnePasswordBackend` against a real,
    /// installed 1Password Desktop — never required in CI (`#[ignore]`;
    /// CI has no 1Password Desktop to authorize against). Run manually:
    ///
    /// ```text
    /// SECRETS_OP_ACCOUNT_NAME="<account name>" \
    /// SECRETS_OP_TEST_VAULT="<vault>" \
    /// SECRETS_OP_TEST_ITEM="<item>" \
    /// SECRETS_OP_TEST_FIELD="<field>" \
    /// cargo test --package secretsd --lib backend::onepassword::backend::tests::real_desktop_resolves_a_known_field -- --ignored
    /// ```
    ///
    /// Never prints the resolved value — only that one was obtained.
    #[test]
    #[ignore = "requires a real, installed 1Password Desktop and account — see this test's own doc comment"]
    fn real_desktop_resolves_a_known_field() {
        let account_name = std::env::var("SECRETS_OP_ACCOUNT_NAME")
            .expect("SECRETS_OP_ACCOUNT_NAME must be set for this opt-in test");
        let vault = std::env::var("SECRETS_OP_TEST_VAULT")
            .expect("SECRETS_OP_TEST_VAULT must be set for this opt-in test");
        let item_title = std::env::var("SECRETS_OP_TEST_ITEM")
            .expect("SECRETS_OP_TEST_ITEM must be set for this opt-in test");
        let field = std::env::var("SECRETS_OP_TEST_FIELD")
            .expect("SECRETS_OP_TEST_FIELD must be set for this opt-in test");

        let backend = OnePasswordBackend::open(account_name).unwrap();
        let item = ItemPath::new(vec![item_title]).unwrap();
        let value = backend.get_field(&vault, &item, &field).unwrap();
        assert!(!value.expose_secret().is_empty());
    }
}
