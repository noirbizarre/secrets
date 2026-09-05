//! The confirmed 1Password Desktop IPC message envelope and payload
//! shapes.
//!
//! Confirmed against 1Password's own official, MIT-licensed Go SDK
//! (`internal/shared_lib_core.go` and `internal/core.go` in
//! `github.com/1Password/onepassword-sdk-go`, and `secrets.go` for the
//! `SecretsResolve` method name/parameters) — field names, JSON tags and
//! nesting match that source exactly, not a guess. See
//! `docs/architecture/1password-integration.md` for the full citation.
//!
//! Every message is: an outer JSON envelope
//! (`{"kind","account_name","payload"}`, `payload` base64-encoded, same
//! as Go's `[]byte` auto-encoding through `encoding/json`), wrapping an
//! inner, `kind`-specific JSON payload.
//!
//! `#[allow(dead_code)]` below is deliberate: nothing outside this
//! module's own tests calls these functions yet — the Step 8 probe is
//! their first real caller.
#![allow(dead_code)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use super::ipc::Request;

/// The outer envelope every message to `op_sdk_ipc_send_message` uses.
#[derive(Serialize)]
struct Envelope {
    kind: &'static str,
    account_name: String,
    /// Base64 of the inner, `kind`-specific JSON payload's bytes —
    /// matches Go's `[]byte` field auto-encoding through `encoding/json`.
    payload: String,
}

/// `init_client`'s inner payload. Field names are JSON tags confirmed
/// against the Go SDK's `internal.ClientConfig` — including
/// `account_name` being the one field that is *not* camelCase, unlike
/// its siblings.
#[derive(Serialize)]
struct ClientConfig {
    #[serde(rename = "serviceAccountToken")]
    service_account_token: String,
    #[serde(rename = "programmingLanguage")]
    programming_language: String,
    #[serde(rename = "sdkVersion")]
    sdk_version: String,
    #[serde(rename = "integrationName")]
    integration_name: String,
    #[serde(rename = "integrationVersion")]
    integration_version: String,
    #[serde(rename = "requestLibraryName")]
    request_library_name: String,
    #[serde(rename = "requestLibraryVersion")]
    request_library_version: String,
    os: String,
    #[serde(rename = "osVersion")]
    os_version: String,
    architecture: String,
    account_name: Option<String>,
}

/// `invoke`'s inner payload — confirmed against the Go SDK's
/// `internal.InvokeConfig`/`Invocation`/`Parameters`.
#[derive(Serialize)]
struct InvokeConfig {
    invocation: Invocation,
}

#[derive(Serialize)]
struct Invocation {
    #[serde(rename = "clientId", skip_serializing_if = "Option::is_none")]
    client_id: Option<u64>,
    parameters: Parameters,
}

#[derive(Serialize)]
struct Parameters {
    name: String,
    parameters: serde_json::Value,
}

/// Everything that can go wrong interpreting a response envelope or
/// payload. Carries only structural context — never a response's
/// decoded contents, which may be secret.
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    /// The outer envelope was not the expected `{success, payload}` JSON
    /// shape.
    #[error("the response envelope was not valid JSON")]
    InvalidEnvelope,

    /// The `payload` field was not valid base64.
    #[error("the response payload was not valid base64")]
    InvalidBase64,

    /// 1Password Desktop reported `"success": false`. The message is
    /// 1Password Desktop's own diagnostic text (not a secret value —
    /// resolved field contents only ever appear inside a *successful*
    /// payload), but is still not printed by anything in this crate
    /// beyond this error's own `Display`.
    #[error("1Password Desktop reported failure: {0}")]
    Failure(String),

    /// A successful envelope's payload was not the shape a specific
    /// operation (`init_client`'s client ID, `SecretsResolve`'s string
    /// result, ...) expects.
    #[error("the response payload had an unexpected shape")]
    UnexpectedPayloadShape,
}

/// The `sdkVersion` field's confirmed-required format: **not** a semver
/// string. Found by `strace`-comparing this project's raw request bytes
/// against the real, official Go SDK's own raw request bytes on the same
/// socket — the Go SDK sends its `//go:embed release/version-build`
/// value verbatim, a 7-digit build-number encoding, not `"v0.4.1"` or
/// similar. 1Password Desktop's server-side session delegation rejects
/// (with an opaque `HttpStatus(400)`, no field-specific error) any
/// `sdkVersion` that is not a value it recognizes — a semver-looking
/// placeholder string is enough to trigger that rejection on its own,
/// independent of every other field. This exact string is the Go SDK
/// v0.4.1 release's build number, confirmed working against a real
/// account; it is not this project's own version and will need
/// re-confirming (the same way, against whatever the current official
/// SDK sends) if 1Password's accepted-version set ever changes. See
/// `docs/architecture/1password-poc-results.md` for the full finding.
const CONFIRMED_SDK_VERSION: &str = "0040102";

/// Build an `init_client` request.
///
/// `account_name` is the 1Password account name (or account UUID) as
/// shown in the Desktop app's sidebar — required by the protocol itself,
/// not an implementation choice of this module.
#[must_use]
pub fn init_client_request(
    account_name: &str,
    integration_name: &str,
    integration_version: &str,
) -> Request {
    let config = ClientConfig {
        service_account_token: String::new(),
        programming_language: "Rust".to_string(),
        sdk_version: CONFIRMED_SDK_VERSION.to_string(),
        integration_name: integration_name.to_string(),
        integration_version: integration_version.to_string(),
        request_library_name: "secretsd".to_string(),
        request_library_version: env!("CARGO_PKG_VERSION").to_string(),
        os: std::env::consts::OS.to_string(),
        os_version: "0.0.0".to_string(),
        architecture: std::env::consts::ARCH.to_string(),
        account_name: Some(account_name.to_string()),
    };
    envelope_request("init_client", account_name, &config)
}

/// Build an `invoke` request calling `SecretsResolve` for
/// `secret_reference` (an `op://vault/item/field` reference) against an
/// already-initialized `client_id`.
#[must_use]
pub fn resolve_secret_request(
    account_name: &str,
    client_id: u64,
    secret_reference: &str,
) -> Request {
    invoke_request(
        account_name,
        client_id,
        "SecretsResolve",
        serde_json::json!({ "secret_reference": secret_reference }),
    )
}

/// Build a generic `invoke` request calling `method_name` with
/// `parameters`, against an already-initialized `client_id`.
///
/// The one seam every `OnePasswordBackend` operation
/// (`VaultsList`/`ItemsList`/`ItemsGetAll`/`SecretsResolve`) builds its
/// request through — method names and parameter shapes are confirmed
/// against the Go SDK's own source per operation (see
/// `docs/architecture/1password-integration.md`), not invented here.
#[must_use]
pub fn invoke_request(
    account_name: &str,
    client_id: u64,
    method_name: &'static str,
    parameters: serde_json::Value,
) -> Request {
    let config = InvokeConfig {
        invocation: Invocation {
            client_id: Some(client_id),
            parameters: Parameters {
                name: method_name.to_string(),
                parameters,
            },
        },
    };
    envelope_request("invoke", account_name, &config)
}

fn envelope_request(kind: &'static str, account_name: &str, payload: &impl Serialize) -> Request {
    let payload_json = serde_json::to_vec(payload).expect("these payload shapes always serialize");
    let envelope = Envelope {
        kind,
        account_name: account_name.to_string(),
        payload: BASE64.encode(payload_json),
    };
    let bytes = serde_json::to_vec(&envelope).expect("the envelope always serializes");
    Request(bytes)
}

/// The `payload` field's encoding: normally base64 text (matching Go's
/// `[]byte` auto-encoding through `encoding/json`, and every successful
/// response observed against the real Desktop app), but confirmed, in
/// practice, to sometimes be a raw JSON array of byte values instead —
/// observed on an internal-error response path (an early failure before
/// the normal response constructor ever runs; see "Confirmed wire
/// protocol" in `docs/architecture/1password-integration.md`). Handling
/// both is not defensive guessing: both shapes were seen from the real
/// library, not merely anticipated.
#[derive(Deserialize)]
#[serde(untagged)]
enum PayloadEncoding {
    Base64(String),
    Raw(Vec<u8>),
}

#[derive(Deserialize)]
struct RawResponseEnvelope {
    success: bool,
    payload: PayloadEncoding,
}

/// Decode a response envelope's outer JSON and its payload encoding
/// (see [`PayloadEncoding`]), returning the inner payload's raw bytes on
/// success.
///
/// # Errors
///
/// [`ProtocolError::InvalidEnvelope`]/[`ProtocolError::InvalidBase64`] if
/// the response is not shaped as this protocol expects;
/// [`ProtocolError::Failure`] if 1Password Desktop reported
/// `"success": false`.
fn decode_response(bytes: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let raw: RawResponseEnvelope =
        serde_json::from_slice(bytes).map_err(|_| ProtocolError::InvalidEnvelope)?;
    let decoded = match raw.payload {
        PayloadEncoding::Base64(text) => BASE64
            .decode(&text)
            .map_err(|_| ProtocolError::InvalidBase64)?,
        PayloadEncoding::Raw(bytes) => bytes,
    };
    if raw.success {
        Ok(decoded)
    } else {
        Err(ProtocolError::Failure(
            String::from_utf8_lossy(&decoded).to_string(),
        ))
    }
}

/// Parse an `init_client` response into the `u64` client ID subsequent
/// `invoke` calls must reference.
///
/// # Errors
///
/// See [`decode_response`] and [`ProtocolError::UnexpectedPayloadShape`].
pub fn parse_client_id(response_bytes: &[u8]) -> Result<u64, ProtocolError> {
    let payload = decode_response(response_bytes)?;
    serde_json::from_slice(&payload).map_err(|_| ProtocolError::UnexpectedPayloadShape)
}

/// Parse a generic `invoke` response's payload as `T` — the counterpart
/// to [`invoke_request`] for operations
/// (`VaultsList`/`ItemsList`/`ItemsGetAll`/...) whose success payload
/// isn't a fixed, dedicated type this module models itself.
///
/// # Errors
///
/// See [`decode_response`] (a `"success": false` response is
/// [`ProtocolError::Failure`] here too — see
/// [`super::types::InvokeErrorPayload`] for parsing its `message` on the
/// caller's side, since only `OnePasswordBackend` knows which
/// missing-vault/item/field text to match against for a given
/// operation) and [`ProtocolError::UnexpectedPayloadShape`] if `T`
/// doesn't match.
pub fn parse_invoke_response<T: serde::de::DeserializeOwned>(
    response_bytes: &[u8],
) -> Result<T, ProtocolError> {
    let payload = decode_response(response_bytes)?;
    serde_json::from_slice(&payload).map_err(|_| ProtocolError::UnexpectedPayloadShape)
}

/// A secret resolved via `SecretsResolve`. `Debug`/`Display` never print
/// the value — the one thing this whole integration exists to protect —
/// mirroring `secrets_core::SecretValue`'s discipline without depending
/// on `secrets_core` (this module stays isolated from it, per the task's
/// own constraint).
pub struct ResolvedSecret(String);

impl ResolvedSecret {
    /// The resolved value. Named the same as `secrets_core::SecretValue`'s
    /// equivalent accessor, deliberately, so a future caller recognizes
    /// the pattern.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ResolvedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ResolvedSecret(REDACTED)")
    }
}

/// Parse a `SecretsResolve` `invoke` response into the resolved value.
///
/// # Errors
///
/// See [`decode_response`] and [`ProtocolError::UnexpectedPayloadShape`].
pub fn parse_resolved_secret(response_bytes: &[u8]) -> Result<ResolvedSecret, ProtocolError> {
    let payload = decode_response(response_bytes)?;
    let value: String =
        serde_json::from_slice(&payload).map_err(|_| ProtocolError::UnexpectedPayloadShape)?;
    Ok(ResolvedSecret(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_init_client_request_has_the_confirmed_envelope_shape() {
        let request = init_client_request("ExampleAccount", "secretsd", "0.1.0");
        let outer: serde_json::Value = serde_json::from_slice(&request.0).unwrap();

        assert_eq!(outer["kind"], "init_client");
        assert_eq!(outer["account_name"], "ExampleAccount");
        let payload_json = BASE64.decode(outer["payload"].as_str().unwrap()).unwrap();
        let inner: serde_json::Value = serde_json::from_slice(&payload_json).unwrap();

        // Field names are JSON tags confirmed against the Go SDK's
        // ClientConfig — a typo here would silently build a request
        // 1Password Desktop's own deserializer rejects.
        assert_eq!(inner["programmingLanguage"], "Rust");
        assert_eq!(inner["integrationName"], "secretsd");
        assert_eq!(inner["account_name"], "ExampleAccount");
        // Confirmed end-to-end against a real account (see
        // docs/architecture/1password-poc-results.md): a semver-looking
        // placeholder here is rejected server-side on its own, regardless
        // of every other field.
        assert_eq!(inner["sdkVersion"], CONFIRMED_SDK_VERSION);
        assert!(inner.get("serviceAccountToken").is_some());
    }

    #[test]
    fn a_resolve_secret_request_has_the_confirmed_invocation_shape() {
        let request = resolve_secret_request("ExampleAccount", 42, "op://Private/Item/password");
        let outer: serde_json::Value = serde_json::from_slice(&request.0).unwrap();
        assert_eq!(outer["kind"], "invoke");

        let payload_json = BASE64.decode(outer["payload"].as_str().unwrap()).unwrap();
        let inner: serde_json::Value = serde_json::from_slice(&payload_json).unwrap();

        assert_eq!(inner["invocation"]["clientId"], 42);
        assert_eq!(inner["invocation"]["parameters"]["name"], "SecretsResolve");
        assert_eq!(
            inner["invocation"]["parameters"]["parameters"]["secret_reference"],
            "op://Private/Item/password"
        );
    }

    #[test]
    fn a_successful_client_id_response_parses() {
        let payload = serde_json::to_vec(&42u64).unwrap();
        let envelope = serde_json::json!({
            "success": true,
            "payload": BASE64.encode(payload),
        });
        let bytes = serde_json::to_vec(&envelope).unwrap();

        assert_eq!(parse_client_id(&bytes).unwrap(), 42);
    }

    #[test]
    fn a_failure_response_is_reported_without_pretending_to_parse_a_client_id() {
        let payload = b"account_name is required".to_vec();
        let envelope = serde_json::json!({
            "success": false,
            "payload": BASE64.encode(payload),
        });
        let bytes = serde_json::to_vec(&envelope).unwrap();

        let error = parse_client_id(&bytes).unwrap_err();
        assert!(matches!(error, ProtocolError::Failure(msg) if msg.contains("account_name")));
    }

    #[test]
    fn a_failure_response_with_a_raw_byte_array_payload_still_parses() {
        // Confirmed against the real Desktop app, not a hypothetical:
        // an internal-error response path emits `payload` as a raw JSON
        // array of byte values rather than base64 text (see the module
        // doc's `PayloadEncoding`). A parser that only accepted base64
        // would report a generic "invalid envelope" instead of this
        // real, useful diagnostic text.
        let message = b"Failed to create delegated session".to_vec();
        let envelope = serde_json::json!({
            "success": false,
            "payload": message,
        });
        let bytes = serde_json::to_vec(&envelope).unwrap();

        let error = parse_client_id(&bytes).unwrap_err();
        assert!(matches!(error, ProtocolError::Failure(msg) if msg.contains("delegated session")));
    }

    #[test]
    fn a_resolved_secret_never_prints_through_debug() {
        let payload = serde_json::to_vec("correct horse battery staple").unwrap();
        let envelope = serde_json::json!({
            "success": true,
            "payload": BASE64.encode(payload),
        });
        let bytes = serde_json::to_vec(&envelope).unwrap();

        let secret = parse_resolved_secret(&bytes).unwrap();
        assert_eq!(secret.expose_secret(), "correct horse battery staple");
        assert!(!format!("{secret:?}").contains("correct horse battery staple"));
    }

    #[test]
    fn a_malformed_envelope_is_rejected_without_panicking() {
        let error = parse_client_id(b"not json at all").unwrap_err();
        assert!(matches!(error, ProtocolError::InvalidEnvelope));
    }
}
