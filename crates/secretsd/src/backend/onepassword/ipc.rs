//! A minimal, protocol-agnostic client around [`super::ffi::IpcLibrary`]:
//! bounded-timeout request/response round trips, with error mapping and
//! response validation kept generic rather than schema-specific.
//!
//! This module deliberately does **not** claim to speak 1Password
//! Desktop's real message protocol: that schema is not confirmed (see
//! `docs/architecture/1password-integration.md`'s "What remains
//! unknown"). [`Request`]/[`Response`] are opaque byte buffers, not a
//! modeled protocol — this is the transport-level seam Step 7 (session
//! management) and the probe build on, once/if a real request body is
//! confirmed to work. Nothing here is `secrets_core`-visible.
//!
//! `#[allow(dead_code)]` below is deliberate: nothing outside this
//! module's own tests calls `IpcClient` yet — Step 7's session
//! management is its first real caller.
#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use super::ffi::{IpcLibrary, RawIpcError};

/// The default bound on any single native round trip, if a caller does
/// not choose their own via [`IpcClient::with_timeout`]. Generous enough
/// for a user-facing authorization prompt in 1Password Desktop to be
/// answered; short enough that an unresponsive Desktop app does not block
/// `secretsd` forever.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A byte-oriented request payload.
///
/// Deliberately opaque: no field here should be read as "the confirmed
/// 1Password Desktop message schema" — none is confirmed. Callers
/// construct whatever bytes they are experimenting with.
#[derive(Clone)]
pub struct Request(pub Vec<u8>);

impl std::fmt::Debug for Request {
    // Deliberately does not print the bytes: a request may eventually
    // carry something secret-shaped (a passphrase-derived token, an
    // item identifier) once a real schema exists, and this type has no
    // way to know which requests do — never printing any is the only
    // choice safe under the AGENTS.md rule for every future caller.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Request").field(&self.0.len()).finish()
    }
}

/// A byte-oriented response payload, returned only after passing this
/// module's own minimal structural checks (see [`IpcClient::invoke`]).
#[derive(Clone)]
pub struct Response(Vec<u8>);

impl Response {
    /// The response's raw bytes.
    ///
    /// Not assumed to be secret by this module (it does not know what
    /// they mean — see the module doc), but a caller building on top of
    /// this, once a real schema is known, should treat anything derived
    /// from it as potentially secret until proven otherwise.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Response {
    // Same reasoning as `Request`'s `Debug` impl.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Response").field(&self.0.len()).finish()
    }
}

/// Everything that can go wrong on one [`IpcClient::invoke`] round trip.
/// Carries only structural information (byte lengths, native status
/// codes) — never request or response contents, which may be secret.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// The native call itself failed, or returned a response this
    /// module's own consistency check rejected — see [`RawIpcError`].
    #[error("1Password Desktop IPC call failed: {0}")]
    Raw(#[from] RawIpcError),

    /// The native call did not return within the configured timeout.
    /// 1Password Desktop may be unresponsive, or waiting on user
    /// interaction (an authorization prompt) that never completed.
    #[error("1Password Desktop did not respond within {0:?}")]
    Timeout(Duration),

    /// The call could not even be attempted — a `secretsd`-side resource
    /// problem (e.g. a thread could not be spawned), not a 1Password
    /// Desktop one.
    #[error("could not complete the IPC call: {0}")]
    Internal(String),
}

/// A minimal client around a loaded [`IpcLibrary`].
///
/// Cheap to clone (an `Arc` underneath) — every [`IpcClient::invoke`]
/// call is independent and may run concurrently with others.
#[derive(Clone)]
pub struct IpcClient {
    library: Arc<IpcLibrary>,
    timeout: Duration,
}

impl IpcClient {
    /// Wrap an already-loaded library as a client, using
    /// [`DEFAULT_TIMEOUT`] for every `invoke` call.
    ///
    /// Performs no round trip itself: constructing a legitimate
    /// "initialize a session" request requires 1Password Desktop's
    /// actual message schema, which is not confirmed (see the
    /// architecture doc) — this only prepares the client to attempt one
    /// via [`IpcClient::invoke`].
    #[must_use]
    pub fn init_client(library: IpcLibrary) -> Self {
        Self {
            library: Arc::new(library),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// The same as [`IpcClient::init_client`], with an explicit timeout
    /// instead of [`DEFAULT_TIMEOUT`].
    #[must_use]
    pub fn with_timeout(library: IpcLibrary, timeout: Duration) -> Self {
        Self {
            library: Arc::new(library),
            timeout,
        }
    }

    /// Send `request` and wait up to this client's configured timeout for
    /// a response.
    ///
    /// Runs the native call — necessarily blocking, since it calls into
    /// code this process does not control — on its own thread, and joins
    /// it with a timeout: the only way to bound an FFI call this module
    /// cannot itself cancel. A timed-out call's thread is abandoned, not
    /// forcibly killed (Rust has no safe way to do that), so a stuck
    /// native call may continue running in the background — but
    /// `invoke` itself always returns within the bound, never blocking
    /// its caller indefinitely.
    ///
    /// # Errors
    ///
    /// See [`IpcError`].
    pub fn invoke(&self, request: &Request) -> Result<Response, IpcError> {
        let library = Arc::clone(&self.library);
        let bytes = request.0.clone();
        let (sender, receiver) = std::sync::mpsc::channel();

        let spawned = std::thread::Builder::new()
            .name("op-ipc-invoke".to_string())
            .spawn(move || {
                let result = library.send_message_raw(&bytes);
                // The receiver may already be gone (the caller timed
                // out and stopped waiting) — a failed send here just
                // means nobody is listening anymore, not a bug.
                let _ = sender.send(result);
            });
        if let Err(error) = spawned {
            return Err(IpcError::Internal(format!(
                "could not start the IPC worker thread: {error}"
            )));
        }

        match receiver.recv_timeout(self.timeout) {
            Ok(Ok(bytes)) => Ok(Response(bytes)),
            Ok(Err(raw_error)) => Err(IpcError::Raw(raw_error)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(IpcError::Timeout(self.timeout)),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(IpcError::Internal(
                "the IPC worker thread ended without a result (it likely panicked)".to_string(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::onepassword::test_support::compile_fixture;

    /// Echoes the request back, reporting a true, self-consistent
    /// `(len, cap)` — a legitimate response by this module's own
    /// definition of one.
    const ECHO_FIXTURE: &str = r#"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int op_sdk_ipc_send_message(const uint8_t *req_ptr, intptr_t req_len,
                             size_t *out_len, size_t *out_cap, size_t *out_ptr) {
    if (req_len < 0) { return -1; }
    size_t len = (size_t)req_len;
    uint8_t *buf = (uint8_t *)malloc(len > 0 ? len : 1);
    if (len > 0) { memcpy(buf, req_ptr, len); }
    *out_len = len;
    *out_cap = len;
    *out_ptr = (size_t)(uintptr_t)buf;
    return 0;
}

void op_sdk_ipc_free_response(uint8_t *ptr, size_t unused, size_t len) {
    (void)unused;
    (void)len;
    free(ptr);
}
"#;

    /// Reports success (status `0`) but with a null data pointer — a
    /// malformed/inconsistent response no genuine successful call could
    /// produce.
    const MALFORMED_FIXTURE: &str = r#"
#include <stdint.h>
#include <stddef.h>

int op_sdk_ipc_send_message(const uint8_t *req_ptr, intptr_t req_len,
                             size_t *out_len, size_t *out_cap, size_t *out_ptr) {
    (void)req_ptr; (void)req_len;
    *out_len = 1;
    *out_cap = 0; /* len > cap: self-inconsistent */
    *out_ptr = 0;
    return 0;
}

void op_sdk_ipc_free_response(uint8_t *ptr, size_t unused, size_t len) {
    (void)ptr; (void)unused; (void)len;
}
"#;

    /// Always reports native status `7`, regardless of input — a
    /// deterministic stand-in for whatever numeric rejection code
    /// 1Password Desktop's own IPC handler might return.
    const ALWAYS_REJECTS_FIXTURE: &str = r#"
#include <stdint.h>
#include <stddef.h>

int op_sdk_ipc_send_message(const uint8_t *req_ptr, intptr_t req_len,
                             size_t *out_len, size_t *out_cap, size_t *out_ptr) {
    (void)req_ptr; (void)req_len; (void)out_len; (void)out_cap; (void)out_ptr;
    return 7;
}

void op_sdk_ipc_free_response(uint8_t *ptr, size_t unused, size_t len) {
    (void)ptr; (void)unused; (void)len;
}
"#;

    /// Sleeps past any reasonable test timeout before ever touching the
    /// output parameters — simulates 1Password Desktop hanging (e.g. on
    /// an unanswered authorization prompt).
    const SLOW_FIXTURE: &str = r#"
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>

int op_sdk_ipc_send_message(const uint8_t *req_ptr, intptr_t req_len,
                             size_t *out_len, size_t *out_cap, size_t *out_ptr) {
    (void)req_ptr; (void)req_len; (void)out_len; (void)out_cap; (void)out_ptr;
    sleep(10);
    return -1;
}

void op_sdk_ipc_free_response(uint8_t *ptr, size_t unused, size_t len) {
    (void)ptr; (void)unused; (void)len;
}
"#;

    #[test]
    fn a_successful_round_trip_returns_the_response_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let Some(path) = compile_fixture(dir.path(), ECHO_FIXTURE) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        let library = IpcLibrary::try_load(&path).unwrap();
        let client = IpcClient::init_client(library);

        let response = client.invoke(&Request(b"hello".to_vec())).unwrap();
        assert_eq!(response.as_bytes(), b"hello");
    }

    #[test]
    fn a_malformed_response_is_rejected_without_panicking() {
        let dir = tempfile::tempdir().unwrap();
        let Some(path) = compile_fixture(dir.path(), MALFORMED_FIXTURE) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        let library = IpcLibrary::try_load(&path).unwrap();
        let client = IpcClient::init_client(library);

        let error = client.invoke(&Request(b"anything".to_vec())).unwrap_err();
        assert!(matches!(
            error,
            IpcError::Raw(RawIpcError::MalformedResponse)
        ));
    }

    #[test]
    fn a_native_rejection_is_reported_with_its_status_code() {
        let dir = tempfile::tempdir().unwrap();
        let Some(path) = compile_fixture(dir.path(), ALWAYS_REJECTS_FIXTURE) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        let library = IpcLibrary::try_load(&path).unwrap();
        let client = IpcClient::init_client(library);

        let error = client.invoke(&Request(b"anything".to_vec())).unwrap_err();
        assert!(matches!(error, IpcError::Raw(RawIpcError::Native(7))));
    }

    #[test]
    fn an_unresponsive_backend_times_out_instead_of_blocking_forever() {
        let dir = tempfile::tempdir().unwrap();
        let Some(path) = compile_fixture(dir.path(), SLOW_FIXTURE) else {
            eprintln!("skipping: no C compiler available");
            return;
        };

        let library = IpcLibrary::try_load(&path).unwrap();
        let client = IpcClient::with_timeout(library, Duration::from_millis(200));

        let error = client.invoke(&Request(b"anything".to_vec())).unwrap_err();
        assert!(matches!(error, IpcError::Timeout(_)));
    }

    #[test]
    fn request_and_response_debug_output_never_prints_the_bytes() {
        let request = Request(b"super-secret-value".to_vec());
        let response = Response(b"also-super-secret".to_vec());

        assert!(!format!("{request:?}").contains("super-secret-value"));
        assert!(!format!("{response:?}").contains("also-super-secret"));
    }
}
