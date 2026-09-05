//! Session establishment/renewal for 1Password Desktop's IPC channel,
//! kept single-flight: concurrent callers never trigger more than one
//! simultaneous authentication attempt.
//!
//! 1Password Desktop owns authentication itself (its own master
//! password, biometrics, its own lock state) — `secretsd` never stores a
//! master password or session token here or anywhere else. This module
//! only tracks *that* a session currently exists and *when* it expires;
//! constructing the actual bytes a real authentication request would
//! need is delegated to an [`Authenticator`] implementation, since
//! 1Password Desktop's real message schema is not confirmed (see
//! `docs/architecture/1password-integration.md`) — nothing here assumes
//! one exists yet.
//!
//! ```text
//! execute(operation)
//!    |
//!    +-- valid session --------------------> run `operation`
//!    |
//!    +-- missing/expired
//!           |
//!           v
//!      single-flight authenticate()  (bounded by a timeout, shared by
//!           |                         every concurrent caller)
//!           v
//!       run `operation`
//! ```
//!
//! `#[allow(dead_code)]` below is deliberate: nothing outside this
//! module's own tests calls `SessionManager` yet — the Step 8 probe is
//! its first real caller.
#![allow(dead_code)]

use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, Instant};

use super::ipc::IpcClient;

/// The default bound on a single authentication attempt (the leader's
/// own attempt, not a follower's wait — see [`SessionManager::execute`]).
pub const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a freshly-established session is considered valid before
/// [`SessionManager::execute`] transparently re-authenticates. 1Password
/// Desktop's own real session lifetime is not confirmed (see the
/// architecture doc) — this is a conservative, `secretsd`-side default,
/// not a value read from anywhere authoritative.
pub const DEFAULT_SESSION_TTL: Duration = Duration::from_secs(5 * 60);

/// Something that can (re-)establish a session with 1Password Desktop.
///
/// Abstracted so this module's single-flight/timeout/state-machine logic
/// is testable without a real IPC round trip, and so a real
/// authentication request can be plugged in without touching this file.
///
/// Returns the 1Password-assigned client ID an authentication attempt
/// establishes — 1Password Desktop's `init_client` operation returns one
/// (see `docs/architecture/1password-integration.md`), and every
/// subsequent `invoke` call must reference it. [`SessionManager`] holds
/// this alongside its own validity tracking and hands it to
/// [`SessionManager::execute`]'s operation closure — it is 1Password's
/// own session handle, not a credential, and is never itself secret.
pub trait Authenticator: Send + Sync {
    /// Attempt to establish (or renew) a session over `client`.
    ///
    /// # Errors
    ///
    /// Any [`SessionError`] appropriate to what went wrong; this trait
    /// does not itself impose a timeout — [`SessionManager`] bounds the
    /// call from the outside (see [`SessionManager::execute`]'s doc).
    fn authenticate(&self, client: &IpcClient) -> Result<u64, SessionError>;
}

/// Everything that can go wrong establishing or using a session. Carries
/// only structural/descriptive context — never a credential, token, or
/// message payload.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// 1Password Desktop reported (or this module inferred) that
    /// authentication is required and did not succeed.
    #[error("authentication with 1Password Desktop failed: {0}")]
    AuthenticationFailed(String),

    /// 1Password Desktop is not reachable at all.
    #[error("1Password Desktop is unavailable")]
    Unavailable,

    /// Authentication (this caller's own attempt, or another caller's
    /// in-flight attempt this caller was waiting on) did not complete
    /// within the configured timeout.
    #[error("authentication with 1Password Desktop timed out")]
    Timeout,

    /// The operation passed to [`SessionManager::execute`] itself failed,
    /// once a session was confirmed valid.
    #[error(transparent)]
    Ipc(#[from] super::ipc::IpcError),

    /// A `secretsd`-side resource problem (e.g. a thread could not be
    /// spawned) — not a 1Password Desktop problem.
    #[error("could not complete the session operation: {0}")]
    Internal(String),
}

/// The session's current lifecycle state. Never persisted — held only in
/// memory, for exactly as long as `secretsd` runs.
#[derive(Clone, Copy)]
enum SessionState {
    /// No session has been established yet, or the last attempt failed.
    Missing,
    /// A session is currently being established or renewed — every other
    /// caller waits on this one attempt rather than starting their own.
    Authenticating,
    /// A session exists and is valid until `expires_at`, referencing
    /// 1Password's own `client_id` (see [`Authenticator`]'s doc — not a
    /// credential, 1Password's own session handle).
    Valid { expires_at: Instant, client_id: u64 },
}

struct Inner {
    state: SessionState,
}

/// A snapshot of the session's current lifecycle state, without
/// triggering any authentication attempt — for callers that need to
/// *report* status (e.g. `OnePasswordBackend`'s `BackendSession` impl,
/// mapping this to `secrets_core::BackendStatus`), not *use* the
/// session. Deliberately not `secrets_core`-shaped itself — this module
/// stays isolated from `secrets_core`, same as every other module in
/// this tree; only `backend.rs` bridges the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSnapshot {
    /// No session has been established yet, or the last attempt failed.
    Missing,
    /// A session is currently being established or renewed.
    Authenticating,
    /// A session exists and has not yet expired.
    Valid,
    /// A session existed but its TTL has elapsed.
    Expired,
}

/// Owns a session's lifecycle over one [`IpcClient`], serializing
/// authentication so concurrent callers share a single in-flight attempt.
pub struct SessionManager {
    client: IpcClient,
    authenticator: Arc<dyn Authenticator>,
    inner: Mutex<Inner>,
    condvar: Condvar,
    session_ttl: Duration,
    auth_timeout: Duration,
}

impl SessionManager {
    /// Build a manager with [`DEFAULT_SESSION_TTL`]/[`DEFAULT_AUTH_TIMEOUT`].
    #[must_use]
    pub fn new(client: IpcClient, authenticator: Arc<dyn Authenticator>) -> Self {
        Self::with_timing(
            client,
            authenticator,
            DEFAULT_SESSION_TTL,
            DEFAULT_AUTH_TIMEOUT,
        )
    }

    /// The same as [`SessionManager::new`], with explicit timing instead
    /// of the defaults.
    #[must_use]
    pub fn with_timing(
        client: IpcClient,
        authenticator: Arc<dyn Authenticator>,
        session_ttl: Duration,
        auth_timeout: Duration,
    ) -> Self {
        Self {
            client,
            authenticator,
            inner: Mutex::new(Inner {
                state: SessionState::Missing,
            }),
            condvar: Condvar::new(),
            session_ttl,
            auth_timeout,
        }
    }

    /// Ensure a valid session exists (authenticating or renewing exactly
    /// once, however many callers are concurrently waiting on it), then
    /// run `operation` against the underlying client and 1Password's own
    /// `client_id` for the current session.
    ///
    /// Bounded, on every path: a caller that becomes the one responsible
    /// for authenticating has that attempt itself run on its own thread,
    /// joined with `auth_timeout` — a hung 1Password Desktop cannot block
    /// this call forever. A caller that instead waits on someone else's
    /// in-flight attempt is bounded by the same timeout via a condition
    /// variable. Either way, `execute` always returns.
    ///
    /// # Errors
    ///
    /// See [`SessionError`]. `operation`'s own [`super::ipc::IpcError`]
    /// is propagated via [`SessionError::Ipc`].
    pub fn execute<T>(
        &self,
        operation: impl FnOnce(&IpcClient, u64) -> Result<T, super::ipc::IpcError>,
    ) -> Result<T, SessionError> {
        let client_id = self.ensure_authenticated()?;
        operation(&self.client, client_id).map_err(SessionError::from)
    }

    /// A snapshot of the current session state — never triggers
    /// authentication, never blocks on another caller's in-flight
    /// attempt. See [`SessionSnapshot`].
    #[must_use]
    pub fn snapshot(&self) -> SessionSnapshot {
        let guard = self.inner.lock().expect("poisoned");
        match guard.state {
            SessionState::Missing => SessionSnapshot::Missing,
            SessionState::Authenticating => SessionSnapshot::Authenticating,
            SessionState::Valid { expires_at, .. } if expires_at > Instant::now() => {
                SessionSnapshot::Valid
            }
            SessionState::Valid { .. } => SessionSnapshot::Expired,
        }
    }

    fn ensure_authenticated(&self) -> Result<u64, SessionError> {
        let mut guard = self.inner.lock().expect("poisoned");
        loop {
            match guard.state {
                SessionState::Valid {
                    expires_at,
                    client_id,
                } if expires_at > Instant::now() => {
                    return Ok(client_id);
                }
                SessionState::Authenticating => {
                    // Someone else is already authenticating — wait to be
                    // notified, bounded by `auth_timeout` so a caller
                    // that misses its own notification (or a leader that
                    // never finishes) does not wait forever.
                    let (new_guard, wait_result) = self
                        .condvar
                        .wait_timeout(guard, self.auth_timeout)
                        .expect("poisoned");
                    guard = new_guard;
                    if wait_result.timed_out() {
                        return Err(SessionError::Timeout);
                    }
                    // Re-check state from the top: could be `Valid` now,
                    // still `Authenticating` (a different attempt already
                    // started after this one's timeout window), or
                    // `Missing` (the attempt we waited on just failed).
                }
                SessionState::Valid { .. } | SessionState::Missing => break,
            }
        }

        // We are now the one responsible for authenticating.
        guard.state = SessionState::Authenticating;
        drop(guard);

        let result = run_with_timeout(
            {
                let authenticator = Arc::clone(&self.authenticator);
                let client = self.client.clone();
                move || authenticator.authenticate(&client)
            },
            self.auth_timeout,
            "op-session-auth",
        );

        let mut guard = self.inner.lock().expect("poisoned");
        guard.state = match &result {
            Ok(client_id) => SessionState::Valid {
                expires_at: Instant::now() + self.session_ttl,
                client_id: *client_id,
            },
            Err(_) => SessionState::Missing,
        };
        drop(guard);
        // Wake every waiter regardless of outcome: on failure, each one
        // re-evaluates from `Missing` and races to become the next
        // leader, rather than being handed a permanently cached error.
        self.condvar.notify_all();

        result
    }
}

/// Runs `work` on its own named thread, joined with `timeout` — the same
/// "cannot cancel a blocking call, so bound how long we wait for it"
/// pattern [`super::ipc::IpcClient::invoke`] uses for the native FFI
/// call itself, applied here to an arbitrary [`Authenticator`]
/// implementation instead.
fn run_with_timeout(
    work: impl FnOnce() -> Result<u64, SessionError> + Send + 'static,
    timeout: Duration,
    thread_name: &str,
) -> Result<u64, SessionError> {
    let (sender, receiver) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name(thread_name.to_string())
        .spawn(move || {
            let result = work();
            let _ = sender.send(result);
        });
    if let Err(error) = spawned {
        return Err(SessionError::Internal(format!(
            "could not start a worker thread: {error}"
        )));
    }

    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(SessionError::Timeout),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(SessionError::Internal(
            "a worker thread ended without a result (it likely panicked)".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::backend::onepassword::ffi::IpcLibrary;
    use crate::backend::onepassword::test_support::compile_fixture;

    const ECHO_FIXTURE: &str = r#"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int op_sdk_ipc_send_message(const uint8_t *req_ptr, size_t req_len,
                             uint8_t **out_buf, size_t *out_len, size_t *out_cap) {
    uint8_t *buf = (uint8_t *)malloc(req_len > 0 ? req_len : 1);
    if (req_len > 0) { memcpy(buf, req_ptr, req_len); }
    *out_buf = buf;
    *out_len = req_len;
    *out_cap = req_len;
    return 0;
}

void op_sdk_ipc_free_response(uint8_t *buf, size_t len, size_t cap) {
    (void)len;
    (void)cap;
    free(buf);
}
"#;

    /// Builds a real `IpcClient` over a compiled echo fixture — these
    /// tests exercise session *state* logic, not IPC bytes, but still
    /// route through a genuine client rather than something fake.
    fn echo_client(dir: &std::path::Path) -> Option<IpcClient> {
        let path = compile_fixture(dir, ECHO_FIXTURE)?;
        let library = IpcLibrary::try_load(&path).unwrap();
        Some(IpcClient::init_client(library))
    }

    /// Succeeds immediately, counting how many times it was actually
    /// invoked — the load-bearing assertion for single-flight behavior.
    struct CountingAuthenticator {
        calls: AtomicUsize,
    }

    impl CountingAuthenticator {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl Authenticator for CountingAuthenticator {
        fn authenticate(&self, _client: &IpcClient) -> Result<u64, SessionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(1)
        }
    }

    /// Always reports the backend as unavailable, without ever touching
    /// the client.
    struct UnavailableAuthenticator;

    impl Authenticator for UnavailableAuthenticator {
        fn authenticate(&self, _client: &IpcClient) -> Result<u64, SessionError> {
            Err(SessionError::Unavailable)
        }
    }

    /// Sleeps past any reasonable test timeout before ever returning —
    /// simulates 1Password Desktop hanging (e.g. an unanswered
    /// authorization prompt).
    struct HangingAuthenticator;

    impl Authenticator for HangingAuthenticator {
        fn authenticate(&self, _client: &IpcClient) -> Result<u64, SessionError> {
            std::thread::sleep(Duration::from_secs(10));
            Ok(1)
        }
    }

    #[test]
    fn the_operation_receives_the_client_id_authenticate_established() {
        let dir = tempfile::tempdir().unwrap();
        let Some(client) = echo_client(dir.path()) else {
            eprintln!("skipping: no C compiler available");
            return;
        };
        // `CountingAuthenticator::authenticate` always establishes
        // client_id 1 — confirm `execute` hands that exact value to the
        // operation, not just "some" id.
        let manager = SessionManager::new(client, Arc::new(CountingAuthenticator::new()));

        let observed = manager.execute(|_, client_id| Ok(client_id)).unwrap();
        assert_eq!(observed, 1);
    }

    #[test]
    fn snapshot_reflects_state_without_triggering_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let Some(client) = echo_client(dir.path()) else {
            eprintln!("skipping: no C compiler available");
            return;
        };
        let authenticator = Arc::new(CountingAuthenticator::new());
        let manager = SessionManager::with_timing(
            client,
            authenticator.clone(),
            Duration::from_millis(1),
            DEFAULT_AUTH_TIMEOUT,
        );

        assert_eq!(manager.snapshot(), SessionSnapshot::Missing);
        assert_eq!(authenticator.calls.load(Ordering::SeqCst), 0);

        manager.execute(|_, _client_id| Ok(())).unwrap();
        assert_eq!(manager.snapshot(), SessionSnapshot::Valid);

        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(manager.snapshot(), SessionSnapshot::Expired);
        // Still hasn't re-authenticated just from being snapshotted.
        assert_eq!(authenticator.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_missing_session_triggers_authentication_before_the_operation_runs() {
        let dir = tempfile::tempdir().unwrap();
        let Some(client) = echo_client(dir.path()) else {
            eprintln!("skipping: no C compiler available");
            return;
        };
        let authenticator = Arc::new(CountingAuthenticator::new());
        let manager = SessionManager::new(client, authenticator.clone());

        let result = manager.execute(|client, _client_id| {
            client.invoke(&super::super::ipc::Request(b"hi".to_vec()))
        });

        assert!(result.is_ok());
        assert_eq!(authenticator.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_second_call_within_the_session_ttl_does_not_reauthenticate() {
        let dir = tempfile::tempdir().unwrap();
        let Some(client) = echo_client(dir.path()) else {
            eprintln!("skipping: no C compiler available");
            return;
        };
        let authenticator = Arc::new(CountingAuthenticator::new());
        let manager = SessionManager::with_timing(
            client,
            authenticator.clone(),
            Duration::from_secs(60),
            DEFAULT_AUTH_TIMEOUT,
        );

        manager.execute(|_, _client_id| Ok(())).unwrap();
        manager.execute(|_, _client_id| Ok(())).unwrap();

        assert_eq!(authenticator.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn an_expired_session_triggers_renewal() {
        let dir = tempfile::tempdir().unwrap();
        let Some(client) = echo_client(dir.path()) else {
            eprintln!("skipping: no C compiler available");
            return;
        };
        let authenticator = Arc::new(CountingAuthenticator::new());
        // A TTL of effectively zero: the second call always finds an
        // already-expired session.
        let manager = SessionManager::with_timing(
            client,
            authenticator.clone(),
            Duration::from_millis(1),
            DEFAULT_AUTH_TIMEOUT,
        );

        manager.execute(|_, _client_id| Ok(())).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        manager.execute(|_, _client_id| Ok(())).unwrap();

        assert_eq!(authenticator.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn concurrent_callers_share_one_in_flight_authentication() {
        let dir = tempfile::tempdir().unwrap();
        let Some(client) = echo_client(dir.path()) else {
            eprintln!("skipping: no C compiler available");
            return;
        };
        let authenticator = Arc::new(CountingAuthenticator::new());
        let manager = Arc::new(SessionManager::new(client, authenticator.clone()));

        std::thread::scope(|scope| {
            for _ in 0..16 {
                let manager = Arc::clone(&manager);
                scope.spawn(move || {
                    manager.execute(|_, _client_id| Ok(())).unwrap();
                });
            }
        });

        assert_eq!(
            authenticator.calls.load(Ordering::SeqCst),
            1,
            "16 concurrent callers must share exactly one authentication attempt"
        );
    }

    #[test]
    fn an_unavailable_backend_is_reported_without_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let Some(client) = echo_client(dir.path()) else {
            eprintln!("skipping: no C compiler available");
            return;
        };
        let manager = SessionManager::new(client, Arc::new(UnavailableAuthenticator));

        let error = manager.execute(|_, _client_id| Ok(())).unwrap_err();
        assert!(matches!(error, SessionError::Unavailable));
    }

    #[test]
    fn hung_authentication_times_out_instead_of_blocking_forever() {
        let dir = tempfile::tempdir().unwrap();
        let Some(client) = echo_client(dir.path()) else {
            eprintln!("skipping: no C compiler available");
            return;
        };
        let manager = SessionManager::with_timing(
            client,
            Arc::new(HangingAuthenticator),
            DEFAULT_SESSION_TTL,
            Duration::from_millis(200),
        );

        let error = manager.execute(|_, _client_id| Ok(())).unwrap_err();
        assert!(matches!(error, SessionError::Timeout));
    }

    #[test]
    fn a_follower_waiting_on_a_hung_leader_also_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let Some(client) = echo_client(dir.path()) else {
            eprintln!("skipping: no C compiler available");
            return;
        };
        let manager = Arc::new(SessionManager::with_timing(
            client,
            Arc::new(HangingAuthenticator),
            DEFAULT_SESSION_TTL,
            Duration::from_millis(200),
        ));

        let results: Vec<Result<(), SessionError>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..4)
                .map(|_| {
                    let manager = Arc::clone(&manager);
                    scope.spawn(move || manager.execute(|_, _client_id| Ok(())))
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        assert!(
            results
                .iter()
                .all(|r| matches!(r, Err(SessionError::Timeout))),
            "every caller — leader and followers alike — must time out, not hang"
        );
    }
}
