//! Shared test-only fixtures for building a [`DaemonState`] over a
//! throwaway local vault, with or without a fixture backend session —
//! used by unit tests across this crate (`state`, `secret_service::*`,
//! `ssh_agent`) that need to exercise lock/session gating without a real
//! external backend.
//!
//! Kept in one place so every module's tests build `DaemonState` the exact
//! same way production code does (`Arc<dyn Backend>` + `Arc<dyn
//! LockController>` + `Option<Arc<dyn BackendSession>>`), rather than each
//! reinventing a slightly different fixture.

use std::sync::Arc;

use secrets_core::{Backend, BackendSession, BackendStatus};
use tempfile::TempDir;

use crate::backend::local::LocalBackend;
use crate::state::{DaemonState, LockController};

/// A fixture [`BackendSession`] whose reported status is set by the
/// caller, so session-gating logic can be exercised without a real
/// external backend.
pub(crate) struct FixedSession(pub BackendStatus);

impl BackendSession for FixedSession {
    fn backend_status(&self) -> BackendStatus {
        self.0
    }
}

/// Builds a `DaemonState` the same way `open_default_state` does, against
/// a throwaway vault file — no backend session (matches the local
/// backend, which has none).
pub(crate) fn state_over_fresh_vault() -> (TempDir, DaemonState) {
    let dir = tempfile::tempdir().expect("create a temporary directory");
    let local =
        Arc::new(LocalBackend::open(dir.path().join("vault.toml")).expect("open a fresh vault"));
    let backend: Arc<dyn Backend> = local.clone();
    let lock_controller: Arc<dyn LockController> = local;
    (dir, DaemonState::new(backend, lock_controller, None))
}

/// Same as [`state_over_fresh_vault`], but with a fixture backend session
/// attached, reporting `status`.
pub(crate) fn state_with_backend_session(status: BackendStatus) -> (TempDir, DaemonState) {
    let dir = tempfile::tempdir().expect("create a temporary directory");
    let local =
        Arc::new(LocalBackend::open(dir.path().join("vault.toml")).expect("open a fresh vault"));
    let backend: Arc<dyn Backend> = local.clone();
    let lock_controller: Arc<dyn LockController> = local;
    let session: Arc<dyn BackendSession> = Arc::new(FixedSession(status));
    (
        dir,
        DaemonState::new(backend, lock_controller, Some(session)),
    )
}
