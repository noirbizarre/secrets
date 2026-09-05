//! A `Backend`/`BackendSession` implementation talking to 1Password
//! Desktop over its native IPC library, rather than the `op` CLI.
//!
//! Everything here is kept out of `secrets-core` on purpose (see the
//! task constraints in `docs/architecture/1password-integration.md`):
//! this is an isolated, compatibility-sensitive adapter, not a shared
//! Secrets concept. Only [`ffi::IpcLibrary`]'s public methods are used
//! by the rest of this module tree; the raw C ABI and every `unsafe`
//! block live exclusively in [`ffi`].
//!
//! The confirmed, end-to-end-validated `Backend`/`BackendSession`
//! implementation itself lives in [`backend`], re-exported here as
//! [`OnePasswordBackend`] for a clean call site
//! (`onepassword::OnePasswordBackend`, not
//! `onepassword::backend::OnePasswordBackend`).

mod backend;
pub mod ffi;
pub mod ipc;
pub mod protocol;
pub mod session;
pub mod types;

pub use backend::OnePasswordBackend;

#[cfg(test)]
pub(crate) mod test_support;
