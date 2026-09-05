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
//! Not yet implemented: the actual `Backend`/`BackendSession` types —
//! pending a real, end-to-end confirmation via the probe (see
//! `docs/architecture/1password-integration.md`).

pub mod ffi;
pub mod ipc;
pub mod protocol;
pub mod session;

#[cfg(test)]
pub(crate) mod test_support;
