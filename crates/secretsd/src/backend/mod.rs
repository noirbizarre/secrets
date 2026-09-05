//! Backend implementations.
//!
//! The MVP ships exactly one: [`local::LocalBackend`]. See `PLAN.md` §7 and
//! `docs/architecture/overview.md` for the roadmap (Vaultwarden, Bitwarden,
//! 1Password, `pass`, `gopass`, `passage`).

pub mod local;
