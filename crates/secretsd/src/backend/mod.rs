//! Backend implementations.
//!
//! The MVP ships [`local::LocalBackend`]. See `PLAN.md` §7 and
//! `docs/architecture/overview.md` for the roadmap (Vaultwarden, Bitwarden,
//! 1Password, `pass`, `gopass`, `passage`). [`onepassword`] is the second
//! — see `docs/architecture/1password-integration.md`. [`pass`] is the
//! third, covering both `pass` and `gopass` — see
//! [ADR-019](../../../../docs/adr/019-pass-backend.md).

pub mod local;
pub mod onepassword;
pub mod pass;
