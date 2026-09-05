//! Backend implementations.
//!
//! The MVP ships exactly one: [`local::LocalBackend`]. See `PLAN.md` §7 and
//! `docs/architecture/overview.md` for the roadmap (Vaultwarden, Bitwarden,
//! 1Password, `pass`, `gopass`, `passage`). [`onepassword`] is the second,
//! under active construction — see `docs/architecture/1password-
//! integration.md`.

pub mod local;
pub mod onepassword;
