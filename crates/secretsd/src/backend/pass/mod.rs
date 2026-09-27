//! The `pass` (Password Store)-compatible backend — see ADR-019.
//!
//! `gopass` needs no dedicated code: its stores are disk-compatible with
//! `pass`, and its "multiple mounts" are just additional `pass`-
//! compatible directories, each configured as its own `[store.<id>]`
//! instance (#25/ADR-018) — this module never has to know it exists.
//!
//! Module split, mirroring [`super::onepassword`]'s isolation-by-concern
//! pattern: [`backend`] is the only file depending on `secrets_core`'s
//! `Backend`/`CoreError` (plus rPGP itself); [`format`] and [`walk`] are
//! pure, PGP-free, and directly unit-testable against plain strings and
//! a plain filesystem tree.
mod backend;
mod format;
mod walk;

pub use backend::PassBackend;
