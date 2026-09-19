//! `secretsd`'s side of the toolkit-independent prompt provider protocol
//! (`secrets_core::dbus::{PromptBroker1, PromptProvider1, PromptRequest1}`,
//! `secrets_core::prompt`). See
//! [ADR-017](../../../../docs/adr/017-prompt-broker-and-provider-protocol.md)
//! for the full design.
//!
//! **Nothing here ever blocks the D-Bus dispatch thread** waiting on a
//! human or a provider process: `main.rs`'s own module doc notes the
//! blocking `Connection` dispatches every method call on a single
//! background thread, so a handler that blocked in-line on user
//! interaction would stall every other client of `secretsd` for as long
//! as the prompt stayed open. Concretely:
//! - [`broker::PromptBroker::submit`] never waits for an answer — it
//!   returns immediately, registering a callback to run later.
//! - Outbound calls to a provider (`PromptProvider1::handle_request`) and
//!   the per-request timeout each run on their own short-lived thread,
//!   mirroring `crate::backend::onepassword::session::SessionManager`'s
//!   bounded-worker-thread pattern for the same reason (a hung external
//!   process/human must not block `secretsd` itself).
//! - The eventual answer is delivered as the standard `Completed` signal
//!   via `Connection::emit_signal`, called from whichever thread learns
//!   the outcome — the same "emit a signal from outside any live method
//!   call" technique `secret_service::refresh` already uses for topology
//!   change signals.

pub mod broker;
pub mod broker_iface;
pub mod request_iface;
pub mod watcher;

pub use broker::{PromptBroker, PromptId};
pub use broker_iface::PromptBrokerIface;
