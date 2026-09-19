//! `org.freedesktop.Secret.Prompt`.
//!
//! One shared instance answers every operation that would need a real
//! interactive prompt — the MVP simplification from ADR-004 is
//! unchanged: this is still a single, shared object, not one per
//! operation. What changed (see
//! [ADR-017](../../../../../docs/adr/017-prompt-broker-and-provider-protocol.md))
//! is *what it does* while a real
//! `crate::prompt::PromptBroker` provider is registered:
//! [`Service.Unlock`](super::service::ServiceIface::unlock) can now start
//! a genuine passphrase request instead of only ever reporting itself
//! dismissed. With no provider registered, behaviour is byte-for-byte
//! the original MVP one — dismissed immediately, every time.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use secrets_core::SecretValue;
use secrets_core::prompt::{PromptAnswer, PromptKind, PromptOutcome};
use zbus::blocking::Connection;

use super::PROMPT_PATH;
use crate::prompt::{PromptBroker, PromptId};
use crate::state::DaemonState;

/// Coordinates the one prompt the Secret Service compatibility layer can
/// trigger: unlocking the daemon's own passphrase lock. Shared (`Arc`)
/// between [`super::service::ServiceIface`] (which starts a request) and
/// [`PromptIface`] (which the spec's `Prompt()`/`Dismiss()` calls reach).
///
/// Two-step construction, same reason as [`PromptBroker`] itself: the
/// connection needed for [`Connection::emit_signal`] does not exist until
/// after `main.rs`'s builder chain — which must register [`PromptIface`]
/// — returns it.
pub struct UnlockPrompt {
    state: Arc<DaemonState>,
    broker: Arc<PromptBroker>,
    connection: Mutex<Option<Connection>>,
    /// Whether a request is currently outstanding — a plain flag, not the
    /// request's id, so [`UnlockPrompt::is_pending`] never needs to touch
    /// [`UnlockPrompt::current_id`]'s lock. Cleared by
    /// [`UnlockPrompt::complete`] before anything else it does, so a
    /// concurrent [`UnlockPrompt::begin`] is never wedged waiting on
    /// bookkeeping that has not happened yet.
    requested: AtomicBool,
    /// The outstanding request's id, if any — only used by
    /// [`UnlockPrompt::cancel`] for best-effort cancellation. May briefly
    /// hold a stale id if the request concluded on its own in the small
    /// window between [`PromptBroker::submit`] returning and this being
    /// set; [`PromptBroker::resolve`] treats resolving an already-resolved
    /// id as a harmless no-op, so the only consequence is `cancel` doing
    /// nothing when there is nothing left to cancel.
    current_id: Mutex<Option<PromptId>>,
}

impl UnlockPrompt {
    /// Wrap daemon state and the shared broker as a fresh, idle
    /// coordinator.
    #[must_use]
    pub fn new(state: Arc<DaemonState>, broker: Arc<PromptBroker>) -> Self {
        Self {
            state,
            broker,
            connection: Mutex::new(None),
            requested: AtomicBool::new(false),
            current_id: Mutex::new(None),
        }
    }

    /// Supply the real connection, once, right after `main.rs`'s
    /// connection builder returns — see the struct's own doc comment.
    pub fn set_connection(&self, connection: Connection) {
        *self.connection.lock().expect("poisoned") = Some(connection);
    }

    /// Whether an unlock request is currently outstanding.
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }

    /// Start a real unlock request, if one isn't already outstanding —
    /// called by [`super::service::ServiceIface::unlock`] when the
    /// daemon's own passphrase lock (not a backend session) is why access
    /// is currently denied. Never blocks (see `crate::prompt`'s module
    /// doc): with no registered `"unlock"`-capable provider, this
    /// resolves immediately and changes nothing observable — the
    /// eventual [`PromptIface::prompt`] call still dismisses immediately,
    /// exactly like the original MVP behaviour.
    pub fn begin(self: &Arc<Self>) {
        if self.requested.swap(true, Ordering::SeqCst) {
            // Already have one in flight — Secret Service's `Unlock` can
            // be called again (a second client, or the same one retrying)
            // while the first request is still open; reuse it rather than
            // issuing a second, untracked request no one will ever see
            // the answer to.
            return;
        }
        let kind = PromptKind::Unlock {
            backend_name: "the Secrets vault".to_string(),
        };
        let this = Arc::clone(self);
        let id = self
            .broker
            .submit(kind, move |outcome| this.complete(outcome));
        *self.current_id.lock().expect("poisoned") = id;
    }

    /// Best-effort cancellation of the outstanding request, if any — see
    /// [`UnlockPrompt::current_id`]'s own doc comment for why this can be
    /// a harmless no-op.
    pub fn cancel(&self) {
        if let Some(id) = self.current_id.lock().expect("poisoned").take() {
            self.broker.resolve(id, PromptOutcome::Cancelled);
        }
    }

    /// If nothing is outstanding, dismiss immediately — the original MVP
    /// behaviour, preserved byte-for-byte with no provider registered.
    /// If a request *is* outstanding, do nothing here:
    /// [`UnlockPrompt::complete`] emits `Completed` itself once the
    /// provider answers, the request times out, or it vanishes.
    pub fn prompt_now(&self) {
        if !self.is_pending() {
            self.emit_completed(true);
        }
    }

    fn complete(&self, outcome: PromptOutcome) {
        self.requested.store(false, Ordering::SeqCst);
        *self.current_id.lock().expect("poisoned") = None;
        let dismissed = match outcome {
            PromptOutcome::Answered(PromptAnswer::Password(passphrase)) => {
                self.try_unlock(passphrase)
            }
            // Every other outcome (declined, cancelled, timed out, no
            // provider, provider vanished, or a mismatched `Answered`
            // variant `PromptRequestIface::respond` should never actually
            // produce for an "unlock" request) reports as dismissed —
            // there is no passphrase to try.
            _ => true,
        };
        self.emit_completed(dismissed);
    }

    /// Attempt the unlock, logging (never the passphrase) on failure.
    /// Returns whether the prompt should report itself dismissed (`true`)
    /// or succeeded (`false`).
    fn try_unlock(&self, passphrase: SecretValue) -> bool {
        match self.state.unlock(passphrase.expose_secret()) {
            Ok(()) => false,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "a prompt provider's passphrase did not unlock the store"
                );
                true
            }
        }
    }

    /// Emit the standard `Completed` signal. Deliberately **not** emitted
    /// via a `#[zbus(signal)]` codegen'd method (which needs an async
    /// `SignalEmitter` only available inside a live method call) —
    /// `Connection::emit_signal` is already synchronous and independent
    /// of any interface object, the same technique
    /// `secret_service::refresh` already uses for its own signals emitted
    /// from outside a call.
    fn emit_completed(&self, dismissed: bool) {
        let Some(connection) = self.connection.lock().expect("poisoned").clone() else {
            // Not wired up yet (a request resolved before `main.rs` ever
            // called `set_connection` — not reachable in practice, since
            // `begin` is only ever reached via a live D-Bus call, which
            // implies the connection already exists, but this is cheaper
            // and safer than an `expect` here).
            return;
        };
        let result: zbus::zvariant::OwnedValue = zbus::zvariant::Value::from("")
            .try_into()
            .expect("an empty string always converts to an OwnedValue");
        if let Err(error) = connection.emit_signal(
            None::<&str>,
            PROMPT_PATH,
            "org.freedesktop.Secret.Prompt",
            "Completed",
            &(dismissed, result),
        ) {
            tracing::warn!(%error, "could not emit Prompt.Completed");
        }
    }
}

/// The shared prompt object.
pub struct PromptIface {
    unlock_prompt: Arc<UnlockPrompt>,
}

impl PromptIface {
    /// Wrap the shared unlock coordinator as a servable interface.
    #[must_use]
    pub fn new(unlock_prompt: Arc<UnlockPrompt>) -> Self {
        Self { unlock_prompt }
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Prompt")]
impl PromptIface {
    /// Would show the prompt. If nothing is outstanding, dismisses
    /// immediately, exactly like the original MVP; otherwise, a provider
    /// has already been notified (by
    /// [`super::service::ServiceIface::unlock`]) and `Completed` follows
    /// once it answers, times out, or vanishes.
    fn prompt(&self, _window_id: &str) {
        self.unlock_prompt.prompt_now();
    }

    /// Dismiss the prompt, cancelling the outstanding request if any.
    fn dismiss(&self) {
        self.unlock_prompt.cancel();
    }
}
