//! Detects a registered prompt provider's connection closing (a crash, or
//! any exit without calling `UnregisterProvider` first) via
//! `org.freedesktop.DBus`'s own `NameOwnerChanged` signal.
//!
//! Runs on a plain OS thread — no `tokio`, same rationale as
//! `secret_service::refresh`: `zbus::blocking`'s own signal-iterator API
//! is already synchronous from the caller's point of view, so a second
//! executor here would be pure overhead.

use std::sync::Arc;
use std::thread::JoinHandle;

use zbus::blocking::Connection;
use zbus::blocking::fdo::DBusProxy;
use zbus::names::UniqueName;

use super::broker::PromptBroker;

/// Start the watcher thread. Runs for the daemon's whole life, same as
/// `secret_service::refresh::spawn` — a failure to subscribe is only
/// ever logged, never fatal to `secretsd` starting: a headless daemon
/// with no prompt providers has nothing for this thread to watch anyway.
pub fn spawn(connection: Connection, broker: Arc<PromptBroker>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let proxy = match DBusProxy::new(&connection) {
            Ok(proxy) => proxy,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "could not reach org.freedesktop.DBus to watch for prompt provider \
                     disconnects — a vanished provider's requests will only resolve once \
                     their own timeout elapses"
                );
                return;
            }
        };
        let changes = match proxy.receive_name_owner_changed() {
            Ok(changes) => changes,
            Err(error) => {
                tracing::warn!(%error, "could not subscribe to NameOwnerChanged");
                return;
            }
        };
        for signal in changes {
            let Ok(args) = signal.args() else {
                continue;
            };
            // A connection closing reports its own unique name losing its
            // owner entirely (`new_owner` empty) — a well-known name
            // merely changing hands (`name` is not itself a unique name)
            // is not something a provider registration can be, so
            // `UniqueName::try_from` failing here is the expected way to
            // skip it, not an error.
            if args.new_owner().is_some() {
                continue;
            }
            let Ok(name) = UniqueName::try_from(args.name().as_str()) else {
                continue;
            };
            if broker
                .registered_provider_names()
                .iter()
                .any(|registered| *registered == name)
            {
                tracing::info!(provider = %name, "a registered prompt provider vanished");
                broker.handle_provider_vanished(&name);
            }
        }
    })
}
