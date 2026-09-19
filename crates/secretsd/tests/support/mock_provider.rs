//! An in-repo, D-Bus-speaking mock prompt provider.
//!
//! The only "provider" implementation in this workspace — a real one is a
//! separate, out-of-repo project (a future `secrets-prompt-gtk`; see
//! [ADR-017](../../../../docs/adr/017-prompt-broker-and-provider-protocol.md)).
//! This exists purely to exercise `org.secrets.PromptBroker1`/
//! `PromptProvider1`/`PromptRequest1` over a real D-Bus wire, the same
//! way `proxies.rs` exercises the standard Secret Service interfaces —
//! `secretsd`'s own unit tests (`prompt::broker`) already cover the
//! registry logic in-process; this is what proves the *wire* protocol
//! actually round-trips.
//!
//! Always connects as its own, second, independent connection to the
//! same private bus a [`super::TestDaemon`] runs on — a real provider is
//! always a separate process with its own unique D-Bus connection name,
//! and `secretsd` authenticates a provider by that name (see
//! `secretsd::prompt::broker_iface`), never by a self-reported argument.

use std::sync::mpsc;
use std::time::Duration;

use secrets_core::dbus::{PromptBroker1ProxyBlocking, PromptRequest1ProxyBlocking};
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

/// The mock provider's own object path, on its own connection. Only ever
/// needs to be one fixed path: a single [`MockProvider`] is not itself
/// meant to be concurrent-safe (tests using it drive one provider at a
/// time), unlike `secretsd`'s own per-request `PromptRequest1` paths.
const PROVIDER_PATH: &str = "/test/prompt/provider";

/// How long [`MockProvider::wait_for_request`] waits for `secretsd` to
/// call `HandleRequest` before panicking — generous relative to
/// `secretsd::prompt::broker::PROMPT_NOTIFY_TIMEOUT`, so a genuine
/// protocol regression fails loudly rather than racing that timeout.
const NOTIFY_WAIT: Duration = Duration::from_secs(5);

/// The server-side handler `secretsd` calls into. Every call is recorded
/// on `notified` — a channel a test reads from to learn a request
/// arrived (and its object path) without polling `secretsd`'s own state.
struct ProviderIface {
    notified: mpsc::Sender<OwnedObjectPath>,
}

#[zbus::interface(name = "org.secrets.PromptProvider1")]
impl ProviderIface {
    fn handle_request(&self, request: OwnedObjectPath) {
        // Best-effort: a test that dropped its `MockProvider` before
        // `secretsd` got around to notifying it (implicitly testing
        // "provider vanished mid-flight") must not panic *this* call —
        // the receiver being gone is exactly that scenario, not a bug.
        let _ = self.notified.send(request);
    }
}

/// A running mock prompt provider, registered with a [`super::TestDaemon`].
pub struct MockProvider {
    connection: zbus::blocking::Connection,
    notified: mpsc::Receiver<OwnedObjectPath>,
}

impl MockProvider {
    /// Connect to the private bus at `address`, register this process's
    /// own `PromptProvider1` object, then register with `secretsd`'s
    /// broker offering `capabilities` (see `secrets_core::prompt::kind`)
    /// at `priority`.
    ///
    /// # Panics
    ///
    /// If connecting, registering the local object, or registering with
    /// the broker fails — always a harness/test bug, never a condition a
    /// real caller of this test-only type needs to handle gracefully.
    #[must_use]
    pub fn register(address: &str, capabilities: &[&str], priority: i32) -> Self {
        let connection = zbus::blocking::connection::Builder::address(address)
            .expect("a dbus-daemon-printed address is always a valid zbus address")
            .build()
            .expect("connect the mock provider to the private session bus");

        let (notified_tx, notified) = mpsc::channel();
        connection
            .object_server()
            .at(
                PROVIDER_PATH,
                ProviderIface {
                    notified: notified_tx,
                },
            )
            .expect("register the mock provider's own PromptProvider1 object");

        let broker = PromptBroker1ProxyBlocking::new(&connection)
            .expect("construct a PromptBroker1 proxy over an already-open connection");
        broker
            .register_provider(
                ObjectPath::try_from(PROVIDER_PATH).expect("a fixed, valid object path"),
                capabilities.iter().map(ToString::to_string).collect(),
                priority,
            )
            .expect("register as a prompt provider");

        Self {
            connection,
            notified,
        }
    }

    /// Block until `secretsd` notifies this provider of a new request,
    /// returning a proxy for it.
    ///
    /// # Panics
    ///
    /// If no request arrives within [`NOTIFY_WAIT`].
    #[must_use]
    pub fn wait_for_request(&self) -> PromptRequest1ProxyBlocking<'_> {
        let path = self
            .notified
            .recv_timeout(NOTIFY_WAIT)
            .expect("secretsd notifies a registered, matching-capability provider promptly");
        PromptRequest1ProxyBlocking::builder(&self.connection)
            .path(path)
            .expect("a request path secretsd sent is always a valid object path")
            .build()
            .expect("build a PromptRequest1 proxy")
    }

    /// Unregister explicitly, over `UnregisterProvider` — distinct from
    /// [`MockProvider::vanish`], which simulates a crash instead.
    pub fn unregister(&self) {
        PromptBroker1ProxyBlocking::new(&self.connection)
            .expect("construct a PromptBroker1 proxy over an already-open connection")
            .unregister_provider()
            .expect("unregister as a prompt provider");
    }

    /// Disconnect abruptly without unregistering — simulates a provider
    /// process crashing, for
    /// `secretsd::prompt::broker::PromptBroker::handle_provider_vanished`.
    pub fn vanish(self) {
        drop(self.connection);
    }
}
