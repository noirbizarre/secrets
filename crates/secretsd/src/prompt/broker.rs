//! [`PromptBroker`]: the registry of prompt providers and in-flight
//! requests. See the module doc (`super`) for the "nothing blocks"
//! invariant this file's threading exists to uphold.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::time::Duration;

use secrets_core::dbus::{PROMPT_REQUEST_PATH_PREFIX, PromptProvider1ProxyBlocking};
use secrets_core::prompt::{PromptKind, PromptOutcome};
use zbus::blocking::Connection;
use zbus::names::{OwnedUniqueName, UniqueName};
use zbus::zvariant::{ObjectPath, OwnedObjectPath};

use super::request_iface::PromptRequestIface;

/// How long a pending request waits for an answer before resolving as
/// [`PromptOutcome::TimedOut`]. Not a config knob — same status as
/// `secret_service::refresh::REFRESH_INTERVAL` — but overridable via
/// [`PROMPT_TIMEOUT_OVERRIDE_ENV`] for tests, the same "override env var
/// a real deployment never sets" pattern
/// `backend::onepassword::ffi::LIBRARY_PATH_OVERRIDE_ENV` already uses:
/// waiting out a real 120s in an automated test would make the suite
/// unusably slow.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Overrides [`PROMPT_TIMEOUT`], parsed as milliseconds. Unset or
/// unparsable falls back to [`PROMPT_TIMEOUT`] — see its own doc comment.
pub const PROMPT_TIMEOUT_OVERRIDE_ENV: &str = "SECRETS_PROMPT_TIMEOUT_MS";

/// How long the broker waits for the outbound `HandleRequest` call
/// itself to return — independent of, and much shorter than,
/// [`PROMPT_TIMEOUT`]: this only bounds "did the provider acknowledge
/// taking the request", not "did the user answer it". Mirrors
/// `crate::backend::onepassword::session::DEFAULT_AUTH_TIMEOUT`'s role
/// for a different external call.
pub const PROMPT_NOTIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// Overrides [`PROMPT_NOTIFY_TIMEOUT`], parsed as milliseconds — see
/// [`PROMPT_TIMEOUT_OVERRIDE_ENV`]'s own doc comment.
pub const PROMPT_NOTIFY_TIMEOUT_OVERRIDE_ENV: &str = "SECRETS_PROMPT_NOTIFY_TIMEOUT_MS";

/// Read `env_var` as a millisecond duration, falling back to `default` if
/// it is unset or not a valid non-negative integer.
fn duration_from_env_or(env_var: &str, default: Duration) -> Duration {
    std::env::var(env_var)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(default)
}

/// Opaque, process-local identifier for one pending prompt request.
///
/// Minted from a monotonic counter, not a UUID: uniqueness only needs to
/// hold for the lifetime of one `secretsd` process (it becomes an object
/// path segment), so a new dependency buys nothing here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PromptId(u64);

impl PromptId {
    /// The object path this request is (or was) registered at.
    #[must_use]
    pub fn object_path(self) -> OwnedObjectPath {
        format!("{PROMPT_REQUEST_PATH_PREFIX}/{}", self.0)
            .try_into()
            .expect("a decimal counter is always a valid object path segment")
    }
}

/// One registered provider.
#[derive(Clone)]
struct ProviderEntry {
    unique_name: OwnedUniqueName,
    object_path: OwnedObjectPath,
    capabilities: Vec<String>,
    priority: i32,
    /// Registration sequence number — lower (earlier) wins a priority
    /// tie, so the first provider to register for a capability is
    /// preferred over one that registers later at the same priority.
    registered_at: u64,
}

/// A completion callback, invoked exactly once, from whichever thread
/// learns the final [`PromptOutcome`] — never from inside a D-Bus
/// dispatch call (see the module doc).
type OnComplete = Box<dyn FnOnce(PromptOutcome) + Send>;

struct Pending {
    /// Which provider (if any) this request was routed to — `None` means
    /// it was resolved as [`PromptOutcome::NoProviderAvailable`] before
    /// any provider was ever notified, so there is nothing to watch for
    /// vanishing.
    routed_to: Option<OwnedUniqueName>,
    on_complete: Option<OnComplete>,
}

#[derive(Default)]
struct Registry {
    providers: Vec<ProviderEntry>,
    pending: HashMap<PromptId, Pending>,
    next_registration: u64,
}

/// Registration failures — mirrors [`secrets_core::dbus::PromptError`]'s
/// variants that are actually reachable from provider-facing D-Bus calls.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    /// The calling connection already has a provider registered.
    #[error("{0} is already registered as a prompt provider")]
    AlreadyRegistered(String),
}

/// The prompt broker: `secretsd`'s registry of providers and in-flight
/// requests, shared (`Arc`) with [`super::broker_iface::PromptBrokerIface`],
/// [`super::watcher`], and every Secret Service object that can trigger a
/// real prompt (`secret_service::prompt`, `secret_service::service`).
///
/// Constructed in two steps, like `secret_service`'s own topology
/// refresher is *wired* in two steps (`main.rs` builds `LiveTopology`
/// before the connection exists, then hands `refresh::spawn` the real
/// `Connection` once it does): a `PromptBroker` must be servable
/// (`serve_at(PROMPT_BROKER_PATH, ...)`) *before*
/// `zbus::blocking::connection::Builder::build()` returns a `Connection`
/// at all, so it cannot require one at construction time. Every method
/// that needs the connection is only ever reachable via an inbound D-Bus
/// call, which cannot happen before `build()` completes — so by the time
/// any of them run, [`PromptBroker::set_connection`] is guaranteed to
/// have already been called.
pub struct PromptBroker {
    connection: OnceLock<Connection>,
    registry: Mutex<Registry>,
    next_id: AtomicU64,
    prompt_timeout: Duration,
    notify_timeout: Duration,
}

impl Default for PromptBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl PromptBroker {
    /// A fresh, empty broker with no connection yet — see the struct's
    /// own doc comment.
    #[must_use]
    pub fn new() -> Self {
        Self {
            connection: OnceLock::new(),
            registry: Mutex::new(Registry::default()),
            next_id: AtomicU64::new(0),
            prompt_timeout: duration_from_env_or(PROMPT_TIMEOUT_OVERRIDE_ENV, PROMPT_TIMEOUT),
            notify_timeout: duration_from_env_or(
                PROMPT_NOTIFY_TIMEOUT_OVERRIDE_ENV,
                PROMPT_NOTIFY_TIMEOUT,
            ),
        }
    }

    /// Supply the real connection, once, right after
    /// `zbus::blocking::connection::Builder::build()` returns.
    ///
    /// # Panics
    ///
    /// Panics if called more than once — a programming error in `main.rs`
    /// wiring, not a runtime condition any caller can trigger.
    pub fn set_connection(&self, connection: Connection) {
        self.connection
            .set(connection)
            .unwrap_or_else(|_| panic!("PromptBroker::set_connection must be called exactly once"));
    }

    fn connection(&self) -> &Connection {
        self.connection.get().expect(
            "PromptBroker::set_connection is always called right after main.rs's connection \
             builder returns, before any D-Bus call could possibly reach this broker",
        )
    }

    /// Register `sender` as a provider offering `capabilities` (a subset
    /// of [`secrets_core::prompt::kind`]'s tags) at `priority`, reachable
    /// at `object_path` on `sender`'s own connection.
    ///
    /// # Errors
    ///
    /// Returns [`RegisterError::AlreadyRegistered`] if `sender` already
    /// has a registration — call [`PromptBroker::unregister_provider`]
    /// first to replace it, rather than silently overwriting.
    pub fn register_provider(
        &self,
        sender: OwnedUniqueName,
        object_path: OwnedObjectPath,
        capabilities: Vec<String>,
        priority: i32,
    ) -> Result<(), RegisterError> {
        let mut registry = self.registry.lock().expect("poisoned");
        if registry
            .providers
            .iter()
            .any(|provider| provider.unique_name == sender)
        {
            return Err(RegisterError::AlreadyRegistered(sender.to_string()));
        }
        let registered_at = registry.next_registration;
        registry.next_registration += 1;
        registry.providers.push(ProviderEntry {
            unique_name: sender,
            object_path,
            capabilities,
            priority,
            registered_at,
        });
        Ok(())
    }

    /// Remove `sender`'s registration, if any. A no-op if it was never
    /// registered — same "harmless no-op" contract as the Secret Service
    /// `Session.Close`/`Prompt.Dismiss` methods.
    ///
    /// Does **not** resolve any pending requests already routed to
    /// `sender` — an explicit unregistration is not the same as vanishing
    /// mid-request (see [`PromptBroker::handle_provider_vanished`]), and a
    /// well-behaved provider is expected to answer or cancel its own
    /// in-flight requests before unregistering.
    pub fn unregister_provider(&self, sender: &UniqueName<'_>) {
        let mut registry = self.registry.lock().expect("poisoned");
        registry
            .providers
            .retain(|provider| provider.unique_name != *sender);
    }

    /// Every unique name currently registered as a provider — used by
    /// [`super::watcher`] to know which `NameOwnerChanged` signals matter.
    #[must_use]
    pub fn registered_provider_names(&self) -> Vec<OwnedUniqueName> {
        self.registry
            .lock()
            .expect("poisoned")
            .providers
            .iter()
            .map(|provider| provider.unique_name.clone())
            .collect()
    }

    /// `sender`'s connection closed or its name was otherwise lost mid-way
    /// through owning a registration. Removes it from the registry and
    /// resolves every request that was routed to it as
    /// [`PromptOutcome::ProviderVanished`] — see ADR-017's "provider
    /// disappearance leaves the daemon in a deterministic state"
    /// acceptance criterion.
    pub fn handle_provider_vanished(&self, sender: &UniqueName<'_>) {
        let stranded: Vec<PromptId> = {
            let mut registry = self.registry.lock().expect("poisoned");
            registry
                .providers
                .retain(|provider| provider.unique_name != *sender);
            registry
                .pending
                .iter()
                .filter(|(_, pending)| {
                    pending
                        .routed_to
                        .as_ref()
                        .is_some_and(|name| *name == *sender)
                })
                .map(|(id, _)| *id)
                .collect()
        };
        for id in stranded {
            self.resolve(id, PromptOutcome::ProviderVanished);
        }
    }

    /// Submit a new prompt request. **Never blocks** (see the module
    /// doc): if no registered provider supports `kind`'s capability tag,
    /// `on_complete` runs inline, right here, with
    /// [`PromptOutcome::NoProviderAvailable`], and this returns `None` —
    /// this is the path that keeps a headless `secretsd` functional.
    /// Otherwise, the highest-priority matching provider (ties broken by
    /// whichever registered first) is notified on its own thread, a
    /// per-request timeout thread is started, `on_complete` is deferred
    /// until [`PromptBroker::resolve`] is eventually called (by the
    /// provider's own `Respond`/`Decline`/`Cancel` call, by the timeout
    /// thread, or by [`PromptBroker::handle_provider_vanished`]), and this
    /// returns `Some` of the request's id — a caller that wants to be
    /// able to cancel it later (e.g.
    /// `secret_service::prompt::UnlockPrompt::cancel`) should hold on to
    /// it.
    pub fn submit(
        self: &Arc<Self>,
        kind: PromptKind,
        on_complete: impl FnOnce(PromptOutcome) + Send + 'static,
    ) -> Option<PromptId> {
        let tag = kind.as_tag();
        let selected = {
            let registry = self.registry.lock().expect("poisoned");
            registry
                .providers
                .iter()
                .filter(|provider| provider.capabilities.iter().any(|c| c == tag))
                .max_by_key(|provider| {
                    (provider.priority, std::cmp::Reverse(provider.registered_at))
                })
                .cloned()
        };
        let Some(provider) = selected else {
            on_complete(PromptOutcome::NoProviderAvailable);
            return None;
        };

        let id = PromptId(self.next_id.fetch_add(1, Ordering::SeqCst));
        {
            let mut registry = self.registry.lock().expect("poisoned");
            registry.pending.insert(
                id,
                Pending {
                    routed_to: Some(provider.unique_name.clone()),
                    on_complete: Some(Box::new(on_complete)),
                },
            );
        }

        let path = id.object_path();
        if let Err(error) = self
            .connection()
            .object_server()
            .at(&path, PromptRequestIface::new(Arc::clone(self), id, kind))
        {
            tracing::warn!(%error, "could not register a PromptRequest1 object");
            self.resolve(id, PromptOutcome::NoProviderAvailable);
            return None;
        }

        let broker = Arc::clone(self);
        let prompt_timeout = self.prompt_timeout;
        std::thread::spawn(move || {
            std::thread::sleep(prompt_timeout);
            broker.resolve(id, PromptOutcome::TimedOut);
        });

        let broker = Arc::clone(self);
        let connection = self.connection().clone();
        let notify_timeout = self.notify_timeout;
        std::thread::spawn(move || {
            if let Err(error) = notify_provider_bounded(
                &connection,
                &provider.unique_name,
                &provider.object_path,
                path.as_ref(),
                notify_timeout,
            ) {
                tracing::warn!(
                    provider = %provider.unique_name,
                    %error,
                    "prompt provider did not accept a new request in time"
                );
                broker.resolve(id, PromptOutcome::NoProviderAvailable);
            }
        });

        Some(id)
    }

    /// The single choke point every path that concludes a request goes
    /// through: the provider's own `Respond`/`Decline`/`Cancel`, the
    /// per-request timeout thread, and
    /// [`PromptBroker::handle_provider_vanished`] all call this. Removes
    /// the `PromptRequest1` object and the pending entry, then invokes
    /// `on_complete` exactly once — whichever caller reaches this first
    /// for a given `id` wins; every later call (e.g. a timeout firing
    /// just after a late `Respond`) is a harmless no-op, reported back via
    /// the returned `bool` so a D-Bus method handler can turn a *second*
    /// call into `org.secrets.Prompt.Error.RequestNotFound`.
    pub fn resolve(&self, id: PromptId, outcome: PromptOutcome) -> bool {
        let on_complete = {
            let mut registry = self.registry.lock().expect("poisoned");
            match registry.pending.remove(&id) {
                Some(mut pending) => pending.on_complete.take(),
                None => return false,
            }
        };
        let _ = self
            .connection()
            .object_server()
            .remove::<PromptRequestIface, _>(id.object_path());
        if let Some(on_complete) = on_complete {
            on_complete(outcome);
        }
        true
    }
}

/// Call `object_path.HandleRequest(request)` on `provider`, bounded by
/// `notify_timeout` (normally [`PROMPT_NOTIFY_TIMEOUT`], shorter under the
/// test-only override — see [`PROMPT_NOTIFY_TIMEOUT_OVERRIDE_ENV`]) —
/// mirrors `crate::backend::onepassword::session`'s own `run_with_timeout`
/// helper for the same reason: a blocking D-Bus call to an external
/// process must never be allowed to hang the caller forever.
fn notify_provider_bounded(
    connection: &Connection,
    provider: &UniqueName<'_>,
    object_path: &OwnedObjectPath,
    request: ObjectPath<'_>,
    notify_timeout: Duration,
) -> Result<(), String> {
    let (sender, receiver) = mpsc::channel();
    let connection = connection.clone();
    let provider = provider.to_string();
    let object_path = object_path.to_string();
    let request = request.to_owned();
    let spawned = std::thread::Builder::new()
        .name("prompt-notify".to_string())
        .spawn(move || {
            let result = (|| -> Result<(), String> {
                let proxy = PromptProvider1ProxyBlocking::builder(&connection)
                    .destination(provider.as_str())
                    .map_err(|error| error.to_string())?
                    .path(object_path.as_str())
                    .map_err(|error| error.to_string())?
                    .build()
                    .map_err(|error| error.to_string())?;
                proxy
                    .handle_request(request.as_ref())
                    .map_err(|error| error.to_string())
            })();
            let _ = sender.send(result);
        });
    if let Err(error) = spawned {
        return Err(format!("could not start a worker thread: {error}"));
    }
    match receiver.recv_timeout(notify_timeout) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err("timed out".to_string()),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err("the notify worker thread ended without a result".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider_entry(name: &str, priority: i32, registered_at: u64) -> ProviderEntry {
        ProviderEntry {
            unique_name: UniqueName::try_from(name).unwrap().into(),
            object_path: OwnedObjectPath::try_from("/provider").unwrap(),
            capabilities: vec!["unlock".to_string()],
            priority,
            registered_at,
        }
    }

    #[test]
    fn a_prompt_id_round_trips_through_its_own_object_path() {
        let id = PromptId(7);
        assert_eq!(
            id.object_path().as_str(),
            format!("{PROMPT_REQUEST_PATH_PREFIX}/7")
        );
    }

    #[test]
    fn provider_selection_prefers_higher_priority() {
        let providers = [provider_entry(":1.1", 0, 0), provider_entry(":1.2", 10, 1)];
        let selected = providers
            .iter()
            .max_by_key(|p| (p.priority, std::cmp::Reverse(p.registered_at)))
            .unwrap();
        assert_eq!(selected.unique_name.as_str(), ":1.2");
    }

    #[test]
    fn provider_selection_breaks_priority_ties_by_earliest_registration() {
        let providers = [provider_entry(":1.1", 5, 0), provider_entry(":1.2", 5, 1)];
        let selected = providers
            .iter()
            .max_by_key(|p| (p.priority, std::cmp::Reverse(p.registered_at)))
            .unwrap();
        assert_eq!(
            selected.unique_name.as_str(),
            ":1.1",
            "the earlier registration must win a priority tie"
        );
    }

    #[test]
    fn an_empty_registry_never_matches_any_capability() {
        let registry = Registry::default();
        assert!(registry.pending.is_empty());
        assert!(registry.providers.is_empty());
    }
}
