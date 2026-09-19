//! The background topology refresher — keeps the Secret Service
//! `Collection`/`Item` objects in sync with whatever the backend
//! currently reports, without ever blocking or failing daemon startup on
//! it. See [ADR-015](../../../../docs/adr/015-live-secret-service-topology.md).
//!
//! Runs on a plain OS thread, **not** its own `tokio` runtime (unlike
//! `crate::ssh_agent::spawn`, which needs one for `ssh-agent-lib`'s async
//! `Session` trait): `zbus::blocking`'s `ObjectServer::at`/`remove` and
//! `Connection::emit_signal` are already synchronous from the caller's
//! point of view (each wraps its own internal `block_on`), so a second
//! executor here would be pure overhead this daemon's "deliberately
//! synchronous" design otherwise avoids.

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

use secrets_core::StoreId;
use zbus::blocking::Connection;
use zbus::zvariant::OwnedObjectPath;

use super::collection::CollectionIface;
use super::item::ItemIface;
use super::{ALIAS_DEFAULT_PATH, LiveTopology, SERVICE_PATH, Topology, collection_path, discover};
use crate::state::DaemonState;

/// How often the refresher re-scans the backend for topology changes,
/// absent an explicit reactive trigger from `Manager.Unlock`/`Lock` (see
/// `crate::manager::ManagerIface`). Hardcoded for now, not a config knob
/// — see ADR-015's consequences.
const REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Start the background refresher. Runs the very first scan immediately
/// (no initial wait) — this is what lets `main.rs` finish starting up
/// without ever waiting for, or being able to fail because of, that scan:
/// a failed scan (initial or later) is only ever logged, never fatal, and
/// leaves the previous topology in place until the next attempt succeeds.
///
/// `trigger` lets another part of the daemon (`ManagerIface::unlock`/
/// `lock`) wake this loop immediately instead of waiting up to
/// `REFRESH_INTERVAL` — used for the one case that matters in practice:
/// the local backend's vault file being created for the first time.
pub fn spawn(
    connection: Connection,
    state: Arc<DaemonState>,
    topology: LiveTopology,
    trigger: mpsc::Receiver<()>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        loop {
            match discover(&state) {
                Ok(new) => reconcile(&connection, &state, &topology, new),
                Err(error) => {
                    tracing::warn!(
                        "Secret Service topology refresh failed, keeping the previous \
                         topology until the next attempt: {error}"
                    );
                }
            }
            match trigger.recv_timeout(REFRESH_INTERVAL) {
                Ok(()) | Err(RecvTimeoutError::Timeout) => {}
                // Defensive only: `trigger`'s sender is held by
                // `ManagerIface` for the daemon's whole life. If it were
                // ever dropped, fall back to sleeping the same interval
                // instead of busy-looping.
                Err(RecvTimeoutError::Disconnected) => std::thread::sleep(REFRESH_INTERVAL),
            }
        }
    })
}

/// Reconcile the live D-Bus object set (and the `"default"` alias) against
/// `new`, adding/removing `Collection`/`Item` objects and emitting the
/// standard Secret Service signals for each change, then replace
/// `topology` with `new`.
///
/// Every `object_server()` failure is logged, not propagated — one
/// object's registration failing must not abort reconciling the rest, nor
/// crash the refresher thread.
fn reconcile(
    connection: &Connection,
    state: &Arc<DaemonState>,
    topology: &LiveTopology,
    new: Topology,
) {
    let old = topology.snapshot();
    let object_server = connection.object_server();

    let old_vaults: HashSet<&(StoreId, String)> = old.vaults.iter().collect();
    let new_vaults: HashSet<&(StoreId, String)> = new.vaults.iter().collect();

    for (store, vault) in new.vaults.iter().filter(|pair| !old_vaults.contains(pair)) {
        let path = collection_path(store, vault);
        match object_server.at(
            &path,
            CollectionIface::new(
                state.clone(),
                store.clone(),
                vault.clone(),
                topology.clone(),
            ),
        ) {
            Ok(true) => emit(
                connection,
                SERVICE_PATH,
                "org.freedesktop.Secret.Service",
                "CollectionCreated",
                &path,
            ),
            // Already registered somehow (e.g. a concurrent reconcile) —
            // nothing changed, so nothing to announce.
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%store, vault, %error, "could not register a new Collection");
            }
        }
    }
    for (store, vault) in old.vaults.iter().filter(|pair| !new_vaults.contains(pair)) {
        let path = collection_path(store, vault);
        match object_server.remove::<CollectionIface, _>(&path) {
            Ok(true) => emit(
                connection,
                SERVICE_PATH,
                "org.freedesktop.Secret.Service",
                "CollectionDeleted",
                &path,
            ),
            Ok(false) => {}
            Err(error) => {
                tracing::warn!(%store, vault, %error, "could not remove a vanished Collection");
            }
        }
    }

    // Items: keyed by their (stable, per (store, vault, item, field)
    // quadruple) object path.
    let old_items: HashSet<&OwnedObjectPath> = old.items.iter().map(|known| &known.path).collect();
    let new_items: HashSet<&OwnedObjectPath> = new.items.iter().map(|known| &known.path).collect();

    for known in new
        .items
        .iter()
        .filter(|known| !old_items.contains(&known.path))
    {
        let collection = collection_path(&known.store, &known.vault);
        match object_server.at(
            &known.path,
            ItemIface::new(
                state.clone(),
                known.store.clone(),
                known.vault.clone(),
                known.item.clone(),
                known.field.clone(),
            ),
        ) {
            Ok(true) => emit(
                connection,
                collection.as_str(),
                "org.freedesktop.Secret.Collection",
                "ItemCreated",
                &known.path,
            ),
            Ok(false) => {}
            Err(error) => tracing::warn!(
                store = %known.store,
                vault = known.vault,
                item = %known.item,
                field = known.field,
                %error,
                "could not register a new Item",
            ),
        }
    }
    for known in old
        .items
        .iter()
        .filter(|known| !new_items.contains(&known.path))
    {
        let collection = collection_path(&known.store, &known.vault);
        match object_server.remove::<ItemIface, _>(&known.path) {
            Ok(true) => emit(
                connection,
                collection.as_str(),
                "org.freedesktop.Secret.Collection",
                "ItemDeleted",
                &known.path,
            ),
            Ok(false) => {}
            Err(error) => tracing::warn!(
                store = %known.store,
                vault = known.vault,
                item = %known.item,
                field = known.field,
                %error,
                "could not remove a vanished Item",
            ),
        }
    }

    reconcile_default_alias(connection, state, topology, &old, &new);

    topology.replace(new);
}

/// The `"default"` alias's collection is a *duplicate* registration of
/// whichever `(store, vault)` pair sorts first (ADR-013 item 2, redefined
/// by ADR-018 from "the first vault" to "the first `(store, vault)` pair"
/// over `Topology`'s own deterministic order), at its own literal path.
/// Because `CollectionIface` reads the shared `LiveTopology` live (not a
/// construction-time snapshot), it never needs re-registering just because
/// that vault's *items* changed — only when the *identity* of "the first
/// pair" itself changes (a pair was added before it in that order,
/// removed, or there were none and now there is one, or vice versa).
fn reconcile_default_alias(
    connection: &Connection,
    state: &Arc<DaemonState>,
    topology: &LiveTopology,
    old: &Topology,
    new: &Topology,
) {
    if old.vaults.first() == new.vaults.first() {
        return;
    }
    let object_server = connection.object_server();
    // Ignore "nothing was registered there" — this runs unconditionally
    // whenever the first pair changes, including from `None`.
    let _ = object_server.remove::<CollectionIface, _>(ALIAS_DEFAULT_PATH);
    if let Some((store, vault)) = new.vaults.first()
        && let Err(error) = object_server.at(
            ALIAS_DEFAULT_PATH,
            CollectionIface::new(
                state.clone(),
                store.clone(),
                vault.clone(),
                topology.clone(),
            ),
        )
    {
        tracing::warn!(%error, "could not re-register the \"default\" alias collection");
    }
}

/// Emit one of the standard Secret Service signals (`CollectionCreated`/
/// `CollectionDeleted`/`ItemCreated`/`ItemDeleted`), each carrying exactly
/// one object-path argument, per the specification.
///
/// Deliberately **not** emitted via a `#[zbus(signal)]` codegen'd method
/// (which needs an async `SignalEmitter`/`block_on` at the call site,
/// reintroducing exactly the executor this module's own doc comment
/// avoids) — `Connection::emit_signal` is already synchronous and
/// independent of any interface object.
fn emit(
    connection: &Connection,
    path: &str,
    interface: &str,
    signal_name: &str,
    arg: &OwnedObjectPath,
) {
    if let Err(error) =
        connection.emit_signal(None::<&str>, path, interface, signal_name, &(arg.clone(),))
    {
        tracing::warn!(
            path,
            interface,
            signal_name,
            %error,
            "could not emit a Secret Service topology-change signal",
        );
    }
}
