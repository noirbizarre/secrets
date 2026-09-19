//! The daemon's SSH agent: the standard `ssh-agent` wire protocol over a
//! Unix socket under `$XDG_RUNTIME_DIR`, backed by `SshKey` fields from the
//! same vaults `org.secrets.Manager` resolves.
//!
//! Uses `ssh-agent-lib` for the protocol/socket handling and `ssh-key` for
//! parsing and signing — no hand-rolled protocol or cryptography (see
//! ADR-0007). Private key material never leaves this module: signing
//! happens here, and only the signature crosses back to the client.
//!
//! `ssh-agent-lib` requires an async runtime; everything else in this
//! daemon is deliberately synchronous (see `main.rs`), so this module runs
//! on its own `tokio` runtime, in its own thread — the one place async
//! complexity is required, confined to where it is required.

use std::path::PathBuf;
use std::sync::Arc;

use secrets_core::FieldKind;
use signature::Signer;
use ssh_agent_lib::agent::{Session, listen};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, SignRequest};
use ssh_key::{PrivateKey, Signature};

use crate::state::DaemonState;

/// One SSH agent connection's handler.
///
/// Cloned per incoming connection by `ssh-agent-lib` (see its own docs) —
/// cheap, since it only clones an `Arc`.
#[derive(Clone)]
struct SecretsAgent {
    state: Arc<DaemonState>,
}

impl SecretsAgent {
    /// Every `SshKey` field across every accessible store's vaults,
    /// parsed as a private key (ADR-018).
    ///
    /// A store contributes zero identities while inaccessible: unavailable
    /// when that store is locked *or* its own session needs
    /// (re)authentication (see [`DaemonState::is_accessible`]) — this is
    /// the *only* place that decides that, so `request_identities` and
    /// `sign` cannot disagree about it. A store failing to list its own
    /// vaults/items is likewise skipped, not fatal to the others.
    fn private_keys(&self) -> Vec<PrivateKey> {
        let mut keys = Vec::new();
        for store in self.state.store_ids() {
            if !self.state.is_accessible(store) {
                continue;
            }
            let Ok(vaults) = self.state.list_vaults(store) else {
                continue;
            };
            for vault in vaults {
                let Ok(items) = self.state.list_items(Some(store), &vault.name) else {
                    continue;
                };
                for item in items {
                    for field in &item.fields {
                        if field.kind != FieldKind::SshKey {
                            continue;
                        }
                        let Ok(value) =
                            self.state
                                .read_field(store, &vault.name, &item.path, &field.name)
                        else {
                            continue;
                        };
                        match PrivateKey::from_openssh(value.expose_secret()) {
                            Ok(key) => keys.push(key),
                            Err(error) => {
                                // Never logs `value` itself — only which
                                // field failed and why parsing it failed.
                                // A backend reporting `FieldKind::SshKey`
                                // whose value isn't actually
                                // OpenSSH-formatted text (see
                                // `docs/backends/1password.md`'s note on
                                // this) would otherwise vanish from the
                                // agent with no trace at all.
                                tracing::warn!(
                                    store = %store,
                                    vault = %vault.name,
                                    item = %item.path,
                                    field = %field.name,
                                    %error,
                                    "an SshKey field's value could not be parsed as an OpenSSH private key; skipping it",
                                );
                            }
                        }
                    }
                }
            }
        }
        keys
    }
}

#[ssh_agent_lib::async_trait]
impl Session for SecretsAgent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Ok(self
            .private_keys()
            .into_iter()
            .map(|key| Identity {
                credential: key.public_key().key_data().clone().into(),
                comment: key.comment().to_string(),
            })
            .collect())
    }

    async fn sign(&mut self, request: SignRequest) -> Result<Signature, AgentError> {
        let key = self
            .private_keys()
            .into_iter()
            .find(|key| key.public_key().key_data() == request.credential.key_data())
            .ok_or_else(|| {
                AgentError::other(std::io::Error::other(
                    "no matching identity (locked, or unknown key)",
                ))
            })?;
        key.try_sign(&request.data)
            .map_err(|error| AgentError::other(std::io::Error::other(error.to_string())))
    }

    async fn remove_identity(
        &mut self,
        _identity: ssh_agent_lib::proto::message::RemoveIdentity,
    ) -> Result<(), AgentError> {
        // Identities come from the backend, not an in-memory add-list — an
        // agent-side "remove" has nothing to do without deleting the
        // underlying field, which this compatibility surface does not do.
        // Reporting success rather than "unsupported" matches what
        // `ssh-add -d` expects from a well-behaved agent.
        Ok(())
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        Ok(())
    }
}

/// Run the SSH agent, listening on `socket_path`, until the process exits.
///
/// Spawns its own thread and `tokio` runtime; the caller does not need one.
pub fn spawn(state: Arc<DaemonState>, socket_path: PathBuf) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        // A current-thread runtime, not the multi-threaded default: this
        // agent has no CPU-bound or parallel work, only I/O-bound waiting
        // on the socket, so a worker pool would just be idle threads this
        // component doesn't need (see ADR-007's "one extra thread" intent).
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                tracing::error!("SSH agent: could not start its runtime: {error}");
                return;
            }
        };
        runtime.block_on(async move {
            // A stale socket from a previous run would otherwise make
            // `bind` fail with "address in use".
            let _ = std::fs::remove_file(&socket_path);
            let listener = match tokio::net::UnixListener::bind(&socket_path) {
                Ok(listener) => listener,
                Err(error) => {
                    tracing::error!(
                        "SSH agent: could not bind {}: {error}",
                        socket_path.display()
                    );
                    return;
                }
            };
            tracing::info!("SSH agent listening on {}", socket_path.display());
            if let Err(error) = listen(listener, SecretsAgent { state }).await {
                tracing::error!("SSH agent stopped: {error}");
            }
        });
    })
}

#[cfg(test)]
mod tests {
    use secrets_core::BackendStatus;

    use super::*;
    use crate::test_support::{
        default_store_id, state_over_fresh_vault, state_with_backend_session,
    };

    #[test]
    fn private_keys_is_empty_while_locked() {
        let (_dir, state) = state_over_fresh_vault();
        let agent = SecretsAgent {
            state: Arc::new(state),
        };
        assert!(agent.private_keys().is_empty());
    }

    #[test]
    fn private_keys_is_empty_when_the_backend_session_requires_authentication() {
        // Regression guard for #7: an `AlwaysUnlocked` backend (like
        // 1Password) must not surface identities while its own session is
        // unmet, even though that store's own passphrase lock alone would
        // allow it.
        let (_dir, state) = state_with_backend_session(BackendStatus::RequiresAuthentication);
        state
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();
        let agent = SecretsAgent {
            state: Arc::new(state),
        };
        assert!(agent.private_keys().is_empty());
    }

    #[test]
    fn private_keys_reports_the_demo_vaults_ssh_key_once_accessible() {
        // Confirms the accessible path runs to completion
        // (list_vaults/list_items/read_field/from_openssh) end to end
        // against the demo vault's seeded `Infrastructure/Production/
        // ssh-key` field.
        let (_dir, state) = state_over_fresh_vault();
        state
            .unlock(&default_store_id(), "test passphrase")
            .unwrap();
        let agent = SecretsAgent {
            state: Arc::new(state),
        };
        assert_eq!(agent.private_keys().len(), 1);
    }

    #[test]
    fn private_keys_aggregates_identities_across_every_accessible_store() {
        let (_dirs, state, store_a, store_b) =
            crate::test_support::state_over_two_local_stores_with_a_colliding_vault();
        state.unlock(&store_a, "a passphrase").unwrap();
        state.unlock(&store_b, "b passphrase").unwrap();
        let agent = SecretsAgent {
            state: Arc::new(state),
        };
        // Each store's fixture vault has its own distinct `ssh-key`
        // field — both must be reported once both stores are unlocked.
        assert_eq!(agent.private_keys().len(), 2);
    }

    #[test]
    fn private_keys_skips_only_the_locked_store_not_every_store() {
        let (_dirs, state, store_a, _store_b) =
            crate::test_support::state_over_two_local_stores_with_a_colliding_vault();
        // Only store_a is unlocked; store_b stays locked and must
        // contribute zero identities without blocking store_a's own.
        state.unlock(&store_a, "a passphrase").unwrap();
        let agent = SecretsAgent {
            state: Arc::new(state),
        };
        assert_eq!(agent.private_keys().len(), 1);
    }
}
