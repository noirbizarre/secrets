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

use secrets_core::{Backend, FieldKind};
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
    /// Every `SshKey` field across every vault, parsed as a private key.
    ///
    /// Returns an empty list while locked: identities are unavailable when
    /// the store is locked, by construction — this is the *only* place
    /// that decides that, so `request_identities` and `sign` cannot
    /// disagree about it.
    fn private_keys(&self) -> Vec<PrivateKey> {
        if !self.state.is_unlocked() {
            return Vec::new();
        }
        let Ok(vaults) = self.state.list_vaults() else {
            return Vec::new();
        };
        let mut keys = Vec::new();
        for vault in vaults {
            let Ok(items) = self.state.list_items(&vault.name) else {
                continue;
            };
            for item in items {
                for field in &item.fields {
                    if field.kind != FieldKind::SshKey {
                        continue;
                    }
                    let Ok(value) =
                        self.state
                            .backend()
                            .get_field(&vault.name, &item.path, &field.name)
                    else {
                        continue;
                    };
                    if let Ok(key) = PrivateKey::from_openssh(value.expose_secret()) {
                        keys.push(key);
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
        let runtime = match tokio::runtime::Runtime::new() {
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
