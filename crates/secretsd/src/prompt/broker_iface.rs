//! `org.secrets.PromptBroker1` — how an external prompt provider
//! registers/unregisters itself with `secretsd`. See
//! `secrets_core::dbus::PromptBroker1` for the client-side proxy trait
//! and the wire contract's full doc.

use std::sync::Arc;

use secrets_core::dbus::{PROMPT_PROTOCOL_VERSION, PromptError};
use zbus::message::Header;
use zbus::zvariant::ObjectPath;

use super::broker::{PromptBroker, RegisterError};

/// The object served at `secrets_core::dbus::PROMPT_BROKER_PATH`.
pub struct PromptBrokerIface {
    broker: Arc<PromptBroker>,
}

impl PromptBrokerIface {
    /// Wrap the shared broker as a servable interface.
    #[must_use]
    pub fn new(broker: Arc<PromptBroker>) -> Self {
        Self { broker }
    }
}

#[zbus::interface(name = "org.secrets.PromptBroker1")]
impl PromptBrokerIface {
    /// See [`secrets_core::dbus::PromptBroker1::register_provider`].
    ///
    /// The registering identity is always the D-Bus message's own sender
    /// (its unique connection name, from `header`), never a
    /// caller-supplied argument — a provider cannot register or
    /// unregister on another connection's behalf. `secretsd` only ever
    /// serves this interface over the session bus (ADR-001), which always
    /// assigns every connection a unique name, so a missing sender is not
    /// a case a real caller can trigger.
    fn register_provider(
        &self,
        object_path: ObjectPath<'_>,
        capabilities: Vec<String>,
        priority: i32,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<u32, PromptError> {
        let sender = header
            .sender()
            .expect("secretsd only serves org.secrets.PromptBroker1 over the session bus, which always assigns a sender its own unique name")
            .to_owned()
            .into();
        self.broker
            .register_provider(sender, object_path.into(), capabilities, priority)
            .map_err(|error| match error {
                RegisterError::AlreadyRegistered(name) => PromptError::AlreadyRegistered(name),
            })?;
        Ok(PROMPT_PROTOCOL_VERSION)
    }

    /// See [`secrets_core::dbus::PromptBroker1::unregister_provider`].
    fn unregister_provider(&self, #[zbus(header)] header: Header<'_>) {
        if let Some(sender) = header.sender() {
            self.broker.unregister_provider(sender);
        }
    }
}
