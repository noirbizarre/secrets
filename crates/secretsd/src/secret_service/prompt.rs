//! `org.freedesktop.Secret.Prompt`.
//!
//! One shared instance answers every operation that would need a real
//! interactive prompt, and immediately reports itself dismissed: the MVP
//! has no GUI agent to prompt with (that is `secrets-gtk`'s eventual job).
//! Callers that need to unlock or create a collection should use
//! `secrets unlock` instead — see `docs/dbus/secret-service.md`.

/// The shared, always-dismissed prompt object.
#[derive(Default)]
pub struct PromptIface;

#[zbus::interface(name = "org.freedesktop.Secret.Prompt")]
impl PromptIface {
    /// Would show the prompt; instead emits `Completed` as dismissed right
    /// away, since there is nothing in the MVP that can show it.
    async fn prompt(
        &self,
        _window_id: &str,
        #[zbus(signal_emitter)] emitter: zbus::object_server::SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        let result: zbus::zvariant::OwnedValue = zbus::zvariant::Value::from("")
            .try_into()
            .expect("an empty string always converts to an OwnedValue");
        Self::completed(&emitter, true, result).await?;
        Ok(())
    }

    /// Dismiss the prompt. Also a no-op: nothing was ever shown.
    fn dismiss(&self) {}

    /// Signalled once a prompt concludes. Always `dismissed = true` in this
    /// MVP.
    #[zbus(signal)]
    async fn completed(
        emitter: &zbus::object_server::SignalEmitter<'_>,
        dismissed: bool,
        result: zbus::zvariant::OwnedValue,
    ) -> zbus::Result<()>;
}
