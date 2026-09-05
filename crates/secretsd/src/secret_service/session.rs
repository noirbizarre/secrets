//! `org.freedesktop.Secret.Session`.
//!
//! One shared instance answers every `Service.OpenSession` call — see the
//! module-level doc on [`crate::secret_service`] for why that is
//! spec-compliant for the "plain" algorithm.

/// The shared session object.
#[derive(Default)]
pub struct SessionIface;

#[zbus::interface(name = "org.freedesktop.Secret.Session")]
impl SessionIface {
    /// Close the session.
    ///
    /// A no-op: the object is shared across every client, so there is
    /// nothing session-specific to release.
    fn close(&self) {}
}
