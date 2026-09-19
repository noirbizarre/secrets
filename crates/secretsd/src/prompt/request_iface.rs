//! `org.secrets.PromptRequest1` — one pending prompt request. One object
//! per in-flight request, created by [`super::broker::PromptBroker::submit`]
//! and removed by [`super::broker::PromptBroker::resolve`]. See
//! `secrets_core::dbus::PromptRequest1` for the client-side proxy trait
//! (what a provider implementation calls against this object).

use std::sync::Arc;

use secrets_core::SecretValue;
use secrets_core::dbus::PromptError;
use secrets_core::prompt::{PromptAnswer, PromptKind, PromptOutcome};
use zbus::zvariant::Value;

use super::broker::{PromptBroker, PromptId};

/// Validate `answer`'s shape against `kind` and build the corresponding
/// [`PromptAnswer`].
///
/// - `"unlock"` needs a string passphrase — wrapped as a [`SecretValue`]
///   immediately, so it exists un-redacted for as short a time as
///   possible on its way to `DaemonState::unlock`.
/// - `"choice"` needs a string naming one of the request's own offered
///   options verbatim; anything else is
///   [`PromptError::KindMismatch`] rather than silently accepted.
/// - `"confirmation"`/`"security-key"` need no payload at all: calling
///   `respond` (as opposed to `decline`/`cancel`) already means
///   "approved", so the answer value is ignored.
fn build_answer(kind: &PromptKind, answer: Value<'_>) -> Result<PromptAnswer, PromptError> {
    match kind {
        PromptKind::Unlock { .. } => {
            let passphrase = answer.downcast::<String>().map_err(|_| {
                PromptError::KindMismatch(
                    "an \"unlock\" answer must be a string passphrase".to_string(),
                )
            })?;
            Ok(PromptAnswer::Password(SecretValue::new(passphrase)))
        }
        PromptKind::Confirmation { .. } | PromptKind::SecurityKey { .. } => {
            Ok(PromptAnswer::Approved)
        }
        PromptKind::Choice { options, .. } => {
            let selected = answer.downcast::<String>().map_err(|_| {
                PromptError::KindMismatch("a \"choice\" answer must be a string".to_string())
            })?;
            if options.contains(&selected) {
                Ok(PromptAnswer::Selected(selected))
            } else {
                Err(PromptError::KindMismatch(format!(
                    "\"{selected}\" was not one of the offered options"
                )))
            }
        }
    }
}

/// One pending request's D-Bus object.
pub struct PromptRequestIface {
    broker: Arc<PromptBroker>,
    id: PromptId,
    kind: PromptKind,
}

impl PromptRequestIface {
    /// Wrap a request's identity and description as a servable interface.
    #[must_use]
    pub fn new(broker: Arc<PromptBroker>, id: PromptId, kind: PromptKind) -> Self {
        Self { broker, id, kind }
    }

    /// Resolve this request, translating an already-concluded request
    /// into [`PromptError::RequestNotFound`] rather than silently
    /// succeeding — a provider that races its own timeout should be able
    /// to tell the two apart.
    fn resolve(&self, outcome: PromptOutcome) -> Result<(), PromptError> {
        if self.broker.resolve(self.id, outcome) {
            Ok(())
        } else {
            Err(PromptError::RequestNotFound(
                "this request already concluded (answered, cancelled, timed out, or its \
                 provider vanished)"
                    .to_string(),
            ))
        }
    }
}

#[zbus::interface(name = "org.secrets.PromptRequest1")]
impl PromptRequestIface {
    /// See [`secrets_core::dbus::PromptRequest1::kind`].
    #[zbus(property)]
    fn kind(&self) -> String {
        self.kind.as_tag().to_string()
    }

    /// See [`secrets_core::dbus::PromptRequest1::title`].
    #[zbus(property)]
    fn title(&self) -> String {
        self.kind.title()
    }

    /// See [`secrets_core::dbus::PromptRequest1::description`].
    #[zbus(property)]
    fn description(&self) -> String {
        self.kind.description()
    }

    /// See [`secrets_core::dbus::PromptRequest1::options`].
    #[zbus(property)]
    fn options(&self) -> Vec<String> {
        self.kind.options()
    }

    /// See [`secrets_core::dbus::PromptRequest1::respond`].
    fn respond(&self, answer: Value<'_>) -> Result<(), PromptError> {
        let answer = build_answer(&self.kind, answer)?;
        self.resolve(PromptOutcome::Answered(answer))
    }

    /// See [`secrets_core::dbus::PromptRequest1::decline`].
    fn decline(&self) -> Result<(), PromptError> {
        self.resolve(PromptOutcome::Declined)
    }

    /// See [`secrets_core::dbus::PromptRequest1::cancel`].
    fn cancel(&self) -> Result<(), PromptError> {
        self.resolve(PromptOutcome::Cancelled)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unlock_answer_must_be_a_string() {
        let kind = PromptKind::Unlock {
            backend_name: "local".to_string(),
        };
        let error = build_answer(&kind, Value::from(42u32)).unwrap_err();
        assert!(matches!(error, PromptError::KindMismatch(_)));
    }

    #[test]
    fn an_unlock_answer_becomes_a_secret_value() {
        let kind = PromptKind::Unlock {
            backend_name: "local".to_string(),
        };
        let answer = build_answer(&kind, Value::from("hunter2")).unwrap();
        assert!(matches!(answer, PromptAnswer::Password(_)));
    }

    #[test]
    fn a_confirmation_answer_ignores_its_payload() {
        let kind = PromptKind::Confirmation {
            action: "read".to_string(),
            subject: "GitHub".to_string(),
        };
        let answer = build_answer(&kind, Value::from("")).unwrap();
        assert!(matches!(answer, PromptAnswer::Approved));
    }

    #[test]
    fn a_choice_answer_must_name_an_offered_option() {
        let kind = PromptKind::Choice {
            prompt: "Pick one".to_string(),
            options: vec!["yes".to_string(), "no".to_string()],
        };
        let selected = build_answer(&kind, Value::from("yes")).unwrap();
        assert!(matches!(selected, PromptAnswer::Selected(option) if option == "yes"));

        let error = build_answer(&kind, Value::from("maybe")).unwrap_err();
        assert!(matches!(error, PromptError::KindMismatch(_)));
    }
}
