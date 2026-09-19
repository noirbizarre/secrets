//! Toolkit-independent prompt broker types.
//!
//! These types describe *what* is being asked of a human and *what* came
//! back — never *how* it is shown. Nothing here knows GTK, Qt, a
//! terminal, or `secretsd`'s own implementation exists (see the crate's
//! own doc comment) — that is exactly the point: a desktop-specific
//! prompt provider (a separate, out-of-repo process, e.g. a future
//! `secrets-prompt-gtk`) and `secretsd` itself both build against this
//! same, shared vocabulary. See
//! [ADR-017](../../../../docs/adr/017-prompt-broker-and-provider-protocol.md)
//! for the full design and `secrets_core::dbus` for the wire protocol
//! built on top of it.

use crate::secret_value::SecretValue;

/// Stable string tags identifying a [`PromptKind`] — used both in a
/// provider's registered capabilities and in a live request's `Kind`
/// property over D-Bus.
///
/// Plain strings, not a D-Bus enum: a future kind is additive (a new
/// constant, a new [`PromptKind`] variant), never a breaking wire-format
/// change for providers that don't yet know it exists — see ADR-017's
/// versioning rationale.
pub mod kind {
    /// [`PromptKind::Unlock`].
    pub const UNLOCK: &str = "unlock";
    /// [`PromptKind::Confirmation`].
    pub const CONFIRMATION: &str = "confirmation";
    /// [`PromptKind::Choice`].
    pub const CHOICE: &str = "choice";
    /// [`PromptKind::SecurityKey`].
    pub const SECURITY_KEY: &str = "security-key";
}

/// What a prompt is asking for.
///
/// Every field here is a name or a description, never a secret value —
/// this is the request a provider renders as UI, and it crosses the bus
/// to a process outside `secretsd`'s own trust boundary before any answer
/// exists (see `docs/security.md`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptKind {
    /// A passphrase is needed to unlock something. `backend_name` names
    /// what is being unlocked (e.g. the configured backend), never a
    /// vault's contents.
    Unlock {
        /// The backend (or vault) this unlock is for, for display only.
        backend_name: String,
    },
    /// A yes/no confirmation for an action about to happen.
    Confirmation {
        /// A short label for the action being confirmed (e.g.
        /// `"read a secret"`).
        action: String,
        /// What the action would affect (e.g. an application name or a
        /// vault/item name) — never the secret value itself.
        subject: String,
    },
    /// A choice among a fixed set of named options.
    Choice {
        /// The question being asked.
        prompt: String,
        /// The offered options; a [`PromptAnswer::Selected`] must name
        /// one of these verbatim.
        options: Vec<String>,
    },
    /// Approval via a security key / hardware authenticator. `secretsd`
    /// has no notion of the challenge/response protocol itself here —
    /// that is backend-specific and out of this type's scope; this only
    /// carries what a provider needs to *tell the user* something is
    /// pending.
    SecurityKey {
        /// The backend requesting hardware approval, for display only.
        backend_name: String,
        /// A human-readable description of what is being approved.
        challenge_description: String,
    },
}

impl PromptKind {
    /// The stable string tag for this kind (one of the [`kind`]
    /// constants) — what a provider's registered capabilities and a
    /// request's `Kind` D-Bus property both use.
    #[must_use]
    pub fn as_tag(&self) -> &'static str {
        match self {
            Self::Unlock { .. } => kind::UNLOCK,
            Self::Confirmation { .. } => kind::CONFIRMATION,
            Self::Choice { .. } => kind::CHOICE,
            Self::SecurityKey { .. } => kind::SECURITY_KEY,
        }
    }

    /// A short, human-readable title for the request (the `Title`
    /// property) — never derived from a secret value.
    #[must_use]
    pub fn title(&self) -> String {
        match self {
            Self::Unlock { backend_name } => format!("Unlock {backend_name}"),
            Self::Confirmation { action, .. } => format!("Confirm: {action}"),
            Self::Choice { prompt, .. } => prompt.clone(),
            Self::SecurityKey { backend_name, .. } => {
                format!("Security key approval for {backend_name}")
            }
        }
    }

    /// A longer, human-readable description (the `Description`
    /// property) — never derived from a secret value.
    #[must_use]
    pub fn description(&self) -> String {
        match self {
            Self::Unlock { backend_name } => {
                format!("Enter the passphrase to unlock {backend_name}.")
            }
            Self::Confirmation { action, subject } => {
                format!("Allow \"{subject}\" to {action}?")
            }
            Self::Choice { .. } => String::new(),
            Self::SecurityKey {
                challenge_description,
                ..
            } => challenge_description.clone(),
        }
    }

    /// The offered options (the `Options` property) — only ever
    /// non-empty for [`PromptKind::Choice`].
    #[must_use]
    pub fn options(&self) -> Vec<String> {
        match self {
            Self::Choice { options, .. } => options.clone(),
            _ => Vec::new(),
        }
    }
}

/// A provider's positive answer to a prompt.
///
/// Only [`PromptAnswer::Password`] ever carries a secret — it exists for
/// exactly as long as it takes the receiving code (`DaemonState::unlock`)
/// to consume it (see [`SecretValue`]'s own `Zeroize`/`ZeroizeOnDrop`
/// guarantee).
#[derive(Clone)]
pub enum PromptAnswer {
    /// The passphrase for a [`PromptKind::Unlock`] request.
    Password(SecretValue),
    /// A plain "yes"/"approved" for [`PromptKind::Confirmation`] or
    /// [`PromptKind::SecurityKey`] — those kinds carry no further payload.
    Approved,
    /// The chosen option for a [`PromptKind::Choice`] request. Must be one
    /// of the offered [`PromptKind::options`]; the receiving side is
    /// responsible for validating that, not this type.
    Selected(String),
}

impl std::fmt::Debug for PromptAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Mirrors `SecretValue`'s own redacted `Debug`: a stray
        // `{:?}` on a `PromptAnswer` (e.g. in a log statement) must not
        // leak a passphrase.
        match self {
            Self::Password(_) => f.write_str("Password(REDACTED)"),
            Self::Approved => f.write_str("Approved"),
            Self::Selected(option) => f.debug_tuple("Selected").field(option).finish(),
        }
    }
}

/// How a prompt request concluded.
///
/// Every variant here is safe to log or return in an error — see
/// [`crate::error::CoreError`]'s own doc comment for the same discipline.
/// Only [`PromptOutcome::Answered`] can carry a secret, and only via
/// [`PromptAnswer::Password`].
#[derive(Debug)]
pub enum PromptOutcome {
    /// The provider returned an answer.
    Answered(PromptAnswer),
    /// The user explicitly declined (e.g. "No" on a confirmation).
    Declined,
    /// The user dismissed the prompt without answering.
    Cancelled,
    /// No answer arrived before the request's timeout elapsed.
    TimedOut,
    /// No provider is registered for this kind (or none could be reached)
    /// — the path that keeps a headless `secretsd` functional: this is
    /// returned immediately, never left pending.
    NoProviderAvailable,
    /// The provider that was handling this request disappeared (its
    /// D-Bus connection closed) before answering.
    ProviderVanished,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prompt_kind_tag_matches_its_own_kind_constant() {
        assert_eq!(
            PromptKind::Unlock {
                backend_name: "local".to_string()
            }
            .as_tag(),
            kind::UNLOCK
        );
        assert_eq!(
            PromptKind::Confirmation {
                action: "read".to_string(),
                subject: "GitHub".to_string()
            }
            .as_tag(),
            kind::CONFIRMATION
        );
        assert_eq!(
            PromptKind::Choice {
                prompt: "Pick one".to_string(),
                options: vec![]
            }
            .as_tag(),
            kind::CHOICE
        );
        assert_eq!(
            PromptKind::SecurityKey {
                backend_name: "1password".to_string(),
                challenge_description: "tap your key".to_string()
            }
            .as_tag(),
            kind::SECURITY_KEY
        );
    }

    #[test]
    fn only_choice_reports_non_empty_options() {
        let unlock = PromptKind::Unlock {
            backend_name: "local".to_string(),
        };
        assert!(unlock.options().is_empty());

        let choice = PromptKind::Choice {
            prompt: "Pick one".to_string(),
            options: vec!["a".to_string(), "b".to_string()],
        };
        assert_eq!(choice.options(), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn debug_formatting_a_password_answer_never_prints_the_value() {
        let answer = PromptAnswer::Password(SecretValue::new("hunter2".to_string()));
        let debug = format!("{answer:?}");
        assert_eq!(debug, "Password(REDACTED)");
        assert!(!debug.contains("hunter2"));
    }

    #[test]
    fn debug_formatting_a_selected_answer_prints_the_chosen_option() {
        // Unlike `Password`, a `Selected` option is never secret — it must
        // name one of the prompt's own offered, non-secret options, so
        // there is nothing to redact.
        let answer = PromptAnswer::Selected("yes".to_string());
        assert_eq!(format!("{answer:?}"), "Selected(\"yes\")");
    }

    #[test]
    fn kind_descriptions_never_echo_a_secret_shaped_fixture_value() {
        // Regression guard, mirroring
        // `secrets_core::resolver::tests::resolving_an_unknown_field_reports_not_found_without_the_value`:
        // even though nothing here ever receives a real secret, the
        // rendering path itself must not be able to.
        let unlock = PromptKind::Unlock {
            backend_name: "local".to_string(),
        };
        assert!(!unlock.title().contains("hunter2"));
        assert!(!unlock.description().contains("hunter2"));
    }
}
