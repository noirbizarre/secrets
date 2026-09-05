//! A secret's content, wrapped so it cannot be printed, logged or
//! serialized by accident.
//!
//! This is a boundary type, not a cryptographic one: it does not encrypt
//! anything, it just makes "I meant to expose this" a deliberate method
//! call instead of something `{:?}`, `println!` or a derived `Serialize`
//! could do for you. Actual encryption at rest is the backend's job (see
//! `secretsd`'s local backend and `docs/security.md`).

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secret's content: a password, a TOTP seed, a private key, and so on.
///
/// Deliberately has no [`std::fmt::Display`] and a [`std::fmt::Debug`] that
/// never prints the content. The only way to read the value is
/// [`SecretValue::expose_secret`], so every call site that does is
/// grep-able.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretValue(String);

impl SecretValue {
    /// Wrap a value. Takes ownership so the caller cannot keep a second,
    /// un-zeroized copy of the same [`String`] around.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Read the wrapped value.
    ///
    /// Named `expose_secret` rather than e.g. `as_str` on purpose: it must
    /// read, at every call site, as what it is.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The whole point of this type: a stray `{:?}` in a log statement
        // must not leak the value.
        f.write_str("SecretValue(REDACTED)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expose_secret_returns_the_wrapped_value() {
        let value = SecretValue::new("hunter2".to_string());
        assert_eq!(value.expose_secret(), "hunter2");
    }

    #[test]
    fn debug_formatting_never_prints_the_value() {
        let value = SecretValue::new("hunter2".to_string());
        let debug = format!("{value:?}");
        assert_eq!(debug, "SecretValue(REDACTED)");
        assert!(!debug.contains("hunter2"));
    }
}
