//! The local backend's cryptography, behind a small, auditable API.
//!
//! No algorithm invented here: key derivation is Argon2id (via the `argon2`
//! crate), encryption is AES-256-GCM (via `aes-gcm`), randomness is the OS
//! CSPRNG (via `rand_core::OsRng`). See ADR-0006 for why.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use argon2::Argon2;
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// The size, in bytes, of the AES-256 key derived from a passphrase.
const KEY_LEN: usize = 32;

/// The size, in bytes, of an AES-GCM nonce.
const NONCE_LEN: usize = 12;

/// The size, in bytes, of the Argon2id salt.
const SALT_LEN: usize = 16;

/// A derived 256-bit key, zeroized on drop.
///
/// Holds the *only* long-lived secret in this crate: everything else is
/// re-derived or decrypted on demand and dropped as soon as possible.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKey([u8; KEY_LEN]);

impl VaultKey {
    fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// A key derivation failed — Argon2's own errors are all about invalid
/// parameters, never about *why* a passphrase is wrong (there is no way to
/// tell short of trying to decrypt with the result).
#[derive(Debug, thiserror::Error)]
#[error("key derivation failed: {0}")]
pub struct KdfError(String);

/// Decryption failed: either the passphrase was wrong (derived the wrong
/// key) or the ciphertext was corrupted. AES-GCM's authentication tag
/// cannot distinguish the two, and neither can we — see
/// [`crate::error::DaemonError::IncorrectPassphrase`] for why callers
/// should not try to.
#[derive(Debug, thiserror::Error)]
#[error("decryption failed (wrong passphrase or corrupted data)")]
pub struct DecryptError;

/// Generate a fresh random salt for a new vault file.
#[must_use]
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive a vault key from a passphrase and salt using Argon2id.
///
/// Uses the crate's default parameters (Argon2id, 19 MiB, 2 passes, 1
/// lane) — OWASP's current baseline recommendation for interactive use, and
/// deliberately not tuned further: a home-rolled parameter choice is a
/// worse bet than a maintained crate's default.
///
/// # Errors
///
/// Returns [`KdfError`] only if the salt or output length is invalid —
/// never because the passphrase was "wrong" (derivation always succeeds;
/// only the subsequent decryption can fail).
pub fn derive_key(passphrase: &str, salt: &[u8]) -> Result<VaultKey, KdfError> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|error| KdfError(error.to_string()))?;
    Ok(VaultKey(key))
}

/// One field's ciphertext, as stored in the vault file.
pub struct Encrypted {
    /// The per-field random nonce.
    pub nonce: [u8; NONCE_LEN],
    /// The AES-256-GCM ciphertext (includes the authentication tag).
    pub ciphertext: Vec<u8>,
}

/// Encrypt a field's value under the vault key.
///
/// Generates a fresh random nonce per call — required for AES-GCM's
/// security, and cheap enough (12 random bytes) that there is no reason to
/// ever reuse one.
#[must_use]
pub fn encrypt(key: &VaultKey, plaintext: &str) -> Encrypted {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new(key.as_bytes().into());
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        // The only failure mode is a plaintext larger than AES-GCM's ~64GiB
        // limit, which no secret field will ever approach.
        .expect("field values are always within AES-GCM's plaintext limit");
    Encrypted {
        nonce: nonce_bytes,
        ciphertext,
    }
}

/// Decrypt a field's value under the vault key.
///
/// # Errors
///
/// Returns [`DecryptError`] if the authentication tag does not verify —
/// either the wrong key was derived (wrong passphrase) or the stored
/// ciphertext was corrupted or tampered with.
pub fn decrypt(key: &VaultKey, encrypted: &Encrypted) -> Result<String, DecryptError> {
    let cipher = Aes256Gcm::new(key.as_bytes().into());
    let nonce = Nonce::from(encrypted.nonce);
    let plaintext = cipher
        .decrypt(&nonce, encrypted.ciphertext.as_ref())
        .map_err(|_| DecryptError)?;
    String::from_utf8(plaintext).map_err(|_| DecryptError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn encrypting_then_decrypting_returns_the_original_value() {
        let salt = generate_salt();
        let key = derive_key("correct horse battery staple", &salt).unwrap();

        let encrypted = encrypt(&key, "hunter2");
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted, "hunter2");
    }

    #[test]
    fn decrypting_with_the_wrong_passphrase_fails_without_revealing_why() {
        let salt = generate_salt();
        let right_key = derive_key("correct horse battery staple", &salt).unwrap();
        let wrong_key = derive_key("wrong guess", &salt).unwrap();

        let encrypted = encrypt(&right_key, "hunter2");
        let result = decrypt(&wrong_key, &encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn two_encryptions_of_the_same_value_use_different_nonces() {
        let salt = generate_salt();
        let key = derive_key("correct horse battery staple", &salt).unwrap();

        let first = encrypt(&key, "hunter2");
        let second = encrypt(&key, "hunter2");

        assert_ne!(first.nonce, second.nonce);
        assert_ne!(first.ciphertext, second.ciphertext);
    }
}
