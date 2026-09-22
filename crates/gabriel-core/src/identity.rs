//! Gabriel identity hierarchy.
//!
//! v0.1: software-backed Ed25519 keys, persisted as raw bytes on disk.
//! This is explicitly a placeholder for the real design: the blueprint's
//! security section calls for moving private-key storage behind Windows
//! CNG/TPM (a non-exportable key via NCryptCreatePersistedKey) so the
//! private key never exists outside hardware. Nothing that calls into this
//! module should need to change when that swap happens -- callers only
//! ever see `public_key()`, `sign()`, and the free function `verify()`.

use std::fs;
use std::path::Path;

use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

use crate::Result;

/// A device-local identity: one signing keypair per installed Gabriel
/// client/gateway. `public_key()` is what other peers call a device's
/// `device_id` elsewhere in this crate (discovery, GNP packets).
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Loads the identity from `path`, or generates and persists a new one
    /// if the file doesn't exist yet. Use one path per device install.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if let Ok(bytes) = fs::read(path) {
            let seed: [u8; 32] = bytes.try_into().map_err(|_| {
                anyhow::anyhow!("identity key file at {path:?} is corrupt (expected 32 bytes)")
            })?;
            return Ok(Self {
                signing_key: SigningKey::from_bytes(&seed),
            });
        }
        let signing_key = SigningKey::generate(&mut OsRng);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, signing_key.to_bytes())?;
        Ok(Self { signing_key })
    }

    /// A throwaway identity that's never written to disk. Used by tests and
    /// anywhere a stable device identity across restarts doesn't matter.
    pub fn generate_ephemeral() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// This device's public identity key (32 bytes).
    pub fn public_key(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Signs `message` with this device's private identity key.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Verifies `signature` over `message` under the identity claimed by
    /// `public_key`. Used to authenticate discovery announcements (and,
    /// later, GNP packets) from peers we don't have a live session with yet
    /// -- see the threat model's "Fake identity" row in the blueprint.
    pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        let signature = Signature::from_bytes(signature);
        verifying_key.verify(message, &signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_round_trip() {
        let identity = Identity::generate_ephemeral();
        let message = b"gabriel discovery announcement";
        let signature = identity.sign(message);
        assert!(Identity::verify(&identity.public_key(), message, &signature));
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let identity = Identity::generate_ephemeral();
        let signature = identity.sign(b"original");
        assert!(!Identity::verify(&identity.public_key(), b"tampered", &signature));
    }

    #[test]
    fn load_or_create_persists_across_loads() {
        let dir = std::env::temp_dir().join(format!("gabriel-identity-test-{}", std::process::id()));
        let path = dir.join("identity.key");
        let first = Identity::load_or_create(&path).unwrap();
        let second = Identity::load_or_create(&path).unwrap();
        assert_eq!(first.public_key(), second.public_key());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
