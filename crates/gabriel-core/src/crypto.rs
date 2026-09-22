//! Cryptographic agility layer.
//!
//! The blueprint's security section calls for this explicitly: "design a
//! cryptographic agility layer so algorithms can be replaced without
//! redesigning the application protocol." Concretely, that means every
//! public key and signature that goes anywhere near the wire should carry
//! an explicit algorithm tag, and verification should dispatch on that tag
//! -- instead of every message type silently assuming "it's Ed25519,
//! 32-byte keys, 64-byte signatures" the way `identity.rs` and the
//! discovery/gateway/routing wire structs currently do.
//!
//! This module is that abstraction, with two real, working algorithms
//! behind it -- not a bare enum with one variant that nothing exercises:
//!   - `Ed25519`: what `identity.rs` already uses today. Fast, small
//!     (32-byte keys, 64-byte signatures), NOT post-quantum secure.
//!   - `MlDsa44`: NIST FIPS 204, the smallest ML-DSA parameter set, via
//!     RustCrypto's pure-Rust `ml-dsa` crate (no C toolchain / liboqs
//!     needed -- that was the whole reason this was feasible to wire in
//!     for real in this session rather than just stubbed). Post-quantum
//!     secure, at a real cost: ~1.3KB public keys, ~2.4KB signatures.
//!
//! What this module deliberately does NOT do yet: `identity.rs` and the
//! discovery/gateway/routing wire formats are untouched -- they still use
//! bare `[u8; 32]`/`[u8; 64]` Ed25519 keys and signatures, not the tagged
//! types here. Migrating them (so a device could actually run as an
//! ML-DSA identity on the mesh, not just in a standalone test) is the
//! natural next step, and a bigger one: it touches every wire struct that
//! carries a device id or signature. This module is the foundation that
//! migration would build on, proven to actually work for two algorithms
//! first.

// Two different major versions of the `signature` crate are in the
// dependency graph -- ed25519-dalek 2.x pulls in signature 2.x, ml-dsa
// pulls in signature 3.x. Their `Signer`/`Verifier` traits share a name
// but are distinct types to the compiler, so both can be imported
// anonymously (`as _`) without conflict: each concrete key type below
// only implements one of the two, so method resolution is unambiguous.
use ed25519_dalek::{Signer as _, Verifier as _};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, Generate, Keypair as _, MlDsa44,
    Signature as MlDsaRawSignature, Signer as _, Verifier as _, VerifyingKey as MlDsaRawVerifyingKey,
};
use serde::{Deserialize, Serialize};

/// Which algorithm a `AgilePublicKey`/`AgileSignature` was produced with.
/// Carried on the wire (via `Serialize`/`Deserialize`) alongside the key
/// material itself, so a verifier never has to guess or assume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AlgorithmId {
    Ed25519,
    MlDsa44,
}

/// An algorithm-tagged public/verifying key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgilePublicKey {
    pub algorithm: AlgorithmId,
    pub bytes: Vec<u8>,
}

/// An algorithm-tagged signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgileSignature {
    pub algorithm: AlgorithmId,
    pub bytes: Vec<u8>,
}

/// A signing key for one of the supported algorithms. Boxed on the
/// `MlDsa44` arm so the common (today: only) `Ed25519` case doesn't pay
/// for ML-DSA's much larger key size in every `AgileSigningKey`'s stack
/// footprint.
pub enum AgileSigningKey {
    Ed25519(ed25519_dalek::SigningKey),
    MlDsa44(Box<ml_dsa::SigningKey<MlDsa44>>),
}

impl AgileSigningKey {
    /// Generates a fresh key for the given algorithm.
    pub fn generate(algorithm: AlgorithmId) -> Self {
        match algorithm {
            AlgorithmId::Ed25519 => Self::Ed25519(ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng)),
            AlgorithmId::MlDsa44 => Self::MlDsa44(Box::new(ml_dsa::SigningKey::<MlDsa44>::generate())),
        }
    }

    pub fn algorithm(&self) -> AlgorithmId {
        match self {
            Self::Ed25519(_) => AlgorithmId::Ed25519,
            Self::MlDsa44(_) => AlgorithmId::MlDsa44,
        }
    }

    pub fn public_key(&self) -> AgilePublicKey {
        match self {
            Self::Ed25519(signing_key) => AgilePublicKey {
                algorithm: AlgorithmId::Ed25519,
                bytes: signing_key.verifying_key().to_bytes().to_vec(),
            },
            Self::MlDsa44(signing_key) => AgilePublicKey {
                algorithm: AlgorithmId::MlDsa44,
                bytes: signing_key.verifying_key().encode().as_slice().to_vec(),
            },
        }
    }

    pub fn sign(&self, message: &[u8]) -> AgileSignature {
        match self {
            Self::Ed25519(signing_key) => AgileSignature {
                algorithm: AlgorithmId::Ed25519,
                bytes: signing_key.sign(message).to_bytes().to_vec(),
            },
            Self::MlDsa44(signing_key) => {
                let sig: MlDsaRawSignature<MlDsa44> = signing_key.sign(message);
                AgileSignature {
                    algorithm: AlgorithmId::MlDsa44,
                    bytes: sig.encode().as_slice().to_vec(),
                }
            }
        }
    }
}

/// Verifies `signature` over `message` under `public_key`, dispatching on
/// the algorithm tag. A mismatched pairing (e.g. an `Ed25519`-tagged key
/// checked against an `MlDsa44`-tagged signature) fails closed rather than
/// guessing which one to trust.
pub fn verify(public_key: &AgilePublicKey, message: &[u8], signature: &AgileSignature) -> bool {
    if public_key.algorithm != signature.algorithm {
        return false;
    }
    match public_key.algorithm {
        AlgorithmId::Ed25519 => verify_ed25519(&public_key.bytes, message, &signature.bytes),
        AlgorithmId::MlDsa44 => verify_ml_dsa44(&public_key.bytes, message, &signature.bytes),
    }
}

fn verify_ed25519(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let Ok(key_array): Result<[u8; 32], _> = public_key_bytes.try_into() else {
        return false;
    };
    let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(&key_array) else {
        return false;
    };
    let Ok(sig_array): Result<[u8; 64], _> = signature_bytes.try_into() else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_array);
    verifying_key.verify(message, &sig).is_ok()
}

fn verify_ml_dsa44(public_key_bytes: &[u8], message: &[u8], signature_bytes: &[u8]) -> bool {
    let Ok(encoded_key) = EncodedVerifyingKey::<MlDsa44>::try_from(public_key_bytes) else {
        return false; // wrong length for an ML-DSA-44 public key -- can't possibly be valid
    };
    let verifying_key = MlDsaRawVerifyingKey::<MlDsa44>::decode(&encoded_key);

    let Ok(encoded_sig) = EncodedSignature::<MlDsa44>::try_from(signature_bytes) else {
        return false; // wrong length for an ML-DSA-44 signature
    };
    let Some(sig) = MlDsaRawSignature::<MlDsa44>::decode(&encoded_sig) else {
        return false; // right length, but not a structurally valid encoded signature
    };

    verifying_key.verify(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz_support;
    use std::time::Duration;

    #[test]
    fn ed25519_sign_and_verify_round_trip() {
        let key = AgileSigningKey::generate(AlgorithmId::Ed25519);
        let public_key = key.public_key();
        assert_eq!(public_key.algorithm, AlgorithmId::Ed25519);
        let signature = key.sign(b"hello agility");
        assert!(verify(&public_key, b"hello agility", &signature));
    }

    #[test]
    fn ml_dsa44_sign_and_verify_round_trip() {
        let key = AgileSigningKey::generate(AlgorithmId::MlDsa44);
        let public_key = key.public_key();
        assert_eq!(public_key.algorithm, AlgorithmId::MlDsa44);
        let signature = key.sign(b"hello post-quantum world");
        assert!(verify(&public_key, b"hello post-quantum world", &signature));

        // Concrete, measured (not just claimed in the module doc comment)
        // proof of ML-DSA-44's real cost versus Ed25519's 32/64 bytes --
        // these are FIPS 204's official ML-DSA-44 sizes.
        assert_eq!(public_key.bytes.len(), 1312, "ML-DSA-44 public key size");
        assert_eq!(signature.bytes.len(), 2420, "ML-DSA-44 signature size");
    }

    /// The actual "agility" property: two different algorithms, same
    /// verify() call site, no special-casing by the caller.
    #[test]
    fn verify_dispatches_correctly_across_both_algorithms() {
        let ed = AgileSigningKey::generate(AlgorithmId::Ed25519);
        let mldsa = AgileSigningKey::generate(AlgorithmId::MlDsa44);

        let ed_pub = ed.public_key();
        let ed_sig = ed.sign(b"same message");
        let mldsa_pub = mldsa.public_key();
        let mldsa_sig = mldsa.sign(b"same message");

        assert!(verify(&ed_pub, b"same message", &ed_sig));
        assert!(verify(&mldsa_pub, b"same message", &mldsa_sig));
    }

    #[test]
    fn verify_rejects_a_tampered_message_for_both_algorithms() {
        for algorithm in [AlgorithmId::Ed25519, AlgorithmId::MlDsa44] {
            let key = AgileSigningKey::generate(algorithm);
            let public_key = key.public_key();
            let signature = key.sign(b"original");
            assert!(
                !verify(&public_key, b"tampered", &signature),
                "{algorithm:?} accepted a signature over the wrong message"
            );
        }
    }

    /// Fails-closed on a mismatched pairing rather than trying to guess --
    /// the actual point of tagging both sides instead of just one.
    #[test]
    fn verify_rejects_mismatched_algorithm_pairing() {
        let ed = AgileSigningKey::generate(AlgorithmId::Ed25519);
        let mldsa = AgileSigningKey::generate(AlgorithmId::MlDsa44);

        let ed_pub = ed.public_key();
        let mldsa_sig = mldsa.sign(b"message");

        assert!(!verify(&ed_pub, b"message", &mldsa_sig));
    }

    /// Both verifiers eventually parse attacker-controlled bytes (a device
    /// id + signature arriving over the network) -- same "never panic on
    /// garbage" bar as every other parser hardened earlier this pass.
    #[test]
    fn garbage_bytes_never_panic_either_verifier() {
        fuzz_support::assert_never_panics_on_random_bytes(2000, |bytes| {
            let _ = verify_ed25519(bytes, b"msg", bytes);
        });
        fuzz_support::assert_never_panics_on_random_bytes(2000, |bytes| {
            let _ = verify_ml_dsa44(bytes, b"msg", bytes);
        });
    }

    #[test]
    fn ml_dsa44_verify_completes_quickly_even_on_garbage() {
        let bytes = vec![0xAAu8; 4096];
        let completed = fuzz_support::completes_within(Duration::from_secs(2), move || {
            let _ = verify_ml_dsa44(&bytes, b"msg", &bytes);
        });
        assert!(completed, "ML-DSA verification must not hang on malformed input");
    }
}
