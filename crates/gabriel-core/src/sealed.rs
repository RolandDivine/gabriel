//! End-to-end encryption for mesh messages.
//!
//! Until now a Gabriel message was signed but readable: the destination
//! could prove who sent it and that nobody altered it, but every device
//! that relayed it along the way could read the text. On a mesh, where
//! relaying is done by whoever happens to be nearby, that is the whole
//! problem. This module closes it.
//!
//! # The construction
//!
//! Ephemeral-static X25519, an HKDF-SHA256 key schedule, and
//! ChaCha20-Poly1305 — the same shape as HPKE's base mode, assembled from
//! audited primitives rather than hand-rolled:
//!
//! 1. The sender generates a fresh X25519 keypair for **this one message**.
//! 2. It performs Diffie-Hellman against the recipient's static X25519
//!    key, giving a shared secret only those two can compute.
//! 3. HKDF turns that into an AEAD key, binding in the ephemeral public
//!    key and both device ids so a sealed message cannot be re-pointed at
//!    a different recipient or re-attributed to a different sender.
//! 4. ChaCha20-Poly1305 encrypts the body, with the envelope header as
//!    associated data.
//!
//! Sender authentication is *not* done here. It is already done, once, by
//! the Ed25519 signature that `routing` puts over the whole envelope. That
//! is deliberate: a relay can still verify a message is genuine before
//! forwarding it, without being able to read a word of it.
//!
//! # Where the recipient's key comes from, and the tradeoff
//!
//! A device id **is** an Ed25519 public key, and an Ed25519 public key
//! converts to an X25519 public key by the standard birational map. So
//! any device can encrypt to any device id it can address — including one
//! it has never seen, several hops away, with no key exchange, no
//! directory and no pairing step.
//!
//! That property is not a convenience here, it is load-bearing. Mesh
//! routing addresses a destination by device id and floods towards it. If
//! encryption needed a key the sender had to fetch first, it could only
//! ever work for peers already visible on the LAN, which is precisely the
//! case that did not need a mesh.
//!
//! The cost is real and worth stating plainly: **this reuses one keypair
//! for signing and for key agreement**, which dalek's own documentation
//! recommends against, citing [*On using the same key pair for Ed25519 and
//! an X25519 based KEM*](https://eprint.iacr.org/2021/509). That paper
//! finds joint security holds for this construction, and libsodium ships
//! the same conversions, so this is a considered tradeoff rather than an
//! oversight — but it is a tradeoff, not a free lunch.
//!
//! [`SealedMessage::version`] exists so the alternative can land without a
//! flag day: a v2 that carries a separately-derived X25519 identity key,
//! distributed in the (already signed) discovery beacon, would change the
//! key *source* and nothing else about the format.
//!
//! # What this gives, and what it does not
//!
//! **Gives:** confidentiality from relays, integrity, and — because the
//! sender's key is discarded after one message — forward secrecy against
//! later compromise of the *sender*.
//!
//! **Does not give:** forward secrecy against compromise of the
//! *recipient*. Their identity key is long-lived, so someone who steals it
//! and kept copies of old ciphertext can read those messages. Fixing that
//! needs a ratchet (MLS, or Double Ratchet), which needs per-peer session
//! state the mesh does not carry yet. This module is the layer that makes
//! that worth building, not a substitute for it.
//!
//! **Also does not give:** metadata privacy. Who is talking to whom, and
//! when, is visible to every relay — routing needs the destination in
//! clear to know where to flood. Hiding that is a different problem.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::VerifyingKey;
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};

use crate::identity::Identity;
use crate::Result;

/// Envelope format version. Bumped if the key schedule, the AEAD, or
/// where the recipient's key comes from ever changes.
pub const SEALED_VERSION: u8 = 1;

/// Domain separation for the key schedule. Any other protocol deriving
/// keys from the same X25519 secret gets different keys, because this
/// string differs.
const HKDF_INFO_PREFIX: &[u8] = b"gabriel-seal-v1";

/// ChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 12;

/// A refusal to decrypt. Deliberately coarse: distinguishing "wrong key"
/// from "tampered ciphertext" tells an attacker which of the two they got
/// wrong, and neither is recoverable, so both read the same.
#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("unsupported sealed-message version {0} (this build speaks {SEALED_VERSION})")]
    UnsupportedVersion(u8),
    #[error("that device id is not a valid Ed25519 public key")]
    InvalidRecipient,
    #[error("malformed sealed message")]
    Malformed,
    #[error("could not decrypt: wrong recipient, or the message was altered")]
    Undecryptable,
}

/// An encrypted message body. Everything here is safe for a relay to see;
/// none of it reveals the plaintext.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedMessage {
    pub version: u8,
    /// The sender's one-time X25519 public key for this message.
    pub ephemeral_public: [u8; 32],
    /// Rides as a `Vec` because serde's built-in array impls stop at 32,
    /// and is length-checked on the way back in.
    pub nonce: Vec<u8>,
    /// ChaCha20-Poly1305 output, with its 16-byte authentication tag.
    pub ciphertext: Vec<u8>,
}

impl SealedMessage {
    /// Bytes on the wire, for callers that want to carry this as an opaque
    /// blob rather than a struct.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(bincode::serialize(self)?)
    }

    pub fn from_bytes(bytes: &[u8]) -> std::result::Result<Self, SealError> {
        bincode::deserialize(bytes).map_err(|_| SealError::Malformed)
    }
}

/// The X25519 public key a device id encrypts to.
///
/// Returns `None` for 32 bytes that do not decompress to an Ed25519
/// point. Roughly half of all 32-byte strings do not, so this catches a
/// mistyped or corrupted device id before anything is sent to it — but it
/// is a sanity check, not proof the device exists.
pub fn recipient_key(device_id: &[u8; 32]) -> Option<XPublicKey> {
    let verifying = VerifyingKey::from_bytes(device_id).ok()?;
    Some(XPublicKey::from(verifying.to_montgomery().to_bytes()))
}

/// This device's X25519 secret, derived from the same Ed25519 seed the
/// identity already holds.
fn own_secret(identity: &Identity) -> StaticSecret {
    StaticSecret::from(identity.x25519_secret_bytes())
}

/// The HKDF `info` string. Binding both device ids in here is what stops
/// a sealed message being re-pointed at another recipient or re-labelled
/// as coming from someone else: change either id and the key changes, so
/// decryption fails.
fn key_schedule_info(ephemeral: &[u8; 32], sender: &[u8; 32], recipient: &[u8; 32]) -> Vec<u8> {
    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + 96);
    info.extend_from_slice(HKDF_INFO_PREFIX);
    info.extend_from_slice(ephemeral);
    info.extend_from_slice(sender);
    info.extend_from_slice(recipient);
    info
}

/// Associated data: authenticated but not encrypted, so a relay can see
/// it and an attacker cannot change it without the tag failing.
fn associated_data(sender: &[u8; 32], recipient: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(65);
    aad.push(SEALED_VERSION);
    aad.extend_from_slice(sender);
    aad.extend_from_slice(recipient);
    aad
}

fn derive_key(shared: &[u8; 32], info: &[u8]) -> Key {
    let hkdf = Hkdf::<Sha256>::new(None, shared);
    let mut key = [0u8; 32];
    hkdf.expand(info, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    Key::from(key)
}

/// Encrypts `plaintext` so that only `recipient` can read it.
///
/// The sender's identity is needed for the key schedule binding, not for
/// the key agreement itself — the DH is ephemeral-to-static, so the
/// sender's long-term key never touches the shared secret.
pub fn seal(
    identity: &Identity,
    recipient: &[u8; 32],
    plaintext: &[u8],
) -> std::result::Result<SealedMessage, SealError> {
    let recipient_public = recipient_key(recipient).ok_or(SealError::InvalidRecipient)?;
    let sender = identity.public_key();

    // A fresh keypair per message. This is what gives forward secrecy
    // against later compromise of the sender: the secret is dropped at the
    // end of this function and never written anywhere.
    let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
    let ephemeral_public = XPublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(&recipient_public);

    let info = key_schedule_info(ephemeral_public.as_bytes(), &sender, recipient);
    let key = derive_key(shared.as_bytes(), &info);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let aad = associated_data(&sender, recipient);
    let ciphertext = ChaCha20Poly1305::new(&key)
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload { msg: plaintext, aad: &aad },
        )
        .map_err(|_| SealError::Malformed)?;

    Ok(SealedMessage {
        version: SEALED_VERSION,
        ephemeral_public: *ephemeral_public.as_bytes(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
    })
}

/// Decrypts a message addressed to this device.
///
/// `sender` is the claimed sender. It is bound into the key schedule, so
/// passing the wrong one fails to decrypt — but note that this alone does
/// not *authenticate* the sender: anyone can seal a message naming
/// someone else as sender. Authentication comes from the Ed25519
/// signature `routing` verifies before this is ever called.
pub fn unseal(
    identity: &Identity,
    sender: &[u8; 32],
    message: &SealedMessage,
) -> std::result::Result<Vec<u8>, SealError> {
    if message.version != SEALED_VERSION {
        return Err(SealError::UnsupportedVersion(message.version));
    }
    let nonce: [u8; NONCE_LEN] = message
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| SealError::Malformed)?;

    let recipient = identity.public_key();
    let secret = own_secret(identity);
    let shared = secret.diffie_hellman(&XPublicKey::from(message.ephemeral_public));

    let info = key_schedule_info(&message.ephemeral_public, sender, &recipient);
    let key = derive_key(shared.as_bytes(), &info);
    let aad = associated_data(sender, &recipient);

    ChaCha20Poly1305::new(&key)
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: &message.ciphertext, aad: &aad },
        )
        .map_err(|_| SealError::Undecryptable)
}

/// Sanity check that the Ed25519 -> X25519 conversion agrees on both
/// sides: the public key a sender derives from a device id must match the
/// one that device derives from its own secret. If these ever disagree,
/// every message silently fails to decrypt, so it is worth asserting
/// rather than assuming.
pub fn keys_agree(identity: &Identity) -> bool {
    let from_public = match recipient_key(&identity.public_key()) {
        Some(key) => key,
        None => return false,
    };
    let from_secret = XPublicKey::from(&own_secret(identity));
    from_public.as_bytes() == from_secret.as_bytes()
}

/// Exposed for the montgomery conversion in `identity`.
pub(crate) fn montgomery_bytes(verifying: &VerifyingKey) -> [u8; 32] {
    let point: MontgomeryPoint = verifying.to_montgomery();
    point.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz_support;

    #[test]
    fn a_sealed_message_round_trips() {
        let alice = Identity::generate_ephemeral();
        let bob = Identity::generate_ephemeral();

        let sealed = seal(&alice, &bob.public_key(), b"meet me at the market").unwrap();
        let opened = unseal(&bob, &alice.public_key(), &sealed).unwrap();
        assert_eq!(opened, b"meet me at the market");
    }

    /// The whole point: a device that relays the message cannot read it.
    #[test]
    fn a_relay_holding_the_ciphertext_cannot_read_it() {
        let alice = Identity::generate_ephemeral();
        let bob = Identity::generate_ephemeral();
        let relay = Identity::generate_ephemeral();

        let sealed = seal(&alice, &bob.public_key(), b"private").unwrap();

        // The relay has the full ciphertext and both device ids -- exactly
        // what a forwarding node sees -- and still gets nothing.
        assert!(unseal(&relay, &alice.public_key(), &sealed).is_err());
        assert!(unseal(&relay, &relay.public_key(), &sealed).is_err());
        assert!(
            !sealed.ciphertext.windows(7).any(|w| w == b"private"),
            "the plaintext must not appear in the ciphertext"
        );
    }

    #[test]
    fn the_wrong_recipient_cannot_decrypt() {
        let alice = Identity::generate_ephemeral();
        let bob = Identity::generate_ephemeral();
        let carol = Identity::generate_ephemeral();

        let sealed = seal(&alice, &bob.public_key(), b"for bob only").unwrap();
        assert!(matches!(
            unseal(&carol, &alice.public_key(), &sealed),
            Err(SealError::Undecryptable)
        ));
    }

    /// The sender id is bound into the key schedule, so a message cannot
    /// be re-attributed to someone else even by the real recipient.
    #[test]
    fn claiming_a_different_sender_fails_to_decrypt() {
        let alice = Identity::generate_ephemeral();
        let bob = Identity::generate_ephemeral();
        let mallory = Identity::generate_ephemeral();

        let sealed = seal(&alice, &bob.public_key(), b"from alice").unwrap();
        assert!(unseal(&bob, &mallory.public_key(), &sealed).is_err());
        assert!(unseal(&bob, &alice.public_key(), &sealed).is_ok());
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let alice = Identity::generate_ephemeral();
        let bob = Identity::generate_ephemeral();

        let mut sealed = seal(&alice, &bob.public_key(), b"transfer 100").unwrap();
        sealed.ciphertext[0] ^= 0x01;
        assert!(matches!(
            unseal(&bob, &alice.public_key(), &sealed),
            Err(SealError::Undecryptable)
        ));
    }

    #[test]
    fn tampering_with_the_ephemeral_key_or_nonce_is_detected() {
        let alice = Identity::generate_ephemeral();
        let bob = Identity::generate_ephemeral();
        let original = seal(&alice, &bob.public_key(), b"unchanged").unwrap();

        let mut swapped_key = original.clone();
        swapped_key.ephemeral_public[0] ^= 0xff;
        assert!(unseal(&bob, &alice.public_key(), &swapped_key).is_err());

        let mut swapped_nonce = original.clone();
        swapped_nonce.nonce[0] ^= 0xff;
        assert!(unseal(&bob, &alice.public_key(), &swapped_nonce).is_err());
    }

    /// Two identical plaintexts to the same recipient must not produce
    /// identical ciphertext, or an observer learns when a message repeats.
    #[test]
    fn the_same_plaintext_seals_differently_every_time() {
        let alice = Identity::generate_ephemeral();
        let bob = Identity::generate_ephemeral();

        let first = seal(&alice, &bob.public_key(), b"same text").unwrap();
        let second = seal(&alice, &bob.public_key(), b"same text").unwrap();

        assert_ne!(first.ciphertext, second.ciphertext);
        assert_ne!(first.ephemeral_public, second.ephemeral_public, "a fresh key per message");
        assert_ne!(first.nonce, second.nonce);

        // Both still open.
        assert_eq!(unseal(&bob, &alice.public_key(), &first).unwrap(), b"same text");
        assert_eq!(unseal(&bob, &alice.public_key(), &second).unwrap(), b"same text");
    }

    /// If the two conversions ever disagreed, every message would silently
    /// fail to decrypt and the cause would be very hard to find.
    #[test]
    fn the_public_and_secret_conversions_agree() {
        for _ in 0..50 {
            assert!(keys_agree(&Identity::generate_ephemeral()));
        }
    }

    #[test]
    fn a_device_id_that_is_not_a_curve_point_is_refused() {
        let alice = Identity::generate_ephemeral();
        // Not every 32-byte string decompresses to an Ed25519 point --
        // roughly half do not. Search for one rather than assuming a
        // particular constant is invalid, which is how the first version
        // of this test got it wrong.
        let bogus = (0u32..5000)
            .map(|i| {
                let mut b = [0u8; 32];
                b[..4].copy_from_slice(&i.to_le_bytes());
                b
            })
            .find(|b| recipient_key(b).is_none())
            .expect("some 32-byte string must fail to decompress");

        assert!(matches!(
            seal(&alice, &bogus, b"nowhere"),
            Err(SealError::InvalidRecipient)
        ));
    }

    #[test]
    fn an_unknown_version_is_refused_rather_than_guessed() {
        let alice = Identity::generate_ephemeral();
        let bob = Identity::generate_ephemeral();
        let mut sealed = seal(&alice, &bob.public_key(), b"hello").unwrap();
        sealed.version = 99;
        assert!(matches!(
            unseal(&bob, &alice.public_key(), &sealed),
            Err(SealError::UnsupportedVersion(99))
        ));
    }

    #[test]
    fn an_empty_message_seals_and_opens() {
        let alice = Identity::generate_ephemeral();
        let bob = Identity::generate_ephemeral();
        let sealed = seal(&alice, &bob.public_key(), b"").unwrap();
        assert!(!sealed.ciphertext.is_empty(), "the tag is still there");
        assert_eq!(unseal(&bob, &alice.public_key(), &sealed).unwrap(), b"");
    }

    #[test]
    fn a_large_message_survives_the_round_trip() {
        let alice = Identity::generate_ephemeral();
        let bob = Identity::generate_ephemeral();
        let big = vec![0xa5u8; 200_000];
        let sealed = seal(&alice, &bob.public_key(), &big).unwrap();
        assert_eq!(unseal(&bob, &alice.public_key(), &sealed).unwrap(), big);
    }

    #[test]
    fn the_envelope_round_trips_through_bincode() {
        let alice = Identity::generate_ephemeral();
        let bob = Identity::generate_ephemeral();
        let sealed = seal(&alice, &bob.public_key(), b"over the wire").unwrap();

        let decoded = SealedMessage::from_bytes(&sealed.to_bytes().unwrap()).unwrap();
        assert_eq!(decoded, sealed);
        assert_eq!(unseal(&bob, &alice.public_key(), &decoded).unwrap(), b"over the wire");
    }

    /// Sealed bytes arrive from the network, so the parser is
    /// attacker-reachable and held to the same bar as every other one.
    #[test]
    fn garbage_bytes_never_panic_the_parser() {
        let bob = Identity::generate_ephemeral();
        let sender = [7u8; 32];
        fuzz_support::assert_never_panics_on_random_bytes(3000, |bytes| {
            if let Ok(message) = SealedMessage::from_bytes(bytes) {
                let _ = unseal(&bob, &sender, &message);
            }
        });
    }

    #[test]
    fn a_malicious_length_prefix_does_not_hang_or_over_allocate() {
        let alice = Identity::generate_ephemeral();
        let bob = Identity::generate_ephemeral();
        let sealed = seal(&alice, &bob.public_key(), &vec![0u8; 24601]).unwrap();
        let mut bytes = sealed.to_bytes().unwrap();
        fuzz_support::replace_first_u64_le(&mut bytes, 24601 + 16, u64::MAX);

        let completed = fuzz_support::completes_within(std::time::Duration::from_secs(2), move || {
            let _ = SealedMessage::from_bytes(&bytes);
        });
        assert!(completed, "parsing must not hang on a corrupted length prefix");
    }
}
