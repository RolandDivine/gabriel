//! Gabriel Network Protocol (GNP) -- packet model.
//!
//! See the blueprint's "Transport & Protocol" section for the full design.
//! v0.1 implements the packet shape and the message types actually used by
//! the MVP roadmap; PAYMENT and FILE_TRANSFER variants are reserved but
//! unused until their respective milestones.

use serde::{Deserialize, Serialize};

pub const GNP_VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketType {
    Identity,
    Discovery,
    Pairing,
    Routing,
    Messaging,
    Sync,
    ServiceDiscovery,
    Capability,
    // Reserved, not implemented in v0.1:
    Payment,
    FileTransfer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GnpPacket {
    pub version: u8,
    pub packet_type: PacketType,
    pub source_identity: [u8; 32],
    pub destination_identity: [u8; 32],
    /// Opaque routing hint (e.g. next-hop peer id on the LAN mesh).
    pub route_info: Vec<u8>,
    pub sequence_number: u64,
    /// Unix timestamp (seconds) after which this packet should be discarded
    /// rather than delivered or forwarded.
    pub expiration: u64,
    /// MLS/AEAD-encrypted application payload. Never plaintext on the wire.
    pub encrypted_payload: Vec<u8>,
    pub authentication_tag: [u8; 16],
}

impl GnpPacket {
    pub fn new(
        packet_type: PacketType,
        source_identity: [u8; 32],
        destination_identity: [u8; 32],
        sequence_number: u64,
        expiration: u64,
        encrypted_payload: Vec<u8>,
        authentication_tag: [u8; 16],
    ) -> Self {
        Self {
            version: GNP_VERSION,
            packet_type,
            source_identity,
            destination_identity,
            route_info: Vec::new(),
            sequence_number,
            expiration,
            encrypted_payload,
            authentication_tag,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz_support;
    use std::time::Duration;

    #[test]
    fn round_trips_through_bincode() {
        let packet = GnpPacket::new(
            PacketType::Messaging,
            [1u8; 32],
            [2u8; 32],
            7,
            999,
            b"payload".to_vec(),
            [3u8; 16],
        );
        let bytes = bincode::serialize(&packet).unwrap();
        let decoded: GnpPacket = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.sequence_number, 7);
        assert_eq!(decoded.encrypted_payload, b"payload");
    }

    /// GNP isn't wired to a live transport yet (see the module doc), but
    /// it's the packet type the roadmap's "fuzzing GNP parsing" hardening
    /// item names directly, and it will be attacker-reachable the moment
    /// something does start feeding it real network bytes. No reason to
    /// wait until then to know it doesn't panic on garbage.
    #[test]
    fn garbage_bytes_never_panic_the_parser() {
        fuzz_support::assert_never_panics_on_random_bytes(3000, |bytes| {
            let _ = bincode::deserialize::<GnpPacket>(bytes);
        });
    }

    #[test]
    fn malicious_payload_length_does_not_hang_or_panic() {
        let packet = GnpPacket::new(
            PacketType::Messaging,
            [1u8; 32],
            [2u8; 32],
            1,
            1,
            vec![0u8; 24601], // distinctive length -- see replace_first_u64_le's doc
            [0u8; 16],
        );
        let mut bytes = bincode::serialize(&packet).unwrap();
        fuzz_support::replace_first_u64_le(&mut bytes, 24601, u64::MAX);

        let completed = fuzz_support::completes_within(Duration::from_secs(2), move || {
            let result = bincode::deserialize::<GnpPacket>(&bytes);
            assert!(
                result.is_err(),
                "a payload length prefix claiming u64::MAX with only a few KB of real data must fail to parse, not succeed"
            );
        });
        assert!(completed, "parsing must not hang on a corrupted length prefix");
    }
}
