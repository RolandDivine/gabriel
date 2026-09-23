//! gabriel-core
//!
//! Shared library for the Gabriel adaptive connectivity platform.
//! Loaded by both `gabriel-gatewayd` (the background service / gateway)
//! and `gabriel-client` (the interactive client).
//!
//! v0.1 scope, per the blueprint:
//!   - identity: device + identity key hierarchy (software Ed25519 for now;
//!     TPM/CNG-backed keys land later behind the same public API)
//!   - discovery: signed UDP-multicast LAN peer discovery
//!   - gateway: authenticated TCP relay so a peer with internet access can
//!     share it with peers that don't have one
//!   - routing: multi-hop message flooding across mesh neighbors, with a
//!     hop-count TTL and dedup (no routing table needed at this scale)
//!   - protocol: Gabriel Network Protocol (GNP) packet model
//!   - store: local-first SQLite data model (users, devices, contacts, messages, rooms, routes)
//!   - metering: per-device byte accounting and quotas for the gateway
//!     relay, so shared bandwidth is countable and limitable rather than
//!     merely offered
//!
//! `wire` is a private module: shared length-prefixed frame I/O used by
//! both `gateway` and `routing`, not part of this crate's public API.
//!
//! Beyond discovery, the gateway relay, and mesh routing, nothing here
//! talks to a network transport directly -- GACL (general adaptive path
//! scoring across Wi-Fi/Ethernet/mobile broadband) is developed after
//! these pieces are solid (see "Recommended build order" in the
//! blueprint).

pub mod crypto;
pub mod discovery;
#[cfg(test)]
mod fuzz_support;
pub mod gateway;
pub mod identity;
pub mod metering;
pub mod protocol;
pub mod routing;
pub mod store;
mod wire;

/// Crate-wide result type.
pub type Result<T> = anyhow::Result<T>;

/// Lowercase hex encoding, used anywhere a device id / public key needs to
/// be shown to a human (logs, CLI output) or put in a compact wire format.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
