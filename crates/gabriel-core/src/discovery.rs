//! LAN peer discovery.
//!
//! Per the blueprint's "Mesh & Peer-to-Peer Networking on Windows" section:
//! peers find each other over UDP multicast on whatever LAN segment they
//! already share -- no special radio mode, no Wi-Fi Direct dependency.
//!
//! Each device periodically broadcasts a *signed* announcement to a
//! well-known multicast group. Peers verify the signature before trusting
//! an announcement, which is the first concrete piece of the threat
//! model's "Fake identity" control (cryptographic device identity +
//! authenticated key exchange) -- an unauthenticated UDP broadcast on its
//! own would let anyone on the LAN inject fake peers.
//!
//! This module deliberately does NOT try to be mDNS/DNS-SD compliant
//! (`_gabriel._udp.local`, resolvable by generic mDNS tools) -- that's a
//! reasonable later enhancement, but a purpose-built beacon using the same
//! signing/verification primitives the rest of Gabriel needs anyway is
//! simpler to get right first.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::time::MissedTickBehavior;

use crate::identity::Identity;
use crate::Result;

/// Administratively-scoped multicast group used for LAN discovery.
/// Arbitrary choice within 239.0.0.0/8 -- revisit if it ever collides with
/// something else on a real deployment network.
pub const DISCOVERY_MULTICAST_ADDR: Ipv4Addr = Ipv4Addr::new(239, 255, 42, 99);
pub const DISCOVERY_PORT: u16 = 42424;

const ANNOUNCE_INTERVAL: Duration = Duration::from_secs(5);
/// Drop a peer if we haven't heard from it in this long -- a few missed
/// announce intervals, not just one, so a single dropped UDP packet doesn't
/// flap a peer in and out of the table.
const PEER_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_DATAGRAM_SIZE: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Announcement {
    device_id: [u8; 32],
    display_name: String,
    /// Port this device will listen for GNP connections on, once GNP has a
    /// transport listener (v0.1 discovery ships ahead of that -- peers
    /// record it now so nothing has to change when it's wired up).
    gnp_port: u16,
    /// Whether this device is running a gateway relay (see `gateway.rs`)
    /// that other peers can route through. Discovery just carries the flag;
    /// it doesn't imply the relay is actually reachable or has real
    /// internet access -- that's on the peer choosing to trust it.
    offers_gateway: bool,
    timestamp_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedAnnouncement {
    announcement: Announcement,
    // serde's built-in array impls stop short of 64 elements, so this rides
    // as a Vec on the wire; `handle_datagram` converts it back to the
    // `[u8; 64]` `Identity::verify` expects and rejects anything the wrong
    // length.
    signature: Vec<u8>,
}

/// What we know about a peer discovered on the LAN.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub device_id: [u8; 32],
    pub display_name: String,
    pub addr: SocketAddr,
    pub gnp_port: u16,
    pub offers_gateway: bool,
    pub last_seen: Instant,
}

#[derive(Default)]
struct PeerTable {
    peers: Mutex<HashMap<[u8; 32], PeerInfo>>,
}

impl PeerTable {
    fn upsert(&self, peer: PeerInfo) {
        self.peers.lock().unwrap().insert(peer.device_id, peer);
    }

    fn prune_stale(&self, max_age: Duration) {
        let now = Instant::now();
        self.peers
            .lock()
            .unwrap()
            .retain(|_, p| now.duration_since(p.last_seen) < max_age);
    }

    fn snapshot(&self) -> Vec<PeerInfo> {
        self.peers.lock().unwrap().values().cloned().collect()
    }
}

/// Announces this device on the LAN and tracks other devices' announcements.
pub struct DiscoveryService {
    identity: Arc<Identity>,
    display_name: String,
    gnp_port: u16,
    offers_gateway: bool,
    peers: PeerTable,
}

impl DiscoveryService {
    pub fn new(
        identity: Arc<Identity>,
        display_name: String,
        gnp_port: u16,
        offers_gateway: bool,
    ) -> Self {
        Self {
            identity,
            display_name,
            gnp_port,
            offers_gateway,
            peers: PeerTable::default(),
        }
    }

    /// Current snapshot of discovered peers (never includes this device).
    pub fn peers(&self) -> Vec<PeerInfo> {
        self.peers.snapshot()
    }

    /// Binds the discovery sockets and spawns the announce/listen loop on
    /// the current tokio runtime. Returns immediately; hold the returned
    /// handle if you need to await or abort the background task.
    pub fn spawn(self: Arc<Self>) -> Result<tokio::task::JoinHandle<()>> {
        let recv_socket = Self::bind_multicast_recv_socket()?;
        let send_socket = Self::bind_send_socket()?;

        Ok(tokio::spawn(async move {
            if let Err(err) = self.run(send_socket, recv_socket).await {
                eprintln!("gabriel discovery loop exited with an error: {err:?}");
            }
        }))
    }

    /// Bound to `DISCOVERY_PORT` on all interfaces, joined to the multicast
    /// group, with SO_REUSEADDR set *before* bind so more than one Gabriel
    /// process on the same machine (useful for local dev/testing) can all
    /// receive the multicast traffic.
    fn bind_multicast_recv_socket() -> Result<UdpSocket> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;
        let bind_addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, DISCOVERY_PORT).into();
        socket.bind(&bind_addr.into())?;
        socket.join_multicast_v4(&DISCOVERY_MULTICAST_ADDR, &Ipv4Addr::UNSPECIFIED)?;
        let std_socket: std::net::UdpSocket = socket.into();
        Ok(UdpSocket::from_std(std_socket)?)
    }

    /// A separate ephemeral-port socket for sending announcements. Kept
    /// distinct from the receive socket so we don't have to reason about a
    /// single socket being both a multicast-group member and a sender.
    fn bind_send_socket() -> Result<UdpSocket> {
        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_nonblocking(true)?;
        let bind_addr: SocketAddr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into();
        socket.bind(&bind_addr.into())?;
        // Stay on the local link by default; raise this only if a deployment
        // deliberately needs discovery to cross a router.
        socket.set_multicast_ttl_v4(1)?;
        let std_socket: std::net::UdpSocket = socket.into();
        Ok(UdpSocket::from_std(std_socket)?)
    }

    async fn run(self: Arc<Self>, send_socket: UdpSocket, recv_socket: UdpSocket) -> Result<()> {
        let dest: SocketAddr = SocketAddrV4::new(DISCOVERY_MULTICAST_ADDR, DISCOVERY_PORT).into();
        let mut ticker = tokio::time::interval(ANNOUNCE_INTERVAL);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        let mut buf = [0u8; MAX_DATAGRAM_SIZE];

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let payload = self.build_announcement()?;
                    send_socket.send_to(&payload, dest).await?;
                    self.peers.prune_stale(PEER_TIMEOUT);
                }
                recv = recv_socket.recv_from(&mut buf) => {
                    let (len, src) = recv?;
                    self.handle_datagram(&buf[..len], src);
                    self.peers.prune_stale(PEER_TIMEOUT);
                }
            }
        }
    }

    fn build_announcement(&self) -> Result<Vec<u8>> {
        let timestamp_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let announcement = Announcement {
            device_id: self.identity.public_key(),
            display_name: self.display_name.clone(),
            gnp_port: self.gnp_port,
            offers_gateway: self.offers_gateway,
            timestamp_unix,
        };
        let signature = self.identity.sign(&bincode::serialize(&announcement)?).to_vec();
        let signed = SignedAnnouncement {
            announcement,
            signature,
        };
        Ok(bincode::serialize(&signed)?)
    }

    fn handle_datagram(&self, data: &[u8], src: SocketAddr) {
        let Ok(signed) = bincode::deserialize::<SignedAnnouncement>(data) else {
            return; // not a Gabriel announcement (or a corrupt one) -- ignore, don't crash the loop
        };
        if signed.announcement.device_id == self.identity.public_key() {
            return; // heard our own announcement come back via multicast loopback
        }
        let Ok(payload) = bincode::serialize(&signed.announcement) else {
            return;
        };
        let Ok(signature): std::result::Result<[u8; 64], _> = signed.signature.try_into() else {
            return; // wrong-length signature -- can't possibly be valid, drop it
        };
        if !Identity::verify(&signed.announcement.device_id, &payload, &signature) {
            return; // signature didn't check out -- don't trust an unauthenticated peer
        }
        self.peers.upsert(PeerInfo {
            device_id: signed.announcement.device_id,
            display_name: signed.announcement.display_name,
            addr: src,
            gnp_port: signed.announcement.gnp_port,
            offers_gateway: signed.announcement.offers_gateway,
            last_seen: Instant::now(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end proof, not just a unit test of the pieces: two real
    /// DiscoveryService instances, real sockets, real multicast traffic on
    /// loopback -- each should learn the other's device_id within the
    /// timeout. This is the "observable test evidence" the blueprint's own
    /// AI-engineering-layer principle asks for, applied to ourselves.
    #[tokio::test]
    async fn two_peers_discover_each_other() {
        let id_a = Arc::new(Identity::generate_ephemeral());
        let id_b = Arc::new(Identity::generate_ephemeral());

        let svc_a = Arc::new(DiscoveryService::new(id_a.clone(), "peer-a".into(), 11000, false));
        let svc_b = Arc::new(DiscoveryService::new(id_b.clone(), "peer-b".into(), 11001, true));

        let _handle_a = svc_a.clone().spawn().expect("spawn peer a");
        let _handle_b = svc_b.clone().spawn().expect("spawn peer b");

        let result = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let a_knows_b = svc_a.peers().iter().any(|p| p.device_id == id_b.public_key());
                let b_knows_a = svc_b.peers().iter().any(|p| p.device_id == id_a.public_key());
                if a_knows_b && b_knows_a {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;

        assert!(result.is_ok(), "peers did not discover each other within 10s");

        let b_as_seen_by_a = svc_a
            .peers()
            .into_iter()
            .find(|p| p.device_id == id_b.public_key())
            .expect("peer b should be in a's table by now");
        assert!(
            b_as_seen_by_a.offers_gateway,
            "peer b advertised offers_gateway=true, a should have recorded that"
        );
    }

    /// Any device on the LAN can send arbitrary UDP bytes to the discovery
    /// multicast port, no authentication required to *reach* the parser
    /// (authentication only gates whether a parsed announcement is
    /// trusted). This is the most exposed parsing surface in the whole
    /// crate -- it deserves the fuzz coverage more than anything else here.
    #[test]
    fn garbage_datagrams_never_panic_the_parser() {
        crate::fuzz_support::assert_never_panics_on_random_bytes(3000, |bytes| {
            let _ = bincode::deserialize::<SignedAnnouncement>(bytes);
        });
    }

    #[test]
    fn malicious_display_name_length_does_not_hang_or_panic() {
        let identity = Identity::generate_ephemeral();
        let announcement = Announcement {
            device_id: identity.public_key(),
            display_name: "M".repeat(54321), // distinctive length, see replace_first_u64_le
            gnp_port: 1,
            offers_gateway: false,
            timestamp_unix: 1,
        };
        let signature = identity.sign(&bincode::serialize(&announcement).unwrap()).to_vec();
        let signed = SignedAnnouncement { announcement, signature };
        let mut bytes = bincode::serialize(&signed).unwrap();
        crate::fuzz_support::replace_first_u64_le(&mut bytes, 54321, u64::MAX);

        let completed = crate::fuzz_support::completes_within(Duration::from_secs(2), move || {
            let result = bincode::deserialize::<SignedAnnouncement>(&bytes);
            assert!(
                result.is_err(),
                "a display_name length claiming u64::MAX with only ~54KB of real data must fail to parse"
            );
        });
        assert!(completed, "parsing must not hang on a corrupted length prefix");
    }
}
