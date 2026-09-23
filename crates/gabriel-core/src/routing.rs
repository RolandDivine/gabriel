//! Multi-hop mesh routing + store-and-forward.
//!
//! Builds on discovery (which tells a device who its *direct* neighbors
//! are) but solves a different problem: delivering a message to a peer you
//! can't reach directly, by having intermediate peers forward it for you.
//!
//! v0.1 approach: signed messages, flooded to every currently known
//! neighbor, decremented by a hop-count TTL, with a seen-message cache so
//! a peer never re-forwards (or re-delivers) the same message twice. This
//! needs no routing table and no route-discovery protocol -- correctness
//! only depends on there being *some* neighbor chain within TTL hops
//! between sender and destination, which is the right tradeoff for a mesh
//! this size. It wastes bandwidth relative to a real shortest-path
//! protocol (every neighbor gets a copy, not just the one on the best
//! path); that's a deliberate, documented v0.1 simplification -- see the
//! blueprint's Routing Intelligence section for where real path scoring
//! comes in once there's a mesh large enough to need it.
//!
//! The neighbor table here is deliberately decoupled from `discovery`:
//! this module only knows "here are addresses I can reach directly and
//! forward through," not how that list was learned. In normal use the
//! caller syncs it from `DiscoveryService::peers()`; tests populate it
//! directly to build controlled topologies that discovery's real UDP
//! multicast can't simulate on one machine -- multicast on loopback makes
//! every process a direct neighbor of every other, so it can't produce an
//! actual multi-hop scenario by itself.
//!
//! Store-and-forward: `send()` floods to whatever neighbors are known
//! *right now*. If at least one neighbor got it, that's considered this
//! device's job done (full delivery guarantees with acks/retries across
//! the whole path are a later, separate concern -- see the blueprint's
//! pipeline's "ACKNOWLEDGE" stage). If there were *zero* neighbors, the
//! message is persisted to the local SQLite store's `mesh_outbox` table
//! instead of being dropped, and `spawn_retry_task` periodically re-signs
//! (fresh timestamp, same `message_id` so receivers still dedup it
//! correctly) and re-floods anything still queued, until it either goes
//! out or its expiry passes. This is what makes the queue survive a
//! process restart, not just a brief gap between neighbors appearing.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::identity::Identity;
use crate::store::Store;
use crate::wire::{check_freshness, random_id16, read_frame, write_frame, SeenCache};
use crate::Result;

/// Well-known default port for the mesh router, same "fixed for v0.1"
/// pattern as discovery's and the gateway relay's ports.
pub const DEFAULT_MESH_PORT: u16 = 42426;

/// Hop budget for a freshly sent message. Each forward decrements it by
/// one; a message is dropped once it hits zero rather than forwarded
/// again, bounding how far -- and how much traffic -- a single message
/// can generate across the mesh.
const DEFAULT_TTL: u8 = 5;
/// How many recently seen message ids to remember for dedup. Bounded so a
/// long-running node's memory doesn't grow forever; old entries fall off
/// a FIFO once this fills up.
const SEEN_CACHE_CAPACITY: usize = 4096;

/// How long a queued message is retried before being given up on and
/// pruned. A fixed 24h default for v0.1 -- long enough to survive an
/// overnight-offline peer, not so long the queue accumulates forever.
const OUTBOX_TTL_SECS: i64 = 24 * 60 * 60;
/// How often `spawn_retry_task`'s background loop attempts to flush
/// whatever's currently queued.
const RETRY_INTERVAL: Duration = Duration::from_secs(15);

/// Hard cap on concurrently in-flight incoming connections -- see the
/// comment in `serve` for why. Matches the gateway relay's
/// `MAX_CONCURRENT_RELAYS` in spirit; the numbers aren't required to match
/// since the two listeners have different connection-lifetime profiles.
const MAX_CONCURRENT_MESH_CONNECTIONS: usize = 256;

pub type DeviceId = [u8; 32];
pub type MessageId = [u8; 16];

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MessagePayload {
    message_id: MessageId,
    source_id: DeviceId,
    destination_id: DeviceId,
    timestamp_unix: u64,
    body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedMessage {
    payload: MessagePayload,
    signature: Vec<u8>,
    /// Hop budget, decremented on every forward. Deliberately OUTSIDE the
    /// signed payload: it's per-hop transport metadata that every
    /// forwarding node mutates, not something the original sender vouches
    /// for. Keeping it out of the signature means a forward never needs
    /// to (and, without the source's private key, never could) re-sign
    /// anything -- the same signature stays valid end-to-end, so the
    /// destination verifies it really came from `source_id`, not just
    /// from whichever peer forwarded it last.
    ttl: u8,
}

/// A message that arrived addressed to us -- handed to whoever is
/// consuming the receiver half returned by `MeshRouter::new`.
#[derive(Debug, Clone)]
pub struct DeliveredMessage {
    pub source_id: DeviceId,
    pub body: Vec<u8>,
}

/// Addresses of peers we can reach with one direct TCP connection. Shared
/// (cheaply cloneable) so a background task can keep it in sync with
/// discovery while the router reads it on every send/forward.
#[derive(Clone, Default)]
pub struct NeighborTable {
    inner: Arc<Mutex<HashMap<DeviceId, SocketAddr>>>,
}

impl NeighborTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(&self, device_id: DeviceId, addr: SocketAddr) {
        self.inner.lock().unwrap().insert(device_id, addr);
    }

    pub fn remove(&self, device_id: &DeviceId) {
        self.inner.lock().unwrap().remove(device_id);
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every neighbor we currently know how to reach, as (id, address)
    /// pairs. The UI lists these so a user can see -- and prune -- the
    /// table that flooding actually walks, rather than inferring it from
    /// the discovery peer list (which also contains unroutable peers).
    pub fn list(&self) -> Vec<(DeviceId, SocketAddr)> {
        self.snapshot()
    }

    fn snapshot(&self) -> Vec<(DeviceId, SocketAddr)> {
        self.inner.lock().unwrap().iter().map(|(k, v)| (*k, *v)).collect()
    }
}

/// Floods signed messages to known neighbors, forwards what isn't ours,
/// and delivers what is.
pub struct MeshRouter {
    identity: Arc<Identity>,
    neighbors: NeighborTable,
    seen: Mutex<SeenCache>,
    inbox_tx: mpsc::UnboundedSender<DeliveredMessage>,
    store: Arc<Store>,
}

impl MeshRouter {
    /// Returns the router and the receiving half of its delivery channel --
    /// hold onto the receiver and poll it for anything addressed to us.
    /// `store` backs the outbound retry queue; pass `Store::open_in_memory`
    /// for a router that doesn't need its queue to survive a restart
    /// (mainly tests), or `Store::open(path)` for a real one.
    pub fn new(
        identity: Arc<Identity>,
        neighbors: NeighborTable,
        store: Arc<Store>,
    ) -> (Arc<Self>, mpsc::UnboundedReceiver<DeliveredMessage>) {
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel();
        (
            Arc::new(Self {
                identity,
                neighbors,
                seen: Mutex::new(SeenCache::new(SEEN_CACHE_CAPACITY)),
                inbox_tx,
                store,
            }),
            inbox_rx,
        )
    }

    pub fn neighbors(&self) -> NeighborTable {
        self.neighbors.clone()
    }

    /// Binds `bind_addr` and starts serving forwarded/incoming messages in
    /// the background. Returns the address actually bound (useful when
    /// `bind_addr`'s port is 0).
    pub async fn listen(self: Arc<Self>, bind_addr: SocketAddr) -> Result<SocketAddr> {
        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        tokio::spawn(self.serve(listener));
        Ok(local_addr)
    }

    async fn serve(self: Arc<Self>, listener: TcpListener) {
        // Same rationale as the gateway relay's cap: each incoming
        // connection is handled on its own spawned task, so with no limit
        // a flood of connections could exhaust sockets/memory. Mesh
        // connections here are normally short-lived (connect, one frame,
        // close), so this mostly guards against a burst flood rather than
        // long-held sessions -- unlike the gateway relay's cap, which
        // guards sessions that stay open indefinitely.
        let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_MESH_CONNECTIONS));
        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(err) => {
                    eprintln!("mesh: accept failed, stopping: {err:#}");
                    return;
                }
            };
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                eprintln!(
                    "mesh: at capacity ({MAX_CONCURRENT_MESH_CONNECTIONS} concurrent connections) \
                     -- rejecting connection from {peer_addr}"
                );
                continue; // dropping `stream` here closes the connection
            };
            let this = self.clone();
            tokio::spawn(async move {
                let _permit = permit;
                if let Err(err) = this.handle_incoming(stream).await {
                    eprintln!("mesh: connection from {peer_addr} ended: {err:#}");
                }
            });
        }
    }

    async fn handle_incoming(self: Arc<Self>, mut stream: TcpStream) -> Result<()> {
        let signed: SignedMessage = read_frame(&mut stream).await?;
        self.process(signed).await
    }

    /// Signs and floods a new message toward `destination_id`. Returns how
    /// many neighbors it was handed to right now. If that's 0, the message
    /// is persisted to the local outbox instead of being dropped --
    /// `spawn_retry_task` (or a manual `retry_pending()` call) will pick it
    /// up once a neighbor appears.
    pub async fn send(&self, destination_id: DeviceId, body: Vec<u8>) -> Result<usize> {
        let message_id = random_id16();
        // Record our own message so we ignore it if it ever floods back to us.
        self.seen.lock().unwrap().insert_if_new(message_id);

        let sent_to = self.sign_and_flood(message_id, destination_id, &body).await?;

        if sent_to == 0 {
            let now = now_unix()?;
            self.store
                .enqueue_outbound(&message_id, &destination_id, &body, now, now + OUTBOX_TTL_SECS)?;
        }
        Ok(sent_to)
    }

    /// Builds a fresh signed envelope (new timestamp, so it passes the
    /// receiver's freshness check even on a retry) for the given logical
    /// message and floods it to whoever's currently a neighbor.
    async fn sign_and_flood(&self, message_id: MessageId, destination_id: DeviceId, body: &[u8]) -> Result<usize> {
        let timestamp_unix = now_unix()? as u64;
        let payload = MessagePayload {
            message_id,
            source_id: self.identity.public_key(),
            destination_id,
            timestamp_unix,
            body: body.to_vec(),
        };
        let signature = self.identity.sign(&bincode::serialize(&payload)?).to_vec();
        let signed = SignedMessage {
            payload,
            signature,
            ttl: DEFAULT_TTL,
        };
        Ok(self.flood(&signed).await)
    }

    /// Attempts to flush the outbox: prunes anything past its expiry, then
    /// (if there's at least one neighbor right now) re-signs and re-floods
    /// everything still queued, removing whatever gets handed to at least
    /// one neighbor. Returns how many messages were sent out this pass.
    pub async fn retry_pending(&self) -> Result<usize> {
        let now = now_unix()?;
        let pruned = self.store.prune_expired_outbound(now)?;
        if pruned > 0 {
            eprintln!("mesh: gave up on {pruned} queued message(s) past their expiry");
        }

        if self.neighbors.is_empty() {
            return Ok(0); // nothing to try yet, don't bother touching the DB further
        }

        let mut delivered = 0;
        for pending in self.store.list_pending_outbound()? {
            let sent_to = self
                .sign_and_flood(pending.message_id, pending.destination_id, &pending.body)
                .await?;
            if sent_to > 0 {
                self.store.remove_outbound(&pending.message_id)?;
                delivered += 1;
            } else {
                self.store.record_attempt(&pending.message_id, now)?;
            }
        }
        Ok(delivered)
    }

    /// Spawns a background task that calls `retry_pending` on a fixed
    /// interval for as long as the returned handle (or the router itself)
    /// is alive.
    pub fn spawn_retry_task(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(RETRY_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if let Err(err) = self.retry_pending().await {
                    eprintln!("mesh: outbox retry failed: {err:#}");
                }
            }
        })
    }

    async fn process(&self, signed: SignedMessage) -> Result<()> {
        Self::authenticate(&signed)?;

        let is_new = self.seen.lock().unwrap().insert_if_new(signed.payload.message_id);
        if !is_new {
            return Ok(()); // duplicate delivery of a message we already handled
        }

        if signed.payload.destination_id == self.identity.public_key() {
            let _ = self.inbox_tx.send(DeliveredMessage {
                source_id: signed.payload.source_id,
                body: signed.payload.body.clone(),
            });
            return Ok(()); // delivered locally -- not forwarded any further
        }

        if signed.ttl == 0 {
            return Ok(()); // hop budget exhausted, drop silently
        }

        let mut forwarded = signed;
        forwarded.ttl -= 1; // payload and signature are untouched -- see SignedMessage's doc comment
        self.flood(&forwarded).await;
        Ok(())
    }

    /// Best-effort: hands `signed` to every currently known neighbor. A
    /// single unreachable neighbor doesn't stop delivery to the rest --
    /// each send is independent and errors there are swallowed (logged),
    /// since one bad link shouldn't sink the whole flood.
    async fn flood(&self, signed: &SignedMessage) -> usize {
        let mut delivered_to = 0;
        for (_, addr) in self.neighbors.snapshot() {
            match Self::send_to(addr, signed).await {
                Ok(()) => delivered_to += 1,
                Err(err) => eprintln!("mesh: couldn't forward to neighbor at {addr}: {err:#}"),
            }
        }
        delivered_to
    }

    async fn send_to(addr: SocketAddr, signed: &SignedMessage) -> Result<()> {
        let mut stream = TcpStream::connect(addr).await?;
        write_frame(&mut stream, signed).await
    }

    fn authenticate(signed: &SignedMessage) -> Result<()> {
        let signature: [u8; 64] = signed
            .signature
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("malformed signature"))?;
        let payload_bytes = bincode::serialize(&signed.payload)?;
        if !Identity::verify(&signed.payload.source_id, &payload_bytes, &signature) {
            anyhow::bail!("signature verification failed");
        }
        check_freshness(signed.payload.timestamp_unix).map_err(|reason| anyhow::anyhow!(reason))?;
        Ok(())
    }
}

fn now_unix() -> Result<i64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_store() -> Arc<Store> {
        Arc::new(Store::open_in_memory().unwrap())
    }

    /// Wires three routers into a line topology -- A knows only B, C knows
    /// only B, B knows both -- entirely by hand (not discovery, which can't
    /// produce a real multi-hop scenario on one machine). A message from A
    /// should still reach C by forwarding through B, proving the flood +
    /// TTL + dedup mechanism actually does multi-hop delivery, not just
    /// direct 1-hop send.
    #[tokio::test]
    async fn message_reaches_a_two_hop_destination_through_an_intermediate_peer() {
        let id_a = Arc::new(Identity::generate_ephemeral());
        let id_b = Arc::new(Identity::generate_ephemeral());
        let id_c = Arc::new(Identity::generate_ephemeral());

        let neighbors_a = NeighborTable::new();
        let neighbors_b = NeighborTable::new();
        let neighbors_c = NeighborTable::new();

        let (router_a, _inbox_a) = MeshRouter::new(id_a.clone(), neighbors_a.clone(), test_store());
        let (router_b, _inbox_b) = MeshRouter::new(id_b.clone(), neighbors_b.clone(), test_store());
        let (router_c, mut inbox_c) = MeshRouter::new(id_c.clone(), neighbors_c.clone(), test_store());

        let addr_a = router_a.clone().listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr_b = router_b.clone().listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr_c = router_c.clone().listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

        // Line topology: A -- B -- C. A and C are NOT each other's neighbors.
        neighbors_a.set(id_b.public_key(), addr_b);
        neighbors_b.set(id_a.public_key(), addr_a);
        neighbors_b.set(id_c.public_key(), addr_c);
        neighbors_c.set(id_b.public_key(), addr_b);

        let sent_to = router_a.send(id_c.public_key(), b"hello from a".to_vec()).await.unwrap();
        assert_eq!(sent_to, 1, "a only has one neighbor (b) to flood to");

        let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), inbox_c.recv())
            .await
            .expect("c should receive the message within the timeout")
            .expect("inbox channel should still be open");

        assert_eq!(delivered.source_id, id_a.public_key());
        assert_eq!(delivered.body, b"hello from a");
    }

    /// Same line topology, but TTL is exhausted after one hop, so the
    /// message should die at B and never reach C. This is what actually
    /// proves TTL does something -- without it, the previous test alone
    /// couldn't distinguish "multi-hop routing works" from "there's no hop
    /// limit at all."
    #[tokio::test]
    async fn message_is_dropped_once_ttl_is_exhausted() {
        let id_a = Arc::new(Identity::generate_ephemeral());
        let id_b = Arc::new(Identity::generate_ephemeral());
        let id_c = Arc::new(Identity::generate_ephemeral());

        let neighbors_a = NeighborTable::new();
        let neighbors_b = NeighborTable::new();
        let neighbors_c = NeighborTable::new();

        let (router_a, _inbox_a) = MeshRouter::new(id_a.clone(), neighbors_a.clone(), test_store());
        let (router_b, _inbox_b) = MeshRouter::new(id_b.clone(), neighbors_b.clone(), test_store());
        let (router_c, mut inbox_c) = MeshRouter::new(id_c.clone(), neighbors_c.clone(), test_store());

        let addr_a = router_a.clone().listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr_b = router_b.clone().listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
        let addr_c = router_c.clone().listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

        neighbors_a.set(id_b.public_key(), addr_b);
        neighbors_b.set(id_a.public_key(), addr_a);
        neighbors_b.set(id_c.public_key(), addr_c);
        neighbors_c.set(id_b.public_key(), addr_b);

        // Build the message by hand, delivered directly to B with TTL=0:
        // "you may deliver this if you're the destination, but you may NOT
        // forward it on." B isn't the destination, so it must drop this
        // rather than forward to C.
        let message_id = random_id16();
        let timestamp_unix = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let payload = MessagePayload {
            message_id,
            source_id: id_a.public_key(),
            destination_id: id_c.public_key(),
            timestamp_unix,
            body: b"should not arrive".to_vec(),
        };
        let signature = id_a.sign(&bincode::serialize(&payload).unwrap()).to_vec();
        let signed = SignedMessage {
            payload,
            signature,
            ttl: 0,
        };
        MeshRouter::send_to(addr_b, &signed).await.unwrap();

        let result = tokio::time::timeout(std::time::Duration::from_secs(2), inbox_c.recv()).await;
        assert!(result.is_err(), "c should NOT receive a message whose TTL ran out at b");
    }

    #[test]
    fn seen_cache_rejects_duplicates_and_evicts_oldest_past_capacity() {
        let mut cache = SeenCache::new(2);
        let a = [1u8; 16];
        let b = [2u8; 16];
        let c = [3u8; 16];

        assert!(cache.insert_if_new(a));
        assert!(!cache.insert_if_new(a), "a is a duplicate the second time");
        assert!(cache.insert_if_new(b));
        assert!(cache.insert_if_new(c), "c is new");
        // Capacity is 2, so inserting c should have evicted a.
        assert!(cache.insert_if_new(a), "a should be forgotten after eviction");
    }

    /// Sending with zero neighbors must not silently lose the message --
    /// this is the exact gap store-and-forward closes. Confirms both
    /// halves: `send()` reports 0 delivered, and the message is actually
    /// sitting in the durable outbox afterward (not just "not an error").
    #[tokio::test]
    async fn send_with_no_neighbors_queues_instead_of_dropping() {
        let identity = Arc::new(Identity::generate_ephemeral());
        let store = test_store();
        let (router, _inbox) = MeshRouter::new(identity, NeighborTable::new(), store.clone());

        let destination = Identity::generate_ephemeral().public_key();
        let sent_to = router.send(destination, b"nobody's listening yet".to_vec()).await.unwrap();
        assert_eq!(sent_to, 0);

        let pending = store.list_pending_outbound().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].destination_id, destination);
        assert_eq!(pending[0].body, b"nobody's listening yet");
    }

    /// A message queued while isolated should actually go out -- and be
    /// removed from the outbox -- once a neighbor shows up and
    /// `retry_pending` runs. This is the "forward" half of store-and-
    /// forward: proves the queue isn't just a write-only log.
    #[tokio::test]
    async fn retry_delivers_a_queued_message_once_a_neighbor_appears() {
        let id_sender = Arc::new(Identity::generate_ephemeral());
        let id_dest = Arc::new(Identity::generate_ephemeral());

        let sender_neighbors = NeighborTable::new();
        let (sender, _sender_inbox) = MeshRouter::new(id_sender.clone(), sender_neighbors.clone(), test_store());
        let (dest_router, mut dest_inbox) =
            MeshRouter::new(id_dest.clone(), NeighborTable::new(), test_store());
        let dest_addr = dest_router.clone().listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

        // Send while completely isolated -- must queue, not deliver.
        let sent_to = sender.send(id_dest.public_key(), b"catch up later".to_vec()).await.unwrap();
        assert_eq!(sent_to, 0);

        // A neighbor "appears" -- wire the destination into the sender's table.
        sender_neighbors.set(id_dest.public_key(), dest_addr);

        let delivered_count = sender.retry_pending().await.unwrap();
        assert_eq!(delivered_count, 1);

        let delivered = tokio::time::timeout(std::time::Duration::from_secs(5), dest_inbox.recv())
            .await
            .expect("destination should receive the retried message")
            .expect("inbox channel should still be open");
        assert_eq!(delivered.body, b"catch up later");

        // And the outbox should be empty now that it actually went out.
        assert!(sender.retry_pending().await.unwrap() == 0, "nothing left to retry");
    }

    /// Any TCP client can connect to the mesh port and send bytes --
    /// `read_frame` parses `SignedMessage` before `authenticate` runs, same
    /// exposure pattern as the gateway relay's request parser.
    #[test]
    fn garbage_mesh_messages_never_panic_the_parser() {
        crate::fuzz_support::assert_never_panics_on_random_bytes(3000, |bytes| {
            let _ = bincode::deserialize::<SignedMessage>(bytes);
        });
    }

    #[test]
    fn malicious_body_length_does_not_hang_or_panic() {
        let payload = MessagePayload {
            message_id: [0u8; 16],
            source_id: [0u8; 32],
            destination_id: [0u8; 32],
            timestamp_unix: 1,
            body: vec![0u8; 27182], // distinctive length, see replace_first_u64_le
        };
        let signature = vec![0u8; 64]; // doesn't need to verify -- parser runs before auth
        let signed = SignedMessage { payload, signature, ttl: 5 };
        let mut bytes = bincode::serialize(&signed).unwrap();
        crate::fuzz_support::replace_first_u64_le(&mut bytes, 27182, u64::MAX);

        let completed = crate::fuzz_support::completes_within(std::time::Duration::from_secs(2), move || {
            let result = bincode::deserialize::<SignedMessage>(&bytes);
            assert!(
                result.is_err(),
                "a body length claiming u64::MAX with only ~27KB of real data must fail to parse"
            );
        });
        assert!(completed, "parsing must not hang on a corrupted length prefix");
    }
    /// The UI lists the neighbour table directly, so `list` has to agree
    /// with what `set`/`remove` actually did -- not just with `len`.
    #[test]
    fn neighbor_table_list_reflects_set_and_remove() {
        let table = NeighborTable::new();
        let a = [1u8; 32];
        let b = [2u8; 32];
        let addr_a: SocketAddr = "127.0.0.1:9001".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:9002".parse().unwrap();

        assert!(table.list().is_empty());

        table.set(a, addr_a);
        table.set(b, addr_b);
        let mut listed = table.list();
        listed.sort_by_key(|(id, _)| *id);
        assert_eq!(listed, vec![(a, addr_a), (b, addr_b)]);
        assert_eq!(listed.len(), table.len());

        table.remove(&a);
        assert_eq!(table.list(), vec![(b, addr_b)]);
    }

}
