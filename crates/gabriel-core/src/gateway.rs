//! Gateway sharing -- a mesh peer with real internet access relays TCP
//! connections for peers that don't have one, per the blueprint's
//! "Community Internet" / gateway-sharing connectivity mode.
//!
//! v0.1 scope: a minimal authenticated CONNECT-style TCP tunnel. A peer
//! opens a connection to a gateway, proves it controls a real Gabriel
//! identity (a signed request -- same pattern as discovery announcements),
//! names a target host:port, and -- if the gateway accepts -- the
//! connection becomes a raw byte pipe: peer <-> gateway <-> target.
//! Nothing here inspects or restricts what rides inside that pipe (HTTP,
//! HTTPS, anything else over TCP all work identically), which mirrors how
//! a real internet-sharing gateway behaves.
//!
//! What's deliberately NOT here yet: an admission policy (today, any
//! device with a keypair can ask -- the blueprint's "CREATE NETWORK"
//! capability-based invitation flow is what should gate this later),
//! bandwidth accounting, and GACL-driven gateway selection. This proves
//! the relay mechanism; those are separate, layered concerns.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::admission::{Admission, AdmissionControl, SignedInvitation};
use crate::identity::Identity;
use crate::metering::{MeteredStream, QuotaDecision, SessionMeter, UsageLedger};
use crate::wire::{random_id16, read_frame, write_frame, SeenCache};
use crate::Result;

/// Well-known default port for the gateway relay, same "fixed for v0.1"
/// approach as discovery's port -- revisit once GACL needs to negotiate it.
pub const DEFAULT_GATEWAY_PORT: u16 = 42425;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How many recent request nonces to remember for replay rejection. Same
/// capacity discovery/routing use for their own seen-caches.
const SEEN_CACHE_CAPACITY: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GatewayRequestPayload {
    device_id: [u8; 32],
    timestamp_unix: u64,
    /// Random per-request id. Exists purely so `authenticate` can reject a
    /// captured, validly-signed request that gets resent -- without this,
    /// the same signed bytes replayed within the timestamp freshness
    /// window would be accepted again every time (see the module's test
    /// `replaying_a_captured_request_is_rejected_the_second_time`, and its
    /// git history for the version that demonstrated this as a real gap
    /// before the field existed).
    nonce: [u8; 16],
    target_host: String,
    target_port: u16,
    /// A capability this gateway signed, when the requester has one.
    /// Optional because an open gateway needs none -- see `admission`.
    invitation: Option<SignedInvitation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedGatewayRequest {
    payload: GatewayRequestPayload,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct GatewayResponse {
    accepted: bool,
    reason: Option<String>,
}

/// Hard cap on concurrently active relay sessions. Each one holds an
/// outbound TCP connection open indefinitely (until either side closes),
/// so with no limit a flood of connections -- malicious or just a busy
/// LAN -- could exhaust file descriptors / sockets. This is the concrete
/// "gateway-level mitigation" the threat model's "Traffic flooding" row
/// calls for. A connection beyond the cap is rejected immediately (closed
/// without a response) rather than queued, so a flood degrades to "new
/// connections get refused" instead of unbounded memory/handle growth.
const MAX_CONCURRENT_RELAYS: usize = 256;

/// The relay side: accepts requests, authenticates them, dials the
/// requested target, and pipes bytes until either end closes. Holds the
/// nonce seen-cache, so it needs to be a real instance now (not just a
/// namespace for associated functions) -- use `GatewayServer::new()`.
pub struct GatewayServer {
    seen: Mutex<SeenCache>,
    /// Byte accounting, when the gateway is metered. `None` keeps the
    /// pre-metering behaviour: relay for anyone, count nothing. A gateway
    /// that intends to charge for bandwidth passes one.
    ledger: Option<Arc<UsageLedger>>,
    /// Who may ask at all. `None` admits anyone, which is what the
    /// gateway did before `admission` existed.
    admission: Option<Arc<AdmissionControl>>,
}

impl GatewayServer {
    /// An unmetered gateway: relays for anyone, counts nothing.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(SeenCache::new(SEEN_CACHE_CAPACITY)),
            ledger: None,
            admission: None,
        })
    }

    /// A metered gateway. Every session is counted against the device
    /// that opened it, quotas are enforced while bytes are moving rather
    /// than only at connect time, and the accounting survives a restart
    /// because it lives in the store rather than in memory.
    pub fn metered(ledger: Arc<UsageLedger>) -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(SeenCache::new(SEEN_CACHE_CAPACITY)),
            ledger: Some(ledger),
            admission: None,
        })
    }

    /// A metered gateway that also decides who may ask. This is the full
    /// configuration a gateway selling bandwidth runs: admission answers
    /// *who*, metering answers *how much*.
    pub fn guarded(ledger: Arc<UsageLedger>, admission: Arc<AdmissionControl>) -> Arc<Self> {
        Arc::new(Self {
            seen: Mutex::new(SeenCache::new(SEEN_CACHE_CAPACITY)),
            ledger: Some(ledger),
            admission: Some(admission),
        })
    }

    /// The access list this gateway enforces, if it enforces one.
    pub fn admission(&self) -> Option<&Arc<AdmissionControl>> {
        self.admission.as_ref()
    }

    /// The ledger this gateway meters against, if it is metered at all.
    pub fn ledger(&self) -> Option<&Arc<UsageLedger>> {
        self.ledger.as_ref()
    }

    /// Binds `bind_addr` and serves forever.
    pub async fn run(self: Arc<Self>, bind_addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        self.serve(listener).await
    }

    /// Serves an already-bound listener. Split out from `run` so tests (and
    /// callers that want to bind to port 0 and discover the real port) can
    /// get the listener's address before the accept loop starts.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        self.serve_with_limit(listener, MAX_CONCURRENT_RELAYS).await
    }

    /// Same as `serve`, with the concurrency cap as a parameter so tests
    /// can exercise it without actually opening hundreds of connections.
    async fn serve_with_limit(self: Arc<Self>, listener: TcpListener, max_concurrent: usize) -> Result<()> {
        let permits = Arc::new(Semaphore::new(max_concurrent));
        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let Ok(permit) = permits.clone().try_acquire_owned() else {
                eprintln!(
                    "gateway: at capacity ({max_concurrent} concurrent relays) -- rejecting connection from {peer_addr}"
                );
                continue; // dropping `stream` here closes the connection
            };
            let this = self.clone();
            tokio::spawn(async move {
                let _permit = permit; // held for the whole relay session
                if let Err(err) = this.handle_connection(stream).await {
                    eprintln!("gateway: connection from {peer_addr} ended: {err:#}");
                }
            });
        }
    }

    async fn handle_connection(self: Arc<Self>, mut client: TcpStream) -> Result<()> {
        let request: SignedGatewayRequest = read_frame(&mut client).await?;

        if let Err(reason) = self.authenticate(&request) {
            write_frame(
                &mut client,
                &GatewayResponse {
                    accepted: false,
                    reason: Some(reason.clone()),
                },
            )
            .await?;
            anyhow::bail!("rejected gateway request: {reason}");
        }

        // Admission first: whether a device may ask at all is a cheaper
        // and more fundamental question than how much it has left, and a
        // refused device should not touch the quota tables.
        if let Some(admission) = &self.admission {
            match admission.admit(&request.payload.device_id, request.payload.invitation.as_ref())? {
                Admission::Admit { reason } => {
                    eprintln!(
                        "gateway: admitting {} ({})",
                        crate::hex_encode(&request.payload.device_id),
                        reason.as_str()
                    );
                }
                Admission::Refuse { reason } => {
                    write_frame(
                        &mut client,
                        &GatewayResponse {
                            accepted: false,
                            reason: Some(reason.clone()),
                        },
                    )
                    .await?;
                    anyhow::bail!(
                        "not admitted {}: {reason}",
                        crate::hex_encode(&request.payload.device_id)
                    );
                }
            }
        }

        // Quota is checked before the target is dialled, so a device that
        // is out of allowance never causes an outbound connection.
        let remaining = match &self.ledger {
            None => crate::metering::UNLIMITED,
            Some(ledger) => match ledger.authorize(&request.payload.device_id)? {
                QuotaDecision::Allow { remaining } => remaining,
                QuotaDecision::Deny { reason } => {
                    write_frame(
                        &mut client,
                        &GatewayResponse {
                            accepted: false,
                            reason: Some(reason.clone()),
                        },
                    )
                    .await?;
                    anyhow::bail!("refused {}: {reason}", crate::hex_encode(&request.payload.device_id));
                }
            },
        };

        let target_host = request.payload.target_host.clone();
        let target_port = request.payload.target_port;
        let target = match timeout(
            CONNECT_TIMEOUT,
            TcpStream::connect((target_host.as_str(), target_port)),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                let reason = format!("couldn't reach {target_host}:{target_port}: {err}");
                write_frame(
                    &mut client,
                    &GatewayResponse {
                        accepted: false,
                        reason: Some(reason.clone()),
                    },
                )
                .await?;
                anyhow::bail!(reason);
            }
            Err(_) => {
                let reason = format!("timed out connecting to {target_host}:{target_port}");
                write_frame(
                    &mut client,
                    &GatewayResponse {
                        accepted: false,
                        reason: Some(reason.clone()),
                    },
                )
                .await?;
                anyhow::bail!(reason);
            }
        };

        write_frame(
            &mut client,
            &GatewayResponse {
                accepted: true,
                reason: None,
            },
        )
        .await?;

        let mut target = target;
        let device_id = request.payload.device_id;
        let destination = format!("{target_host}:{target_port}");

        // Unmetered: the original path, unchanged.
        let Some(ledger) = self.ledger.clone() else {
            let (to_target, to_client) = copy_bidirectional(&mut client, &mut target).await?;
            eprintln!(
                "gateway: session for {} to {destination} closed ({to_target} bytes out, {to_client} bytes back)",
                crate::hex_encode(&device_id)
            );
            return Ok(());
        };

        // Metered. `remaining` was decided by `authorize` before the
        // target was dialled, so a device over quota never causes an
        // outbound connection at all.
        let meter = SessionMeter::new(random_id16(), device_id, &destination, remaining);
        ledger.checkpoint(&meter)?;
        let checkpoint = ledger.spawn_checkpoint_task(meter.clone());

        // Wrapping only the client side meters both directions: reading
        // from the client is upload, writing to it is download.
        let mut metered_client = MeteredStream::new(client, meter.clone());
        let outcome = copy_bidirectional(&mut metered_client, &mut target).await;

        checkpoint.abort();
        ledger.close(&meter)?;

        if meter.is_exhausted() {
            eprintln!(
                "gateway: session for {} to {destination} cut off at its quota ({} bytes)",
                crate::hex_encode(&device_id),
                meter.total()
            );
            // Not an error from the gateway's point of view -- the limit
            // did what it was for.
            return Ok(());
        }

        outcome?;
        eprintln!(
            "gateway: session for {} to {destination} closed ({} up, {} down, {} left)",
            crate::hex_encode(&device_id),
            meter.bytes_up(),
            meter.bytes_down(),
            meter.remaining()
        );
        Ok(())
    }

    fn authenticate(&self, request: &SignedGatewayRequest) -> std::result::Result<(), String> {
        let signature: [u8; 64] = request
            .signature
            .clone()
            .try_into()
            .map_err(|_| "malformed signature".to_string())?;
        let payload_bytes = bincode::serialize(&request.payload).map_err(|e| e.to_string())?;
        if !Identity::verify(&request.payload.device_id, &payload_bytes, &signature) {
            return Err("signature verification failed".to_string());
        }

        crate::wire::check_freshness(request.payload.timestamp_unix)?;

        // Only record the nonce once the request is otherwise genuine --
        // no point letting unauthenticated garbage consume seen-cache
        // slots meant for real replay detection.
        let is_new = self.seen.lock().unwrap().insert_if_new(request.payload.nonce);
        if !is_new {
            return Err("replayed request (nonce already seen)".to_string());
        }
        Ok(())
    }
}

/// The requesting side: dials a gateway, proves identity, and -- once
/// accepted -- hands back a plain `TcpStream` whose bytes go straight
/// to/from `target_host:target_port` via the gateway. Callers use it
/// exactly like any other TCP connection to the target; the relay is
/// invisible past the handshake.
pub struct GatewayClient;

impl GatewayClient {
    pub async fn connect_via(
        identity: &Identity,
        gateway_addr: SocketAddr,
        target_host: &str,
        target_port: u16,
    ) -> Result<TcpStream> {
        Self::connect_via_with_invitation(identity, gateway_addr, target_host, target_port, None)
            .await
    }

    /// Same, presenting a capability the gateway issued. Needed for a
    /// gateway running an invitation-only policy.
    pub async fn connect_via_with_invitation(
        identity: &Identity,
        gateway_addr: SocketAddr,
        target_host: &str,
        target_port: u16,
        invitation: Option<SignedInvitation>,
    ) -> Result<TcpStream> {
        let mut stream = TcpStream::connect(gateway_addr).await?;

        let timestamp_unix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let payload = GatewayRequestPayload {
            device_id: identity.public_key(),
            timestamp_unix,
            nonce: random_id16(),
            target_host: target_host.to_string(),
            target_port,
            invitation,
        };
        let signature = identity.sign(&bincode::serialize(&payload)?).to_vec();
        let request = SignedGatewayRequest { payload, signature };
        write_frame(&mut stream, &request).await?;

        let response: GatewayResponse = read_frame(&mut stream).await?;
        if !response.accepted {
            anyhow::bail!(
                "gateway rejected the request: {}",
                response.reason.unwrap_or_else(|| "no reason given".to_string())
            );
        }
        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// End-to-end: a real gateway server, a real target TCP server, and a
    /// real client tunneling through the gateway to reach it -- all on
    /// loopback, which exercises exactly the same code path a real
    /// two-machine deployment would use (only the addresses differ).
    #[tokio::test]
    async fn relays_a_tcp_connection_to_the_requested_target() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = target_listener.accept().await {
                let mut buf = [0u8; 5];
                if sock.read_exact(&mut buf).await.is_ok() {
                    let _ = sock.write_all(&buf).await;
                }
            }
        });

        let gw_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = gw_listener.local_addr().unwrap();
        tokio::spawn(GatewayServer::new().serve(gw_listener));

        let identity = Identity::generate_ephemeral();
        let mut tunnel = GatewayClient::connect_via(&identity, gw_addr, "127.0.0.1", target_addr.port())
            .await
            .expect("gateway should have accepted a validly signed request");

        tunnel.write_all(b"hello").await.unwrap();
        let mut echoed = [0u8; 5];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hello");
    }

    /// A request whose signature doesn't match its claimed device_id must
    /// be rejected before the gateway ever dials the target -- this is the
    /// concrete authentication control the threat model's "Fake identity" /
    /// "Malicious gateway" rows call for.
    #[tokio::test]
    async fn rejects_a_request_with_a_forged_signature() {
        let gw_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = gw_listener.local_addr().unwrap();
        tokio::spawn(GatewayServer::new().serve(gw_listener));

        let real_signer = Identity::generate_ephemeral();
        let claimed_identity = Identity::generate_ephemeral();

        let mut stream = TcpStream::connect(gw_addr).await.unwrap();
        let payload = GatewayRequestPayload {
            device_id: claimed_identity.public_key(), // lying about who we are
            timestamp_unix: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            nonce: [0u8; 16],
            target_host: "127.0.0.1".to_string(),
            target_port: 1,
            invitation: None,
        };
        // Signed by the WRONG key -- doesn't match device_id above.
        let signature = real_signer.sign(&bincode::serialize(&payload).unwrap()).to_vec();
        let request = SignedGatewayRequest { payload, signature };
        write_frame(&mut stream, &request).await.unwrap();

        let response: GatewayResponse = read_frame(&mut stream).await.unwrap();
        assert!(!response.accepted, "a forged-signature request must not be accepted");
    }

    /// Any TCP client can connect to the gateway port and send bytes --
    /// `read_frame` parses `SignedGatewayRequest` *before* `authenticate`
    /// ever runs, so this parser is reachable with zero credentials. Most
    /// exposed surface in this module; deserves the fuzz coverage most.
    #[test]
    fn garbage_gateway_requests_never_panic_the_parser() {
        crate::fuzz_support::assert_never_panics_on_random_bytes(3000, |bytes| {
            let _ = bincode::deserialize::<SignedGatewayRequest>(bytes);
        });
    }

    #[test]
    fn malicious_target_host_length_does_not_hang_or_panic() {
        let payload = GatewayRequestPayload {
            device_id: [0u8; 32],
            timestamp_unix: 1,
            nonce: [0u8; 16],
            target_host: "H".repeat(31415), // distinctive length, see replace_first_u64_le
            target_port: 80,
            invitation: None,
        };
        // Signature doesn't need to verify -- the parser runs before auth.
        let signature = vec![0u8; 64];
        let request = SignedGatewayRequest { payload, signature };
        let mut bytes = bincode::serialize(&request).unwrap();
        crate::fuzz_support::replace_first_u64_le(&mut bytes, 31415, u64::MAX);

        let completed = crate::fuzz_support::completes_within(Duration::from_secs(2), move || {
            let result = bincode::deserialize::<SignedGatewayRequest>(&bytes);
            assert!(
                result.is_err(),
                "a target_host length claiming u64::MAX with only ~31KB of real data must fail to parse"
            );
        });
        assert!(completed, "parsing must not hang on a corrupted length prefix");
    }

    /// Before the `nonce` field existed, this exact scenario was verified
    /// to succeed *twice* -- a captured, validly-signed request replayed
    /// within the timestamp freshness window got a fresh tunnel both
    /// times. The nonce + seen-cache in `authenticate` closes that: the
    /// second attempt with identical signed bytes must now be rejected.
    #[tokio::test]
    async fn replaying_a_captured_request_is_rejected_the_second_time() {
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                if let Ok((mut sock, _)) = target_listener.accept().await {
                    tokio::spawn(async move {
                        let mut buf = [0u8; 16];
                        let _ = sock.read(&mut buf).await;
                    });
                }
            }
        });

        let gw_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = gw_listener.local_addr().unwrap();
        tokio::spawn(GatewayServer::new().serve(gw_listener));

        let identity = Identity::generate_ephemeral();
        let payload = GatewayRequestPayload {
            device_id: identity.public_key(),
            timestamp_unix: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            nonce: [42u8; 16],
            target_host: "127.0.0.1".to_string(),
            target_port: target_addr.port(),
            invitation: None,
        };
        let signature = identity.sign(&bincode::serialize(&payload).unwrap()).to_vec();
        let captured = SignedGatewayRequest { payload, signature };

        let mut first = TcpStream::connect(gw_addr).await.unwrap();
        write_frame(&mut first, &captured).await.unwrap();
        let first_response: GatewayResponse = read_frame(&mut first).await.unwrap();

        let mut second = TcpStream::connect(gw_addr).await.unwrap();
        write_frame(&mut second, &captured).await.unwrap(); // the exact same signed bytes again
        let second_response: GatewayResponse = read_frame(&mut second).await.unwrap();

        assert!(first_response.accepted, "the first, genuine use of this request must still work");
        assert!(
            !second_response.accepted,
            "a replayed copy of an already-used request must be rejected"
        );
        assert_eq!(second_response.reason.as_deref(), Some("replayed request (nonce already seen)"));
    }

    /// Proves the concurrency cap actually rejects connections once full,
    /// not just that the field exists. Uses `serve_with_limit(_, 1)` so the
    /// test doesn't need to open hundreds of real connections to prove it.
    #[tokio::test]
    async fn rejects_new_connections_once_at_capacity() {
        // A target that accepts a connection and holds it open forever --
        // keeps the first relay session (and its one permit) alive for as
        // long as this test needs it to.
        let target_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target_listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((_sock, _)) = target_listener.accept().await {
                std::future::pending::<()>().await;
            }
        });

        let gw_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let gw_addr = gw_listener.local_addr().unwrap();
        tokio::spawn(GatewayServer::new().serve_with_limit(gw_listener, 1));

        let identity = Identity::generate_ephemeral();

        // First request: accepted, and holds the only permit for the rest
        // of the test (its copy_bidirectional never returns).
        let _first_tunnel = GatewayClient::connect_via(&identity, gw_addr, "127.0.0.1", target_addr.port())
            .await
            .expect("first request should be accepted -- capacity is available");

        // Give the server a moment to actually acquire the permit (accept
        // + auth + dial all happen asynchronously after connect_via returns).
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Second connection: capacity is exhausted. The accept loop rejects
        // it before ever calling read_frame, so the connection should just
        // close with no data -- never a GatewayResponse.
        let mut second_stream = TcpStream::connect(gw_addr).await.unwrap();
        let mut buf = [0u8; 1];
        let read_result = tokio::time::timeout(Duration::from_secs(2), second_stream.read(&mut buf)).await;
        match read_result {
            Ok(Ok(n)) => assert_eq!(n, 0, "rejected connection should close with no data, not send a response"),
            Ok(Err(_)) => {} // a reset is also an acceptable "rejected" signal
            Err(_) => panic!("a rejected connection must close promptly, not hang"),
        }
    }
    // -----------------------------------------------------------------
    // Metering, end to end through a real relay
    // -----------------------------------------------------------------

    use crate::metering::{DeviceUsage, QuotaPolicy, UsageLedger};
    use crate::store::Store;

    /// A target that echoes back everything it is sent, so a test can
    /// drive a known number of bytes in each direction.
    async fn spawn_echo_target() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if sock.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    async fn spawn_metered_gateway(ledger: Arc<UsageLedger>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(GatewayServer::metered(ledger).serve(listener));
        addr
    }

    fn ledger(policy: QuotaPolicy) -> Arc<UsageLedger> {
        UsageLedger::new(Arc::new(Store::open_in_memory().unwrap()), policy)
    }

    /// The core claim: what the ledger records is what actually crossed
    /// the wire, in both directions, attributed to the device that sent it.
    #[tokio::test]
    async fn a_metered_session_records_the_bytes_that_actually_moved() {
        let target = spawn_echo_target().await;
        let ledger = ledger(QuotaPolicy::Open);
        let gateway = spawn_metered_gateway(ledger.clone()).await;

        let identity = Identity::generate_ephemeral();
        let device_id = identity.public_key();
        let mut tunnel = GatewayClient::connect_via(&identity, gateway, "127.0.0.1", target.port())
            .await
            .unwrap();

        let payload = vec![7u8; 4096];
        tunnel.write_all(&payload).await.unwrap();
        let mut echoed = vec![0u8; 4096];
        tunnel.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload, "the relay must still relay correctly");

        drop(tunnel);

        // Let the session close and the final write land.
        let usage = await_usage(&ledger, &device_id, 4096 * 2).await;
        assert_eq!(usage.consumed_bytes, 8192, "4096 up + 4096 back down");
        assert_eq!(usage.sessions, 1);
    }

    /// Polls until the ledger reflects at least `expected` bytes, so the
    /// test does not race the gateway's own close-and-write.
    async fn await_usage(ledger: &Arc<UsageLedger>, device_id: &[u8; 32], expected: u64) -> DeviceUsage {
        for _ in 0..100 {
            let usage = ledger.device_usage(device_id).unwrap();
            if usage.consumed_bytes >= expected {
                return usage;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        ledger.device_usage(device_id).unwrap()
    }

    /// A device with no grant is refused outright under RequireGrant --
    /// which is the policy a gateway selling bandwidth runs.
    #[tokio::test]
    async fn require_grant_refuses_a_device_with_no_allowance() {
        let target = spawn_echo_target().await;
        let ledger = ledger(QuotaPolicy::RequireGrant);
        let gateway = spawn_metered_gateway(ledger.clone()).await;

        let identity = Identity::generate_ephemeral();
        let result = GatewayClient::connect_via(&identity, gateway, "127.0.0.1", target.port()).await;

        let err = result.expect_err("a device with no grant must be refused");
        assert!(
            err.to_string().contains("requires a data grant"),
            "unhelpful refusal: {err}"
        );
    }

    /// The same device, once granted, gets through -- proving the refusal
    /// above was the policy working rather than the relay being broken.
    #[tokio::test]
    async fn a_granted_device_is_allowed_through() {
        let target = spawn_echo_target().await;
        let ledger = ledger(QuotaPolicy::RequireGrant);
        let gateway = spawn_metered_gateway(ledger.clone()).await;

        let identity = Identity::generate_ephemeral();
        ledger.grant(&identity.public_key(), 1_000_000, Some("test grant")).unwrap();

        let mut tunnel = GatewayClient::connect_via(&identity, gateway, "127.0.0.1", target.port())
            .await
            .expect("a granted device must be allowed");
        tunnel.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        tunnel.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
    }

    /// A quota checked only at connect time is not a quota: one connection
    /// could stream forever. This proves the relay is torn down while
    /// bytes are moving.
    #[tokio::test]
    async fn a_session_is_cut_off_when_it_exceeds_its_quota_mid_flight() {
        let target = spawn_echo_target().await;
        let ledger = ledger(QuotaPolicy::RequireGrant);
        let gateway = spawn_metered_gateway(ledger.clone()).await;

        let identity = Identity::generate_ephemeral();
        let device_id = identity.public_key();
        ledger.grant(&device_id, 16_384, None).unwrap();

        let mut tunnel = GatewayClient::connect_via(&identity, gateway, "127.0.0.1", target.port())
            .await
            .unwrap();

        // Push far more than the grant. The echo doubles every byte, so
        // 16KB of allowance is gone well before this finishes.
        let chunk = vec![9u8; 8192];
        let mut sent = 0usize;
        let outcome = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if tunnel.write_all(&chunk).await.is_err() {
                    return sent;
                }
                sent += chunk.len();
                let mut sink = vec![0u8; chunk.len()];
                if tunnel.read_exact(&mut sink).await.is_err() {
                    return sent;
                }
                if sent > 1_000_000 {
                    return sent; // the relay should have stopped us long before here
                }
            }
        })
        .await;

        assert!(outcome.is_ok(), "the relay must end the session, not hang");
        let moved = outcome.unwrap();
        assert!(
            moved < 1_000_000,
            "the session relayed {moved} bytes against a 16KB grant -- the quota did not bite"
        );

        let usage = ledger.device_usage(&device_id).unwrap();
        assert!(usage.consumed_bytes >= 16_384, "usage should reach the grant");
        assert_eq!(usage.remaining(), Some(0), "the grant should be spent");
    }

    /// Usage held only in memory would hand every device a fresh
    /// allowance on restart, which makes a quota decorative. This proves
    /// consumption accumulates across separate sessions.
    #[tokio::test]
    async fn usage_accumulates_across_sessions_rather_than_resetting() {
        let target = spawn_echo_target().await;
        let ledger = ledger(QuotaPolicy::Open);
        let gateway = spawn_metered_gateway(ledger.clone()).await;

        let identity = Identity::generate_ephemeral();
        let device_id = identity.public_key();

        for _ in 0..3 {
            let mut tunnel = GatewayClient::connect_via(&identity, gateway, "127.0.0.1", target.port())
                .await
                .unwrap();
            tunnel.write_all(&[1u8; 1024]).await.unwrap();
            let mut buf = vec![0u8; 1024];
            tunnel.read_exact(&mut buf).await.unwrap();
            drop(tunnel);
        }

        let usage = await_usage(&ledger, &device_id, 3 * 2048).await;
        assert_eq!(usage.sessions, 3, "each session gets its own record");
        assert_eq!(usage.consumed_bytes, 3 * 2048, "1KB up + 1KB down, three times");
    }

    /// Two devices must not be charged for each other's traffic.
    #[tokio::test]
    async fn usage_is_attributed_per_device() {
        let target = spawn_echo_target().await;
        let ledger = ledger(QuotaPolicy::Open);
        let gateway = spawn_metered_gateway(ledger.clone()).await;

        let heavy = Identity::generate_ephemeral();
        let light = Identity::generate_ephemeral();

        for (identity, size) in [(&heavy, 4096usize), (&light, 512usize)] {
            let mut tunnel = GatewayClient::connect_via(identity, gateway, "127.0.0.1", target.port())
                .await
                .unwrap();
            tunnel.write_all(&vec![3u8; size]).await.unwrap();
            let mut buf = vec![0u8; size];
            tunnel.read_exact(&mut buf).await.unwrap();
            drop(tunnel);
        }

        let heavy_usage = await_usage(&ledger, &heavy.public_key(), 8192).await;
        let light_usage = await_usage(&ledger, &light.public_key(), 1024).await;
        assert_eq!(heavy_usage.consumed_bytes, 8192);
        assert_eq!(light_usage.consumed_bytes, 1024);
    }

    /// An unmetered gateway must behave exactly as it did before metering
    /// existed -- relay for anyone, record nothing.
    #[tokio::test]
    async fn an_unmetered_gateway_is_unchanged() {
        let target = spawn_echo_target().await;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(GatewayServer::new().serve(listener));

        let identity = Identity::generate_ephemeral();
        let mut tunnel = GatewayClient::connect_via(&identity, addr, "127.0.0.1", target.port())
            .await
            .expect("an unmetered gateway relays for anyone");
        tunnel.write_all(b"unmetered").await.unwrap();
        let mut buf = [0u8; 9];
        tunnel.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"unmetered");
        assert!(GatewayServer::new().ledger().is_none());
    }

    /// Accounting must survive the process dying mid-session. The
    /// checkpoint bounds the loss; orphaned rows are closed at startup so
    /// their bytes stop looking like live traffic.
    #[test]
    fn a_crashed_session_is_reconciled_on_the_next_start() {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let ledger = UsageLedger::new(store.clone(), QuotaPolicy::Open);
        let device_id = [42u8; 32];

        let meter = SessionMeter::new([1u8; 16], device_id, "example.com:443", crate::metering::UNLIMITED);
        meter.charge(crate::metering::Direction::Up, 5000);
        ledger.checkpoint(&meter).unwrap(); // the process dies right here

        let open = ledger.recent_sessions(10).unwrap();
        assert_eq!(open.len(), 1);
        assert!(!open[0].closed, "still open, as a crash would leave it");
        assert_eq!(open[0].bytes_up, 5000, "checkpointed bytes are not lost");

        let closed = ledger.close_orphaned_sessions().unwrap();
        assert_eq!(closed, 1);
        assert!(ledger.recent_sessions(10).unwrap()[0].closed);

        // And the bytes still count against the device.
        assert_eq!(ledger.device_usage(&device_id).unwrap().consumed_bytes, 5000);
    }

    #[test]
    fn a_grant_can_be_raised_lowered_and_revoked() {
        let ledger = ledger(QuotaPolicy::RequireGrant);
        let device_id = [8u8; 32];

        assert!(matches!(ledger.authorize(&device_id).unwrap(), QuotaDecision::Deny { .. }));

        ledger.grant(&device_id, 1000, None).unwrap();
        assert_eq!(
            ledger.authorize(&device_id).unwrap(),
            QuotaDecision::Allow { remaining: 1000 }
        );

        ledger.grant(&device_id, 50, Some("reduced")).unwrap();
        assert_eq!(ledger.authorize(&device_id).unwrap(), QuotaDecision::Allow { remaining: 50 });

        ledger.revoke(&device_id).unwrap();
        assert!(matches!(ledger.authorize(&device_id).unwrap(), QuotaDecision::Deny { .. }));
    }

    #[test]
    fn a_spent_grant_denies_the_next_connection_before_any_bytes_move() {
        let ledger = ledger(QuotaPolicy::RequireGrant);
        let device_id = [11u8; 32];
        ledger.grant(&device_id, 1000, None).unwrap();

        let meter = SessionMeter::new([2u8; 16], device_id, "example.com:80", 1000);
        meter.charge(crate::metering::Direction::Up, 1000);
        ledger.close(&meter).unwrap();

        match ledger.authorize(&device_id).unwrap() {
            QuotaDecision::Deny { reason } => assert!(reason.contains("quota exhausted"), "{reason}"),
            other => panic!("expected a denial, got {other:?}"),
        }
    }

    #[test]
    fn the_device_list_includes_a_granted_device_that_has_never_connected() {
        let ledger = ledger(QuotaPolicy::RequireGrant);
        ledger.grant(&[77u8; 32], 5_000_000, Some("neighbour")).unwrap();

        let all = ledger.all_device_usage().unwrap();
        assert_eq!(all.len(), 1, "a grant alone should put a device on the list");
        assert_eq!(all[0].granted_bytes, Some(5_000_000));
        assert_eq!(all[0].consumed_bytes, 0);
        assert_eq!(all[0].remaining(), Some(5_000_000));
    }

    // -----------------------------------------------------------------
    // Admission, end to end through a real relay
    // -----------------------------------------------------------------

    use crate::admission::{AdmissionControl, AdmissionPolicy, SignedInvitation};

    fn guarded_gateway(
        policy: AdmissionPolicy,
    ) -> (Arc<UsageLedger>, Arc<AdmissionControl>, Identity) {
        let store = Arc::new(Store::open_in_memory().unwrap());
        let gateway_identity = Identity::generate_ephemeral();
        let ledger = UsageLedger::new(store.clone(), QuotaPolicy::Open);
        let admission = AdmissionControl::new(store, gateway_identity.public_key(), policy);
        (ledger, admission, gateway_identity)
    }

    async fn spawn_guarded(
        ledger: Arc<UsageLedger>,
        admission: Arc<AdmissionControl>,
    ) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(GatewayServer::guarded(ledger, admission).serve(listener));
        addr
    }

    /// The gap this closes: before admission, any device that could
    /// generate a keypair could ask a gateway to relay for it, and
    /// generating a keypair is free.
    #[tokio::test]
    async fn an_invite_only_gateway_turns_away_a_stranger() {
        let target = spawn_echo_target().await;
        let (ledger, admission, _) = guarded_gateway(AdmissionPolicy::InviteOnly);
        let gateway = spawn_guarded(ledger, admission).await;

        let stranger = Identity::generate_ephemeral();
        let err = GatewayClient::connect_via(&stranger, gateway, "127.0.0.1", target.port())
            .await
            .expect_err("a stranger must not get through an invite-only gateway");
        assert!(err.to_string().contains("invitation-only"), "unhelpful refusal: {err}");
    }

    #[tokio::test]
    async fn a_valid_invitation_gets_a_device_through() {
        let target = spawn_echo_target().await;
        let (ledger, admission, gateway_identity) = guarded_gateway(AdmissionPolicy::InviteOnly);
        let gateway = spawn_guarded(ledger, admission).await;

        let guest = Identity::generate_ephemeral();
        let invite =
            SignedInvitation::issue(&gateway_identity, guest.public_key(), 3600, None).unwrap();

        let mut tunnel = GatewayClient::connect_via_with_invitation(
            &guest,
            gateway,
            "127.0.0.1",
            target.port(),
            Some(invite),
        )
        .await
        .expect("an invited device must get through");

        tunnel.write_all(b"invited").await.unwrap();
        let mut buf = [0u8; 7];
        tunnel.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"invited");
    }

    /// After redeeming once, a reconnect works without the token -- or
    /// anyone who closed the app would be locked out until they found
    /// their invitation again.
    #[tokio::test]
    async fn a_redeemed_invitation_does_not_have_to_be_presented_again() {
        let target = spawn_echo_target().await;
        let (ledger, admission, gateway_identity) = guarded_gateway(AdmissionPolicy::InviteOnly);
        let gateway = spawn_guarded(ledger, admission).await;

        let guest = Identity::generate_ephemeral();
        let invite =
            SignedInvitation::issue(&gateway_identity, guest.public_key(), 3600, None).unwrap();

        GatewayClient::connect_via_with_invitation(
            &guest, gateway, "127.0.0.1", target.port(), Some(invite),
        )
        .await
        .unwrap();

        GatewayClient::connect_via(&guest, gateway, "127.0.0.1", target.port())
            .await
            .expect("a redeemed device should stay admitted");
    }

    /// An invitation is safe to pass around in the open precisely because
    /// stealing one gains nothing: the request presenting it is signed by
    /// the requesting device, which must match.
    #[tokio::test]
    async fn a_stolen_invitation_is_useless_to_the_thief() {
        let target = spawn_echo_target().await;
        let (ledger, admission, gateway_identity) = guarded_gateway(AdmissionPolicy::InviteOnly);
        let gateway = spawn_guarded(ledger, admission).await;

        let invited = Identity::generate_ephemeral();
        let thief = Identity::generate_ephemeral();
        let invite =
            SignedInvitation::issue(&gateway_identity, invited.public_key(), 3600, None).unwrap();

        let err = GatewayClient::connect_via_with_invitation(
            &thief, gateway, "127.0.0.1", target.port(), Some(invite),
        )
        .await
        .expect_err("a stolen invitation must not work");
        assert!(err.to_string().contains("different device"), "{err}");
    }

    /// Revocation, end to end: blocking must stop a device that was
    /// already admitted, including one holding a live invitation.
    #[tokio::test]
    async fn blocking_a_device_stops_it_reconnecting() {
        let target = spawn_echo_target().await;
        let (ledger, admission, _) = guarded_gateway(AdmissionPolicy::Open);
        let gateway = spawn_guarded(ledger, admission.clone()).await;

        let device = Identity::generate_ephemeral();
        GatewayClient::connect_via(&device, gateway, "127.0.0.1", target.port())
            .await
            .expect("an open gateway admits anyone at first");

        admission.block(&device.public_key(), Some("used too much")).unwrap();

        let err = GatewayClient::connect_via(&device, gateway, "127.0.0.1", target.port())
            .await
            .expect_err("a blocked device must be refused");
        assert!(err.to_string().contains("blocked"), "{err}");
    }

    /// An invitation can hand over the data allowance at the same time,
    /// so admitting someone and giving them 500MB is one action rather
    /// than two.
    #[tokio::test]
    async fn an_invitation_can_carry_the_data_grant_with_it() {
        let target = spawn_echo_target().await;
        let store = Arc::new(Store::open_in_memory().unwrap());
        let gateway_identity = Identity::generate_ephemeral();
        // RequireGrant, so getting through proves the grant really landed.
        let ledger = UsageLedger::new(store.clone(), QuotaPolicy::RequireGrant);
        let admission =
            AdmissionControl::new(store, gateway_identity.public_key(), AdmissionPolicy::InviteOnly);
        let gateway = spawn_guarded(ledger.clone(), admission).await;

        let guest = Identity::generate_ephemeral();
        let invite = SignedInvitation::issue(
            &gateway_identity,
            guest.public_key(),
            3600,
            Some(500_000_000),
        )
        .unwrap();

        GatewayClient::connect_via_with_invitation(
            &guest, gateway, "127.0.0.1", target.port(), Some(invite),
        )
        .await
        .expect("the invitation should admit and fund in one step");

        let usage = ledger.device_usage(&guest.public_key()).unwrap();
        assert_eq!(usage.granted_bytes, Some(500_000_000));
    }

    /// A gateway with no admission control must behave exactly as it did
    /// before this existed.
    #[tokio::test]
    async fn a_gateway_without_admission_control_is_unchanged() {
        let target = spawn_echo_target().await;
        let ledger = ledger(QuotaPolicy::Open);
        let gateway = spawn_metered_gateway(ledger).await;

        let stranger = Identity::generate_ephemeral();
        GatewayClient::connect_via(&stranger, gateway, "127.0.0.1", target.port())
            .await
            .expect("an ungated gateway relays for anyone");
        assert!(GatewayServer::new().admission().is_none());
    }

    /// A refused device must not appear in the usage tables at all --
    /// admission is checked first precisely so a stranger cannot make a
    /// gateway write rows on its behalf.
    #[tokio::test]
    async fn a_refused_device_leaves_no_trace_in_the_usage_tables() {
        let target = spawn_echo_target().await;
        let (ledger, admission, _) = guarded_gateway(AdmissionPolicy::InviteOnly);
        let gateway = spawn_guarded(ledger.clone(), admission).await;

        let stranger = Identity::generate_ephemeral();
        let _ = GatewayClient::connect_via(&stranger, gateway, "127.0.0.1", target.port()).await;

        let usage = ledger.device_usage(&stranger.public_key()).unwrap();
        assert_eq!(usage.sessions, 0);
        assert_eq!(usage.consumed_bytes, 0);
        assert!(ledger.recent_sessions(10).unwrap().is_empty());
    }

}
