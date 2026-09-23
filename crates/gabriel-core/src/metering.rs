//! Byte metering for the gateway relay.
//!
//! The relay already moves bytes for other devices. This is what makes
//! that countable, attributable and limitable -- the difference between
//! "you may use my connection" and "you may use 500MB of my connection,
//! and I can prove you used 437MB of it."
//!
//! Three pieces:
//!
//!   - [`SessionMeter`] holds live counters for one relay session, as
//!     atomics, so the counting costs an increment per chunk rather than
//!     a lock.
//!   - [`MeteredStream`] wraps the client side of a relay and updates
//!     those counters as bytes pass. Wrapping only the *client* side is
//!     enough for both directions: reading from the client is upload,
//!     writing to it is download.
//!   - [`UsageLedger`] is the durable half -- per-session records and
//!     per-device grants in SQLite, so usage survives a restart and a
//!     device cannot get a fresh allowance by reconnecting.
//!
//! **Enforcement happens during a session, not after it.** A quota
//! checked only at connect time is not a quota: a single connection can
//! stream forever. `MeteredStream` fails the read or write that would
//! cross the limit, which tears the relay down mid-flight. The cost of
//! that choice is that the limit is enforced to within one buffer's worth
//! of bytes, not exactly -- documented on [`SessionMeter::charge`], and
//! tested.
//!
//! What this is *not*: an admission policy. Deciding who is allowed to
//! ask at all is a separate concern (see the gateway module's own note).
//! Metering answers "how much", not "who".

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::store::Store;
use crate::Result;

/// A device identity, as used everywhere else in this crate.
pub type DeviceId = [u8; 32];
/// A relay session's random id.
pub type SessionId = [u8; 16];

/// Written to the ledger this often while a session is open, so a crash
/// loses at most this much accounting rather than the whole session.
pub const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(5);

/// The sentinel for "no limit". Devices with no grant run unmetered under
/// [`QuotaPolicy::Open`] -- still counted, just not capped.
pub const UNLIMITED: u64 = u64::MAX;

/// What to do about a device that has no grant on record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaPolicy {
    /// Relay for it anyway, and count what it uses. This is what the
    /// gateway did before metering existed, kept as the default so
    /// turning metering on does not silently cut off existing peers.
    Open,
    /// Refuse it. What a gateway selling bandwidth wants: no grant, no
    /// relay.
    RequireGrant,
}

/// Why a session was refused or cut off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaDecision {
    /// Allowed, with this many bytes of headroom (`UNLIMITED` if uncapped).
    Allow { remaining: u64 },
    /// Refused before any bytes moved.
    Deny { reason: String },
}

// ---------------------------------------------------------------------
// Live counters
// ---------------------------------------------------------------------

/// Live byte counters for one relay session.
///
/// Cloneable via `Arc`: the stream wrapper holds one handle and the
/// checkpoint task holds another, and both touch the same atomics.
#[derive(Debug)]
pub struct SessionMeter {
    session_id: SessionId,
    device_id: DeviceId,
    target: String,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    /// Remaining allowance across *all* of this device's usage, not just
    /// this session -- seeded from the ledger at connect time.
    remaining: AtomicU64,
    exhausted: AtomicBool,
    started_at: Instant,
    started_unix: u64,
}

impl SessionMeter {
    pub fn new(session_id: SessionId, device_id: DeviceId, target: impl Into<String>, remaining: u64) -> Arc<Self> {
        Arc::new(Self {
            session_id,
            device_id,
            target: target.into(),
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            remaining: AtomicU64::new(remaining),
            exhausted: AtomicBool::new(remaining == 0),
            started_at: Instant::now(),
            started_unix: now_unix(),
        })
    }

    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub fn target(&self) -> &str {
        &self.target
    }

    pub fn bytes_up(&self) -> u64 {
        self.bytes_up.load(Ordering::Relaxed)
    }

    pub fn bytes_down(&self) -> u64 {
        self.bytes_down.load(Ordering::Relaxed)
    }

    pub fn total(&self) -> u64 {
        self.bytes_up().saturating_add(self.bytes_down())
    }

    pub fn remaining(&self) -> u64 {
        self.remaining.load(Ordering::Relaxed)
    }

    pub fn is_exhausted(&self) -> bool {
        self.exhausted.load(Ordering::Relaxed)
    }

    pub fn elapsed(&self) -> Duration {
        self.started_at.elapsed()
    }

    pub fn started_unix(&self) -> u64 {
        self.started_unix
    }

    /// Records `n` bytes in one direction and draws them down against the
    /// remaining allowance.
    ///
    /// Returns `false` once the allowance is gone, which is the stream
    /// wrapper's cue to fail the operation and end the session.
    ///
    /// The bytes that crossed the line are still counted. A quota is
    /// enforced to within one buffer -- the alternative is to inspect and
    /// split every chunk, which costs more than the few kilobytes it would
    /// save. `charge` is therefore "stop at or just past the limit", never
    /// "stop before it", and the ledger records what actually moved.
    pub fn charge(&self, direction: Direction, n: u64) -> bool {
        if n == 0 {
            return !self.is_exhausted();
        }
        match direction {
            Direction::Up => self.bytes_up.fetch_add(n, Ordering::Relaxed),
            Direction::Down => self.bytes_down.fetch_add(n, Ordering::Relaxed),
        };

        // Unlimited sessions never draw down, so the sentinel stays put
        // rather than slowly counting u64::MAX towards zero.
        if self.remaining.load(Ordering::Relaxed) == UNLIMITED {
            return true;
        }

        let previous = self
            .remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |r| Some(r.saturating_sub(n)))
            .unwrap_or(0);

        if previous <= n {
            self.exhausted.store(true, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// A snapshot suitable for writing to the ledger or showing in a UI.
    pub fn snapshot(&self) -> UsageRecord {
        UsageRecord {
            session_id: self.session_id,
            device_id: self.device_id,
            target: self.target.clone(),
            bytes_up: self.bytes_up(),
            bytes_down: self.bytes_down(),
            started_at: self.started_unix as i64,
            ended_at: None,
            closed: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client to target.
    Up,
    /// Target back to client.
    Down,
}

// ---------------------------------------------------------------------
// The counting stream
// ---------------------------------------------------------------------

/// Wraps the client side of a relay and counts bytes in both directions.
///
/// Reading from the client is upload; writing to the client is download.
/// So wrapping one side of `copy_bidirectional` meters both, with no
/// second wrapper and no double counting.
pub struct MeteredStream<S> {
    inner: S,
    meter: Arc<SessionMeter>,
}

impl<S> MeteredStream<S> {
    pub fn new(inner: S, meter: Arc<SessionMeter>) -> Self {
        Self { inner, meter }
    }

    pub fn meter(&self) -> &Arc<SessionMeter> {
        &self.meter
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

fn quota_exhausted() -> io::Error {
    // ConnectionAborted rather than Other: callers that log an io::Error
    // then get a sensible message, and it reads correctly as "this
    // connection was deliberately ended".
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "gateway quota exhausted -- session ended",
    )
}

impl<S: AsyncRead + Unpin> AsyncRead for MeteredStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if self.meter.is_exhausted() {
            return Poll::Ready(Err(quota_exhausted()));
        }
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let read = buf.filled().len().saturating_sub(before) as u64;
            if !self.meter.charge(Direction::Up, read) {
                // The bytes already in `buf` are delivered; the *next*
                // poll fails. Discarding them here would lose data the
                // peer has already sent.
                return Poll::Ready(Ok(()));
            }
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MeteredStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if self.meter.is_exhausted() {
            return Poll::Ready(Err(quota_exhausted()));
        }
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = &result {
            self.meter.charge(Direction::Down, *written as u64);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------
// The durable half
// ---------------------------------------------------------------------

/// One relay session's accounting, as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageRecord {
    pub session_id: SessionId,
    pub device_id: DeviceId,
    pub target: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    /// False while the session is still open. A record that is still open
    /// after a restart is one whose process died mid-session; its byte
    /// counts are whatever the last checkpoint wrote.
    pub closed: bool,
}

impl UsageRecord {
    pub fn total(&self) -> u64 {
        self.bytes_up.saturating_add(self.bytes_down)
    }
}

/// What a device has been granted and what it has used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceUsage {
    pub device_id: DeviceId,
    pub granted_bytes: Option<u64>,
    pub consumed_bytes: u64,
    pub sessions: u64,
    pub last_seen_at: Option<i64>,
}

impl DeviceUsage {
    /// Bytes left, or `None` when this device has no grant (so the answer
    /// depends on policy rather than arithmetic).
    pub fn remaining(&self) -> Option<u64> {
        self.granted_bytes.map(|g| g.saturating_sub(self.consumed_bytes))
    }
}

/// Persistent usage accounting, backed by the shared `Store`.
///
/// Holding usage in memory would mean a device gets a fresh allowance
/// every time the gateway restarts, which makes a quota decorative.
pub struct UsageLedger {
    store: Arc<Store>,
    policy: QuotaPolicy,
}

impl UsageLedger {
    pub fn new(store: Arc<Store>, policy: QuotaPolicy) -> Arc<Self> {
        Arc::new(Self { store, policy })
    }

    pub fn policy(&self) -> QuotaPolicy {
        self.policy
    }

    /// Decides whether a device may open a session, and with how much
    /// headroom. Called once per connection, before any bytes move.
    pub fn authorize(&self, device_id: &DeviceId) -> Result<QuotaDecision> {
        let usage = self.store.device_usage(device_id)?;
        match (usage.granted_bytes, self.policy) {
            (Some(granted), _) => {
                let remaining = granted.saturating_sub(usage.consumed_bytes);
                if remaining == 0 {
                    Ok(QuotaDecision::Deny {
                        reason: format!(
                            "quota exhausted: {} of {} bytes used",
                            usage.consumed_bytes, granted
                        ),
                    })
                } else {
                    Ok(QuotaDecision::Allow { remaining })
                }
            }
            (None, QuotaPolicy::Open) => Ok(QuotaDecision::Allow { remaining: UNLIMITED }),
            (None, QuotaPolicy::RequireGrant) => Ok(QuotaDecision::Deny {
                reason: "this gateway requires a data grant, and this device has none".to_string(),
            }),
        }
    }

    /// Writes the session's current counters. Safe to call repeatedly --
    /// it upserts on `session_id`.
    pub fn checkpoint(&self, meter: &SessionMeter) -> Result<()> {
        self.store.upsert_usage(&meter.snapshot())
    }

    /// Final write when a session ends.
    pub fn close(&self, meter: &SessionMeter) -> Result<()> {
        let mut record = meter.snapshot();
        record.ended_at = Some(now_unix() as i64);
        record.closed = true;
        self.store.upsert_usage(&record)
    }

    pub fn grant(&self, device_id: &DeviceId, bytes: u64, note: Option<&str>) -> Result<()> {
        self.store.set_grant(device_id, bytes, now_unix() as i64, note)
    }

    pub fn revoke(&self, device_id: &DeviceId) -> Result<()> {
        self.store.clear_grant(device_id)
    }

    pub fn device_usage(&self, device_id: &DeviceId) -> Result<DeviceUsage> {
        self.store.device_usage(device_id)
    }

    pub fn all_device_usage(&self) -> Result<Vec<DeviceUsage>> {
        self.store.all_device_usage()
    }

    pub fn recent_sessions(&self, limit: usize) -> Result<Vec<UsageRecord>> {
        self.store.recent_usage(limit)
    }

    /// Marks sessions left open by a crash as closed, so their bytes stop
    /// looking like live traffic. Call once at startup.
    pub fn close_orphaned_sessions(&self) -> Result<usize> {
        self.store.close_open_usage(now_unix() as i64)
    }

    /// Spawns a task that checkpoints this session until it is dropped.
    /// Returns a handle the caller aborts when the session ends.
    pub fn spawn_checkpoint_task(
        self: &Arc<Self>,
        meter: Arc<SessionMeter>,
    ) -> tokio::task::JoinHandle<()> {
        let ledger = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(CHECKPOINT_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                if let Err(err) = ledger.checkpoint(&meter) {
                    eprintln!("gateway: usage checkpoint failed: {err:#}");
                }
            }
        })
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn meter(remaining: u64) -> Arc<SessionMeter> {
        SessionMeter::new([1u8; 16], [2u8; 32], "example.com:80", remaining)
    }

    #[test]
    fn counts_each_direction_separately() {
        let m = meter(UNLIMITED);
        m.charge(Direction::Up, 100);
        m.charge(Direction::Down, 250);
        assert_eq!(m.bytes_up(), 100);
        assert_eq!(m.bytes_down(), 250);
        assert_eq!(m.total(), 350);
    }

    #[test]
    fn an_unlimited_session_never_draws_down() {
        let m = meter(UNLIMITED);
        for _ in 0..1000 {
            assert!(m.charge(Direction::Up, 1_000_000));
        }
        assert_eq!(m.remaining(), UNLIMITED, "the sentinel must not decay");
        assert!(!m.is_exhausted());
    }

    #[test]
    fn a_capped_session_draws_down_across_both_directions() {
        let m = meter(1000);
        assert!(m.charge(Direction::Up, 400));
        assert_eq!(m.remaining(), 600);
        assert!(m.charge(Direction::Down, 500));
        assert_eq!(m.remaining(), 100);
        // Upload and download share one allowance -- a device cannot get
        // twice its grant by splitting traffic between directions.
        assert_eq!(m.total(), 900);
    }

    #[test]
    fn charge_reports_exhaustion_at_or_just_past_the_limit() {
        let m = meter(100);
        assert!(m.charge(Direction::Up, 60), "still inside the allowance");
        assert!(!m.charge(Direction::Up, 60), "the chunk that crosses the line fails");
        assert!(m.is_exhausted());
        assert_eq!(m.remaining(), 0);
        // The bytes that crossed are still counted: the ledger records
        // what actually moved, not what was permitted.
        assert_eq!(m.total(), 120);
    }

    #[test]
    fn a_zero_allowance_is_exhausted_before_any_bytes_move() {
        let m = meter(0);
        assert!(m.is_exhausted());
        assert!(!m.charge(Direction::Up, 1));
    }

    #[test]
    fn charging_zero_bytes_is_a_no_op_that_reports_current_state() {
        let m = meter(10);
        assert!(m.charge(Direction::Up, 0));
        assert_eq!(m.total(), 0);
        assert_eq!(m.remaining(), 10);
    }

    #[test]
    fn concurrent_charges_do_not_lose_counts() {
        let m = meter(UNLIMITED);
        let mut handles = Vec::new();
        for _ in 0..8 {
            let m = m.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..1000 {
                    m.charge(Direction::Up, 1);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(m.bytes_up(), 8000, "atomics must not lose increments under contention");
    }

    /// The counting has to be right against a real async stream, not just
    /// against direct `charge` calls -- the wrapper is where a direction
    /// could be swapped or a chunk double-counted.
    #[tokio::test]
    async fn metered_stream_counts_reads_as_up_and_writes_as_down() {
        let (client, mut peer) = tokio::io::duplex(4096);
        let m = meter(UNLIMITED);
        let mut metered = MeteredStream::new(client, m.clone());

        peer.write_all(b"hello gateway").await.unwrap();
        let mut buf = [0u8; 13];
        metered.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello gateway");
        assert_eq!(m.bytes_up(), 13, "reading from the client is upload");
        assert_eq!(m.bytes_down(), 0);

        metered.write_all(b"response bytes").await.unwrap();
        metered.flush().await.unwrap();
        assert_eq!(m.bytes_down(), 14, "writing to the client is download");
        assert_eq!(m.total(), 27);
    }

    /// The actual point of enforcing during a session: a stream that
    /// exceeds its quota must fail, not run forever.
    #[tokio::test]
    async fn metered_stream_fails_once_the_quota_is_gone() {
        let (client, mut peer) = tokio::io::duplex(65536);
        let m = meter(100);
        let mut metered = MeteredStream::new(client, m.clone());

        peer.write_all(&[0u8; 80]).await.unwrap();
        let mut buf = [0u8; 80];
        metered.read_exact(&mut buf).await.unwrap();
        assert!(!m.is_exhausted(), "80 of 100 bytes is still inside");

        peer.write_all(&[0u8; 80]).await.unwrap();
        let mut buf = [0u8; 80];
        let _ = metered.read(&mut buf).await; // this one crosses the line
        assert!(m.is_exhausted());

        // Every subsequent operation fails rather than relaying more.
        let err = metered.read(&mut [0u8; 16]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        let err = metered.write(b"more").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
    }

    #[tokio::test]
    async fn an_exhausted_stream_refuses_before_reading_anything() {
        let (client, mut peer) = tokio::io::duplex(4096);
        peer.write_all(b"data the client never gets").await.unwrap();
        let mut metered = MeteredStream::new(client, meter(0));
        let err = metered.read(&mut [0u8; 32]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
    }
}
