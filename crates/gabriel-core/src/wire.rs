//! Small wire-format helpers shared by anything in this crate that speaks
//! a length-prefixed bincode protocol over an async stream -- currently
//! the gateway relay's request/response handshake and mesh routing's
//! message envelopes. Not part of the public API: each module defines its
//! own message types and re-exposes whatever shape makes sense for it.

use std::collections::{HashSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::Result;

const MAX_FRAME_LEN: u32 = 64 * 1024;

/// Reject anything whose timestamp is further than this from "now" in
/// either direction -- a cheap replay-window bound used by both the
/// gateway relay's request handshake and mesh routing's message envelope.
pub(crate) const MAX_CLOCK_SKEW_SECS: u64 = 30;

pub(crate) async fn write_frame<W: AsyncWriteExt + Unpin>(writer: &mut W, msg: &impl Serialize) -> Result<()> {
    let bytes = bincode::serialize(msg)?;
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(&bytes).await?;
    Ok(())
}

pub(crate) async fn read_frame<R, T>(reader: &mut R) -> Result<T>
where
    R: AsyncReadExt + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let len = reader.read_u32().await?;
    if len > MAX_FRAME_LEN {
        anyhow::bail!("frame too large ({len} bytes)");
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    Ok(bincode::deserialize(&buf)?)
}

/// A fresh random 16-byte id -- used as a message id (mesh routing, for
/// flood dedup) or a nonce (gateway relay requests, for replay rejection).
/// Both want the same thing: enough entropy that two unrelated ids never
/// collide by chance, at a size cheap enough to carry on every message.
pub(crate) fn random_id16() -> [u8; 16] {
    let mut id = [0u8; 16];
    OsRng.fill_bytes(&mut id);
    id
}

/// Bounded FIFO of recently seen 16-byte ids. Two independent uses share
/// this: mesh routing dedups flooded messages by `message_id` (so a peer
/// never re-forwards or re-delivers the same message twice), and the
/// gateway relay rejects replayed requests by `nonce` (so a captured,
/// validly-signed request can't just be resent to trigger the action
/// again within the timestamp freshness window). Bounded so a long-running
/// node's memory doesn't grow forever -- old entries fall off a FIFO once
/// capacity is reached.
pub(crate) struct SeenCache {
    seen: HashSet<[u8; 16]>,
    order: VecDeque<[u8; 16]>,
    capacity: usize,
}

impl SeenCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            seen: HashSet::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    /// Returns `true` if this id hadn't been seen before (and records it
    /// now); `false` if it's a duplicate.
    pub(crate) fn insert_if_new(&mut self, id: [u8; 16]) -> bool {
        if !self.seen.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        true
    }
}

/// Checks a `timestamp_unix` field against the current time, returning a
/// human-readable rejection reason if it's outside the allowed skew window.
pub(crate) fn check_freshness(timestamp_unix: u64) -> std::result::Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let skew = now.abs_diff(timestamp_unix);
    if skew > MAX_CLOCK_SKEW_SECS {
        return Err(format!("timestamp is {skew}s out of range"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::duplex;

    /// The outer frame-length cap is the first line of defense, ahead of
    /// bincode ever running -- a peer claiming a multi-gigabyte frame
    /// should be rejected immediately, without this side ever reading (or
    /// allocating a buffer for) a body that was never going to be sent.
    #[tokio::test]
    async fn rejects_an_oversized_frame_length_without_reading_a_body() {
        let (mut client, mut server) = duplex(64);
        client.write_u32(MAX_FRAME_LEN + 1).await.unwrap();
        drop(client); // deliberately never sends a body

        let result: Result<u8> = read_frame(&mut server).await;
        assert!(result.is_err(), "a frame length over the cap must be rejected immediately");
    }

    /// A peer that promises N bytes and then hangs up early (or a slow-
    /// loris-style connection) must produce an error once the stream
    /// closes, not hang forever waiting for bytes that are never coming.
    #[tokio::test]
    async fn errors_cleanly_on_a_truncated_frame_instead_of_hanging() {
        let (mut client, mut server) = duplex(64);
        client.write_u32(100).await.unwrap(); // promises 100 bytes
        client.write_all(&[1, 2, 3]).await.unwrap(); // sends only 3
        drop(client); // then hangs up

        let outcome = tokio::time::timeout(Duration::from_secs(2), read_frame::<_, u8>(&mut server)).await;
        let result = outcome.expect("read_frame must not hang once the sender closes early");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn write_then_read_frame_round_trips() {
        let (mut client, mut server) = duplex(1024);
        write_frame(&mut client, &42u32).await.unwrap();
        let value: u32 = read_frame(&mut server).await.unwrap();
        assert_eq!(value, 42);
    }
}
