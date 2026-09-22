//! Shared helpers for adversarial/malformed-input tests across this
//! crate's wire-format parsers (`protocol`, `discovery`, `gateway`,
//! `routing`). Test-only -- `lib.rs` only compiles this module under
//! `#[cfg(test)]`, so none of it exists in a release build.
//!
//! The property under test throughout is narrow and deliberately so: this
//! crate is 100% safe Rust, so memory corruption from malformed input
//! isn't the risk model here the way it would be for a C/C++ parser.
//! What IS a real risk for any `bincode::deserialize` call fed attacker
//! bytes is (a) a panic (a peer sending one bad packet shouldn't be able
//! to crash the process handling it) and (b) a hang or pathological
//! allocation from a corrupted internal length prefix (bincode's own docs
//! warn it isn't hardened against untrusted input by default). Every test
//! that uses these helpers is checking for one of those two things.

use std::sync::mpsc;
use std::time::Duration;

use rand::RngCore;

/// Feeds `parse` random bytes of random (small) length, `iterations`
/// times, asserting none of them panics. Returning `Err` (or even `Ok` on
/// bytes that happen to decode into a structurally valid-looking value) is
/// fine and expected -- a parser is allowed to accept or reject garbage,
/// it is not allowed to crash on it.
pub(crate) fn assert_never_panics_on_random_bytes<F>(iterations: usize, mut parse: F)
where
    F: FnMut(&[u8]),
{
    let mut rng = rand::rngs::OsRng;
    for i in 0..iterations {
        let len = (rng.next_u32() % 512) as usize;
        let mut buf = vec![0u8; len];
        rng.fill_bytes(&mut buf);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| parse(&buf)));
        assert!(
            result.is_ok(),
            "parser panicked on random input #{i} ({len} bytes): {buf:?}"
        );
    }
}

/// Finds the little-endian encoding of `needle` in `haystack` and
/// overwrites it with the little-endian encoding of `replacement`. Used to
/// corrupt a bincode-encoded length prefix (e.g. a `String`/`Vec<u8>`
/// field's byte count) in an otherwise-valid serialized message, so a test
/// can check the parser's behavior on a claimed-length that wildly exceeds
/// the actual data present -- without hand-encoding the whole message.
///
/// Panics if the needle isn't found exactly once; callers should pick a
/// distinctive value (e.g. an odd, specific field length like `54321`)
/// that can't collide with another fixed-width field's bytes in the same
/// payload.
pub(crate) fn replace_first_u64_le(haystack: &mut [u8], needle: u64, replacement: u64) {
    let needle_bytes = needle.to_le_bytes();
    let matches: Vec<usize> = haystack
        .windows(8)
        .enumerate()
        .filter(|(_, w)| *w == needle_bytes)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one occurrence of {needle} to corrupt, found {}; pick a more distinctive needle",
        matches.len()
    );
    haystack[matches[0]..matches[0] + 8].copy_from_slice(&replacement.to_le_bytes());
}

/// Runs `f` on a fresh OS thread and waits up to `timeout` for it to
/// finish. Returns `true` if it completed in time. Used to turn "does this
/// synchronous call hang forever on malformed input" into a bounded,
/// CI-safe assertion instead of an unbounded `cargo test` hang -- the
/// spawned thread itself can't be killed if `f` really does hang, but the
/// *test* fails promptly and says so, which is what matters for signal.
pub(crate) fn completes_within<F>(timeout: Duration, f: F) -> bool
where
    F: FnOnce() + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    rx.recv_timeout(timeout).is_ok()
}
