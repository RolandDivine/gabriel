# Gabriel

Adaptive, privacy-preserving connectivity platform for Windows -- LAN mesh
messaging, store-and-forward resilience, and (later) crypto-native value
transfer over standard, transparent on-chain transactions.

Full architecture, threat model, and roadmap: see the **Windows MVP Blueprint**
doc (kept outside this repo -- link it here once you have a stable share link
for it).

## Status

v0.1 in progress. Working so far, each verified by an automated test plus a
live run (not just "it compiles"):

- `crates/gabriel-core`
  - `crypto` -- cryptographic agility layer: an algorithm-tagged
    `AgilePublicKey`/`AgileSignature`, with a dispatch-based `verify()` that
    picks the right algorithm from the tag rather than assuming one. Two
    real algorithms behind it today: `Ed25519` (what `identity.rs` and the
    wire protocols below still use directly) and `MlDsa44` (NIST FIPS 204,
    genuinely post-quantum, via RustCrypto's pure-Rust `ml-dsa` crate --
    no C toolchain/liboqs needed, which is what made wiring in a *real*
    PQC algorithm feasible in this pass rather than deferring it).
    Measured, not just claimed: a round-trip test asserts the actual
    ML-DSA-44 key/signature sizes (1312 / 2420 bytes) match FIPS 204.
    **Not yet done:** `identity.rs` and the discovery/gateway/routing wire
    structs still hardcode `[u8; 32]`/`[u8; 64]` Ed25519 arrays directly --
    this module is the foundation an actual "run this device as an ML-DSA
    identity on the mesh" migration would build on, not that migration
    itself. That's a bigger, separate change: it touches every wire struct
    that carries a device id or signature.
  - `identity` -- real Ed25519 device keys (software-backed for now; TPM/CNG
    comes later behind the same API)
  - `discovery` -- signed UDP-multicast LAN peer discovery
  - `gateway` -- authenticated TCP relay: a peer with internet access can
    share it with peers that don't have one
  - `routing` -- multi-hop message delivery: signed messages flood across
    known neighbors with a hop-count TTL and dedup, so a message reaches a
    peer you can't hear directly as long as some neighbor chain connects
    you within the hop budget. No routing table yet -- see the module doc
    comment for why that's the right v0.1 tradeoff. Store-and-forward: a
    message sent with zero neighbors persists to the local SQLite outbox
    instead of being dropped, and a background task retries it (re-signed
    with a fresh timestamp, same message id) every 15s until a neighbor
    shows up or it expires (24h default) -- survives the process
    restarting, not just a brief gap.
  - `protocol` -- GNP packet model (defined, not yet wired to a transport)
  - `store` -- local-first SQLite data model, including the `mesh_outbox`
    table routing's store-and-forward queue lives in
- `crates/gabriel-gatewayd` -- announces itself on the LAN (offering gateway
  sharing), runs the mesh router (with its outbox backed by a real file,
  `--store-path`), and runs the gateway relay. Console-mode only; Windows
  Service registration is still a later build-order item.
- `crates/gabriel-client` -- CLI: `id` (print device id), `discover` (LAN
  peer discovery), `fetch` (pull a URL through another device's
  gabriel-gatewayd, proving gateway sharing end-to-end), and `mesh` (run
  the router; optionally fire a one-off message with `--send-to`/
  `--message`). No UI yet.

**Security hardening pass (first increment):** every parser that touches
attacker-controlled bytes -- discovery's UDP handler, the gateway relay's
request handshake, mesh routing's message envelope, GNP's packet type, and
the shared frame-length parsing in `wire` -- now has adversarial-input
tests: ~3000 iterations of random garbage per parser (never panics) plus a
targeted hand-corrupted length-prefix payload per parser (must error
cleanly and promptly, not hang or over-allocate). Also added: a concurrency
cap (`tokio::sync::Semaphore`) on both the gateway relay's and mesh
router's accept loops, so a connection flood degrades to "new connections
refused" instead of unbounded resource growth; and a real fix for a real
bug the testing found -- the gateway relay's request had no nonce, so a
captured, validly-signed request could be replayed and accepted again
within the 30s freshness window (verified exploitable, then fixed with a
nonce + seen-cache, then verified fixed -- see `gateway.rs`'s test
`replaying_a_captured_request_is_rejected_the_second_time` and its doc
comment for the before/after). Real coverage-guided fuzzing (cargo-fuzz)
needs a Linux target -- WSL isn't set up on this machine; installing a
distro just for this felt like too heavy a detour for now, but it's a
solid next step if this project's threat model ever calls for more than
the hand-written adversarial cases above.

Not started: MLS messaging/encryption, GACL path scoring, Windows Service
packaging, an admission policy for who's allowed to route through /
gateway via a given device (today: anyone with a keypair, though a replay
of the same request is no longer one of the ways to abuse that). The
blueprint's IPC boundary (a named pipe between the client and gateway
service, DPAPI-protected token) is design only -- **no code for it exists
yet**, so it hasn't been (and couldn't yet be) pen-tested; today's
client/service processes only talk to each other over the network
protocols above, not a local control channel.

## Build order (see the blueprint for the full rationale)

1. Local mesh + E2E messaging foundation on a single LAN
2. Gateway sharing between two Windows machines
3. Multi-hop routing + store-and-forward across 3+ peers
4. Security hardening pass, cryptographic agility layer
5. (Later, separately scoped) satellite/NTN research, crypto payments module

## Requirements

- Rust (stable, `x86_64-pc-windows-msvc` target) -- install via
  [rustup](https://rustup.rs/)
- Visual Studio Build Tools (2019 or 2022) with the "Desktop development
  with C++" workload, **and** the Windows 10/11 SDK component specifically
  -- the C++ workload alone does not include it, and without it linking
  fails with `LNK1181: cannot open input file 'kernel32.lib'`

## Building

If you're in an ordinary Developer Command Prompt / Developer PowerShell
(or VS Code with the C++ extension's terminal), this just works:

```bash
cargo build --workspace
```

**From Git Bash specifically**, two things bite:

1. Git Bash ships its own `link.exe` (a coreutils hardlink tool, nothing to
   do with linking) which shadows MSVC's real linker on PATH. Run through
   an actual MSVC environment instead -- see `build.cmd` / `verify.cmd`
   (gitignored, machine-specific) for the pattern: call `vcvars64.bat`,
   then `cargo build`, all inside one `cmd.exe` invocation so the env vars
   it sets actually take effect.
2. Git Bash's MSYS layer rewrites arguments that look like Unix paths --
   this mangles both `cmd.exe /c ...` (into a bogus path, so the `/c` flag
   is lost and `cmd` opens an idle interactive prompt instead of running
   your command) and a bare `/` passed as a CLI argument (e.g.
   `--path /` silently becomes `--path C:/Program Files/Git/`). Prefix the
   command with `MSYS_NO_PATHCONV=1` when either applies.

## Running

```bash
# Terminal 1: a gateway that shares its internet connection
cargo run -p gabriel-gatewayd -- --name my-gateway

# Terminal 2: discover it on the LAN
cargo run -p gabriel-client -- discover --name my-laptop

# Terminal 3: prove gateway sharing works by fetching a real page through it
MSYS_NO_PATHCONV=1 cargo run -p gabriel-client -- fetch --via 127.0.0.1:42425 --host example.com --path /
```

**Multi-hop routing demo** -- three nodes in a line (A -- B -- C), where A
and C are deliberately never told about each other, only about B. Real LAN
discovery can't produce this on one machine (multicast makes every local
process a direct neighbor of every other), so this uses `--no-discovery`
and manual `--neighbor` wiring instead -- the routing/forwarding code path
is identical to what discovery would drive on a real multi-machine LAN.

```bash
# Get each node's device id first
cargo run -p gabriel-client -- id --identity-path a.key   # -> ID_A
cargo run -p gabriel-client -- id --identity-path b.key   # -> ID_B
cargo run -p gabriel-client -- id --identity-path c.key   # -> ID_C

# Terminal 1: B knows both A and C
cargo run -p gabriel-client -- mesh --identity-path b.key --mesh-bind 127.0.0.1:43002 \
  --no-discovery --neighbor ID_A@127.0.0.1:43001 --neighbor ID_C@127.0.0.1:43003

# Terminal 2: C only knows B
cargo run -p gabriel-client -- mesh --identity-path c.key --mesh-bind 127.0.0.1:43003 \
  --no-discovery --neighbor ID_B@127.0.0.1:43002

# Terminal 3: A only knows B -- sends straight to C anyway
cargo run -p gabriel-client -- mesh --identity-path a.key --mesh-bind 127.0.0.1:43001 \
  --no-discovery --neighbor ID_B@127.0.0.1:43002 --send-to ID_C --message "hi from a"
# Terminal 2 (C) should print: [mesh] message from <ID_A>: hi from a
```

**Store-and-forward demo** -- send to a peer while completely isolated
(zero neighbors), confirm it queues instead of failing, kill the process,
then restart it later with a neighbor now available and watch the queued
message go out on its own, with no resend command.

```bash
# A, alone, tries to reach a peer it doesn't know about yet -- queues, doesn't fail
cargo run -p gabriel-client -- mesh --identity-path a.key --store-path a.sqlite \
  --mesh-bind 127.0.0.1:44001 --no-discovery --send-to ID_C --message "catch up later"
# -> "[mesh] no neighbors right now -- queued ... for later retry"
# Ctrl+C it (or kill -9 it -- the point is it didn't get a graceful shutdown)

# ...later, C is now reachable. Restart A with the SAME --store-path, no --send-to:
cargo run -p gabriel-client -- mesh --identity-path a.key --store-path a.sqlite \
  --mesh-bind 127.0.0.1:44001 --no-discovery --neighbor ID_C@127.0.0.1:44003
# within 15s (the retry interval), C receives the message A queued in the PREVIOUS run
```

## Non-goals (carried over from the blueprint, load-bearing, do not relax)

- No base-station spoofing or carrier billing bypass
- No unauthorized satellite access or spectrum impersonation
- No transaction mixing/tumbling or anything designed to defeat blockchain
  analysis -- value transfer is standard, transparent on-chain transactions
  only
- No message-content telemetry by default
