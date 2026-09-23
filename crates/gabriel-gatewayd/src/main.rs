//! gabriel-gatewayd
//!
//! v0.1: runs as an ordinary console process for local development. Does
//! three things together, matching the blueprint's Gateway Service role
//! (identity/routing/connection-sharing, minus GACL path scoring which
//! comes later):
//!   1. Announces itself on the LAN via discovery, offering gateway sharing
//!   2. Runs the mesh router, so it can forward messages for peers even
//!      when it isn't the final destination
//!   3. Runs the gateway relay, so peers without their own internet path
//!      can route TCP traffic through it
//!
//! Windows Service registration (via the `windows-service` crate + an
//! installer) is still a later build-order item -- see the Roadmap section
//! of the blueprint -- but the service's actual job runs here already.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use gabriel_core::discovery::DiscoveryService;
use gabriel_core::gateway::{GatewayServer, DEFAULT_GATEWAY_PORT};
use gabriel_core::metering::{QuotaPolicy, UsageLedger};
use gabriel_core::identity::Identity;
use gabriel_core::routing::{MeshRouter, NeighborTable, DEFAULT_MESH_PORT};
use gabriel_core::store::Store;

#[derive(Parser, Debug)]
#[command(name = "gabriel-gatewayd")]
struct Args {
    /// Where to store/load this device's identity key.
    #[arg(long, default_value = "gabriel-gateway-identity.key")]
    identity_path: PathBuf,
    /// Name shown to LAN peers.
    #[arg(long, default_value = "gabriel-gateway")]
    name: String,
    /// Address the gateway relay listens on. Peers without their own
    /// internet path connect here to have their TCP traffic forwarded.
    #[arg(long, default_value_t = SocketAddr::from(([0, 0, 0, 0], DEFAULT_GATEWAY_PORT)))]
    bind: SocketAddr,
    /// Address the mesh router listens on, for messages forwarded through
    /// (or addressed to) this device.
    #[arg(long, default_value_t = SocketAddr::from(([0, 0, 0, 0], DEFAULT_MESH_PORT)))]
    mesh_bind: SocketAddr,
    /// Count every relayed byte against the device that requested it, and
    /// persist the totals. Without this the gateway relays for anyone and
    /// records nothing, which is what it did before metering existed.
    #[arg(long)]
    metered: bool,
    /// Only relay for devices that have been granted an allowance. Implies
    /// --metered. This is the policy a gateway selling bandwidth runs;
    /// without it, a device with no grant is relayed for and simply
    /// counted.
    #[arg(long)]
    require_grant: bool,
    /// Grant a device an allowance and exit: <hex-device-id>=<bytes>.
    /// Accepts a suffix, so 500MB and 2GB both work. Repeat for more than
    /// one device.
    #[arg(long = "grant")]
    grants: Vec<String>,
    /// Print what each device has used, and exit.
    #[arg(long)]
    usage: bool,
    /// SQLite file backing the mesh router's store-and-forward outbox.
    /// Queued messages survive a restart because this is a real file, not
    /// in-memory state.
    #[arg(long, default_value = "gabriel-gateway.sqlite")]
    store_path: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let identity = Arc::new(Identity::load_or_create(&args.identity_path)?);

    println!("gabriel-gatewayd v{} starting", env!("CARGO_PKG_VERSION"));
    println!("device id: {}", gabriel_core::hex_encode(&identity.public_key()));

    let store = Arc::new(Store::open(args.store_path.to_str().ok_or_else(|| {
        anyhow::anyhow!("--store-path must be valid UTF-8")
    })?)?);

    // --require-grant only means anything if usage is being counted.
    let metered = args.metered || args.require_grant || !args.grants.is_empty() || args.usage;
    let policy = if args.require_grant {
        QuotaPolicy::RequireGrant
    } else {
        QuotaPolicy::Open
    };
    let ledger = UsageLedger::new(store.clone(), policy);

    // Granting and reporting are administrative: do the work and exit
    // rather than starting a relay nobody asked for.
    if !args.grants.is_empty() {
        for entry in &args.grants {
            let (device_id, bytes) = parse_grant(entry)?;
            ledger.grant(&device_id, bytes, None)?;
            println!(
                "granted {} to {}",
                format_bytes(bytes),
                gabriel_core::hex_encode(&device_id)
            );
        }
        return Ok(());
    }

    if args.usage {
        let devices = ledger.all_device_usage()?;
        if devices.is_empty() {
            println!("no device has used this gateway yet");
            return Ok(());
        }
        println!("{:<66} {:>12} {:>12} {:>9}", "device", "used", "granted", "sessions");
        for d in devices {
            let granted = d
                .granted_bytes
                .map(format_bytes)
                .unwrap_or_else(|| "unmetered".to_string());
            println!(
                "{:<66} {:>12} {:>12} {:>9}",
                gabriel_core::hex_encode(&d.device_id),
                format_bytes(d.consumed_bytes),
                granted,
                d.sessions
            );
        }
        return Ok(());
    }

    // A session left open by a crash still holds bytes that were
    // checkpointed; close it so those stop looking like live traffic.
    if metered {
        let reconciled = ledger.close_orphaned_sessions()?;
        if reconciled > 0 {
            println!("reconciled {reconciled} session(s) left open by a previous run");
        }
    }

    let neighbors = NeighborTable::new();
    let (router, mut inbox) = MeshRouter::new(identity.clone(), neighbors.clone(), store);
    let mesh_addr = router.clone().listen(args.mesh_bind).await?;
    println!("mesh router listening on {mesh_addr} (outbox: {})", args.store_path.display());
    router.clone().spawn_retry_task();

    // Announce our REAL mesh port, not a placeholder -- other peers use
    // this (PeerInfo.gnp_port) to build their own neighbor tables.
    let discovery = Arc::new(DiscoveryService::new(
        identity.clone(),
        args.name.clone(),
        mesh_addr.port(),
        true, // offers_gateway
    ));
    let _discovery_handle = discovery.clone().spawn()?;
    println!("announcing \"{}\" on the LAN, offering gateway sharing", args.name);

    // Keep the mesh router's neighbor table in sync with whoever discovery
    // currently sees on the LAN.
    tokio::spawn({
        let discovery = discovery.clone();
        let neighbors = neighbors.clone();
        async move {
            loop {
                for peer in discovery.peers() {
                    // Skips discovery-only peers (no mesh listener) -- see
                    // PeerInfo::mesh_addr.
                    if let Some(addr) = peer.mesh_addr() {
                        neighbors.set(peer.device_id, addr);
                    }
                }
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    });

    // Print anything addressed to this device (as opposed to messages it's
    // just forwarding on for someone else).
    tokio::spawn(async move {
        while let Some(msg) = inbox.recv().await {
            println!(
                "[mesh] message from {}: {}",
                gabriel_core::hex_encode(&msg.source_id),
                String::from_utf8_lossy(&msg.body)
            );
        }
    });

    if metered {
        println!(
            "gateway relay listening on {} -- metered, {}",
            args.bind,
            match policy {
                QuotaPolicy::RequireGrant => "relaying only for devices with a grant",
                QuotaPolicy::Open => "relaying for anyone, counting every byte",
            }
        );
    } else {
        println!("gateway relay listening on {} -- unmetered", args.bind);
    }
    // Runs forever; Ctrl+C stops the process. No graceful shutdown wired up
    // yet -- fine for a console dev process, revisit once this becomes a
    // real Windows Service with its own stop-control handler.
    if metered {
        GatewayServer::metered(ledger).run(args.bind).await
    } else {
        GatewayServer::new().run(args.bind).await
    }
}

/// Parses `<hex-device-id>=<bytes>`, where the byte count may carry a
/// KB/MB/GB suffix. Decimal units, not binary: a user typing 500MB means
/// what their data plan means by it.
fn parse_grant(entry: &str) -> anyhow::Result<([u8; 32], u64)> {
    let (id_hex, amount) = entry.split_once('=').ok_or_else(|| {
        anyhow::anyhow!("--grant must look like <hex-device-id>=<bytes>, got {entry:?}")
    })?;

    let device_id = parse_device_id(id_hex)?;
    let amount = amount.trim().to_uppercase();
    let (digits, multiplier) = if let Some(n) = amount.strip_suffix("GB") {
        (n, 1_000_000_000u64)
    } else if let Some(n) = amount.strip_suffix("MB") {
        (n, 1_000_000)
    } else if let Some(n) = amount.strip_suffix("KB") {
        (n, 1_000)
    } else {
        (amount.as_str(), 1)
    };

    let value: f64 = digits
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("{digits:?} is not a number of bytes"))?;
    if value < 0.0 {
        anyhow::bail!("a grant cannot be negative");
    }
    Ok((device_id, (value * multiplier as f64) as u64))
}

fn parse_device_id(hex: &str) -> anyhow::Result<[u8; 32]> {
    if hex.len() != 64 {
        anyhow::bail!("device id must be exactly 64 hex characters, got {}", hex.len());
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("device id must be exactly 32 bytes"))
}

/// Decimal units, to match how data plans are sold.
fn format_bytes(bytes: u64) -> String {
    const UNITS: [(u64, &str); 3] = [(1_000_000_000, "GB"), (1_000_000, "MB"), (1_000, "KB")];
    for (scale, suffix) in UNITS {
        if bytes >= scale {
            return format!("{:.2}{suffix}", bytes as f64 / scale as f64);
        }
    }
    format!("{bytes}B")
}
