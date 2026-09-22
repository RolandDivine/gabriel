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
                    neighbors.set(peer.device_id, SocketAddr::new(peer.addr.ip(), peer.gnp_port));
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

    println!("gateway relay listening on {}", args.bind);
    // Runs forever; Ctrl+C stops the process. No graceful shutdown wired up
    // yet -- fine for a console dev process, revisit once this becomes a
    // real Windows Service with its own stop-control handler.
    GatewayServer::new().run(args.bind).await
}
