//! gabriel-client
//!
//! v0.1 stub: a CLI so gabriel-core can be exercised end-to-end before any
//! UI work starts. Per the blueprint's tech-stack section, the real client
//! becomes WinUI 3 (native look) or Tauri (single Rust+web codebase) once
//! there's a protocol worth putting a face on.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use gabriel_core::discovery::DiscoveryService;
use gabriel_core::gateway::GatewayClient;
use gabriel_core::identity::Identity;
use gabriel_core::routing::{MeshRouter, NeighborTable, DEFAULT_MESH_PORT};
use gabriel_core::store::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
#[command(name = "gabriel-client")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Print this device's identity (creating one if `identity_path`
    /// doesn't exist yet) and exit. Handy for wiring up --neighbor flags
    /// ahead of time without starting a long-running process first.
    Id {
        #[arg(long, default_value = "gabriel-identity.key")]
        identity_path: PathBuf,
    },
    /// Announce this device on the LAN and print peers as they're found.
    /// Run this twice (different --identity-path per instance) on the same
    /// machine or LAN to see discovery actually work.
    Discover {
        /// Where to store/load this device's identity key. Use a distinct
        /// path per instance when running more than one on one machine.
        #[arg(long, default_value = "gabriel-identity.key")]
        identity_path: PathBuf,
        /// Name shown to other peers.
        #[arg(long, default_value = "gabriel-device")]
        name: String,
    },
    /// Fetch a URL through another device's shared gateway (a running
    /// `gabriel-gatewayd`), to prove gateway sharing works end-to-end --
    /// not just that a socket connected.
    Fetch {
        /// The gateway's relay address, e.g. 127.0.0.1:42425, or a LAN
        /// peer's address + gateway port taken from `discover`'s output.
        #[arg(long)]
        via: SocketAddr,
        /// Host to fetch from -- reached *through* the gateway; this
        /// process never resolves or connects to it directly.
        #[arg(long, default_value = "example.com")]
        host: String,
        #[arg(long, default_value_t = 80)]
        port: u16,
        #[arg(long, default_value = "/")]
        path: String,
        #[arg(long, default_value = "gabriel-fetch-identity.key")]
        identity_path: PathBuf,
    },
    /// Run the mesh router: forwards messages for other peers and delivers
    /// anything addressed to this device. Combine with --send-to/--message
    /// to fire off a one-off message once running.
    Mesh {
        #[arg(long, default_value = "gabriel-mesh-identity.key")]
        identity_path: PathBuf,
        #[arg(long, default_value = "gabriel-mesh-device")]
        name: String,
        /// Address the mesh router listens on. Override this when running
        /// more than one mesh node on the same machine (e.g. for a
        /// multi-hop demo) since they can't all share one port.
        #[arg(long, default_value_t = SocketAddr::from(([0, 0, 0, 0], DEFAULT_MESH_PORT)))]
        mesh_bind: SocketAddr,
        /// Skip LAN discovery entirely and rely only on --neighbor entries.
        /// Real discovery can't build a genuine multi-hop topology on one
        /// machine (multicast makes every local process a direct neighbor
        /// of every other), so demos of >1 hop use this instead.
        #[arg(long)]
        no_discovery: bool,
        /// A statically known neighbor: <hex-device-id>@<ip:port>. Repeat
        /// for more than one. Get the hex id from `gabriel-client id`.
        #[arg(long = "neighbor")]
        neighbors: Vec<String>,
        /// SQLite file backing the store-and-forward outbox. A message
        /// sent while this device has no neighbors is queued here and
        /// retried later -- survives even if this process restarts.
        #[arg(long, default_value = "gabriel-mesh.sqlite")]
        store_path: PathBuf,
        /// Hex device id to send a one-off message to once the router is up.
        #[arg(long, requires = "message")]
        send_to: Option<String>,
        /// The message body to send (requires --send-to).
        #[arg(long, requires = "send_to")]
        message: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Id { identity_path }) => {
            let identity = Identity::load_or_create(&identity_path)?;
            println!("{}", gabriel_core::hex_encode(&identity.public_key()));
            Ok(())
        }
        Some(Command::Discover { identity_path, name }) => run_discover(identity_path, name).await,
        Some(Command::Fetch {
            via,
            host,
            port,
            path,
            identity_path,
        }) => run_fetch(via, host, port, path, identity_path).await,
        Some(Command::Mesh {
            identity_path,
            name,
            mesh_bind,
            no_discovery,
            neighbors,
            store_path,
            send_to,
            message,
        }) => run_mesh(identity_path, name, mesh_bind, no_discovery, neighbors, store_path, send_to, message).await,
        None => {
            println!("gabriel-client v{} (CLI stub)", env!("CARGO_PKG_VERSION"));
            println!("Subcommands: id, discover, fetch, mesh -- try `gabriel-client mesh --help`");
            Ok(())
        }
    }
}

async fn run_discover(identity_path: PathBuf, name: String) -> anyhow::Result<()> {
    let identity = Arc::new(Identity::load_or_create(&identity_path)?);
    println!("device id: {}", gabriel_core::hex_encode(&identity.public_key()));
    println!(
        "announcing as \"{name}\" on {}:{} -- Ctrl+C to stop",
        gabriel_core::discovery::DISCOVERY_MULTICAST_ADDR,
        gabriel_core::discovery::DISCOVERY_PORT
    );

    // This client doesn't offer gateway sharing itself -- that's
    // gabriel-gatewayd's job. It still announces so other peers (including
    // a gatewayd) can see it.
    let service = Arc::new(DiscoveryService::new(identity, name, 0, false));
    let _handle = service.clone().spawn()?;

    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let peers = service.peers();
        println!("--- {} peer(s) seen ---", peers.len());
        for p in &peers {
            let gateway_tag = if p.offers_gateway { " [gateway]" } else { "" };
            println!(
                "  {} @ {}{gateway_tag} \"{}\" (last seen {:.1}s ago)",
                gabriel_core::hex_encode(&p.device_id),
                p.addr,
                p.display_name,
                p.last_seen.elapsed().as_secs_f32()
            );
        }
    }
}

async fn run_fetch(
    via: SocketAddr,
    host: String,
    port: u16,
    path: String,
    identity_path: PathBuf,
) -> anyhow::Result<()> {
    let identity = Identity::load_or_create(&identity_path)?;
    println!("device id: {}", gabriel_core::hex_encode(&identity.public_key()));
    println!("requesting {host}:{port}{path} via gateway {via} ...");

    let mut tunnel = GatewayClient::connect_via(&identity, via, &host, port).await?;
    println!("gateway accepted -- tunnel established, sending HTTP request");

    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tunnel.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    tunnel.read_to_end(&mut response).await?;
    println!("--- response ({} bytes, via the gateway at {via}) ---", response.len());
    println!("{}", String::from_utf8_lossy(&response));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_mesh(
    identity_path: PathBuf,
    name: String,
    mesh_bind: SocketAddr,
    no_discovery: bool,
    static_neighbors: Vec<String>,
    store_path: PathBuf,
    send_to: Option<String>,
    message: Option<String>,
) -> anyhow::Result<()> {
    let identity = Arc::new(Identity::load_or_create(&identity_path)?);
    println!("device id: {}", gabriel_core::hex_encode(&identity.public_key()));

    let neighbors = NeighborTable::new();
    for entry in &static_neighbors {
        let (device_id, addr) = parse_neighbor(entry)?;
        neighbors.set(device_id, addr);
        println!("static neighbor: {} @ {addr}", gabriel_core::hex_encode(&device_id));
    }

    let store = Arc::new(Store::open(
        store_path.to_str().ok_or_else(|| anyhow::anyhow!("--store-path must be valid UTF-8"))?,
    )?);
    let (router, mut inbox) = MeshRouter::new(identity.clone(), neighbors.clone(), store);
    let mesh_addr = router.clone().listen(mesh_bind).await?;
    println!("mesh listening on {mesh_addr} (outbox: {})", store_path.display());
    router.clone().spawn_retry_task();

    if no_discovery {
        println!("discovery disabled -- relying only on --neighbor entries above");
    } else {
        let discovery = Arc::new(DiscoveryService::new(identity.clone(), name, mesh_addr.port(), false));
        let _discovery_handle = discovery.clone().spawn()?;
        tokio::spawn({
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
    }

    tokio::spawn(async move {
        while let Some(msg) = inbox.recv().await {
            println!(
                "[mesh] message from {}: {}",
                gabriel_core::hex_encode(&msg.source_id),
                String::from_utf8_lossy(&msg.body)
            );
        }
    });

    if let (Some(dest_hex), Some(text)) = (send_to, message) {
        let dest = parse_device_id(&dest_hex)?;
        // Give discovery/static wiring a moment to settle before flooding.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let sent_to = router.send(dest, text.clone().into_bytes()).await?;
        if sent_to > 0 {
            println!("[mesh] flooded \"{text}\" to {sent_to} neighbor(s)");
        } else {
            println!("[mesh] no neighbors right now -- queued \"{text}\" in the outbox for later retry");
        }
    }

    // Stay up so this device keeps forwarding/receiving for others.
    std::future::pending::<()>().await;
    Ok(())
}

fn parse_neighbor(entry: &str) -> anyhow::Result<([u8; 32], SocketAddr)> {
    let (id_hex, addr) = entry
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("--neighbor must look like <hex-device-id>@<ip:port>, got {entry:?}"))?;
    Ok((parse_device_id(id_hex)?, addr.parse()?))
}

fn parse_device_id(hex: &str) -> anyhow::Result<[u8; 32]> {
    if hex.len() != 64 {
        anyhow::bail!("device id must be exactly 64 hex characters (32 bytes), got {} chars", hex.len());
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("device id must be exactly 32 bytes"))
}
