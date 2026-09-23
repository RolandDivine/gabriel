#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! Gabriel desktop client.
//!
//! Tauri is Rust, so this links `gabriel-core` directly -- no C ABI, no
//! marshalling layer. (`crates/gabriel-ffi` still exists for non-Rust
//! consumers; nothing here needs it.)
//!
//! **Scope rule for this file:** every capability `gabriel-client` and
//! `gabriel-gatewayd` expose on the command line has a command here, plus
//! the parts of `gabriel-core` the CLI never grew a flag for (the crypto
//! agility layer, the GNP packet model, the outbox, the local schema).
//! The first version of this app only did messaging, which made the
//! platform look like a chat client. It isn't one. The mapping is:
//!
//!   gabriel-client id              -> node_status, identity_sign/verify
//!   gabriel-client discover        -> list_peers, set_display_name
//!   gabriel-client mesh            -> send_message, poll_inbox, restart_node
//!   gabriel-client mesh --neighbor -> add_neighbor, remove_neighbor
//!   gabriel-client fetch --via     -> gateway_fetch
//!   gabriel-gatewayd               -> start_gateway, stop_gateway
//!   (no CLI equivalent)            -> list_outbox / retry_outbox / prune_outbox
//!   (no CLI equivalent)            -> crypto_* (the agility layer)
//!   (no CLI equivalent)            -> gnp_build / gnp_decode
//!   gabriel-gatewayd --usage       -> list_usage, list_sessions
//!   gabriel-gatewayd --grant       -> grant_data, revoke_data
//!   (no CLI equivalent)            -> table_counts (the local schema)
//!
//! The core is async and the webview calls in synchronously, so the node
//! owns a tokio runtime and every command blocks briefly on it. Received
//! messages accumulate in a buffer the UI drains by polling, which keeps
//! the frontend a plain static page with no event plumbing.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::{Manager, State};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use gabriel_core::crypto::{self, AgilePublicKey, AgileSignature, AgileSigningKey, AlgorithmId};
use gabriel_core::discovery::{DiscoveryService, DISCOVERY_MULTICAST_ADDR, DISCOVERY_PORT};
use gabriel_core::gateway::{GatewayClient, GatewayServer, DEFAULT_GATEWAY_PORT};
use gabriel_core::metering::{QuotaPolicy, UsageLedger};
use gabriel_core::identity::Identity;
use gabriel_core::protocol::{GnpPacket, PacketType};
use gabriel_core::routing::{MeshRouter, NeighborTable};
use gabriel_core::store::Store;

/// How long `gateway_fetch` waits for a whole response before giving up.
/// Long enough for a slow relay hop, short enough that a wedged gateway
/// doesn't leave the UI's button spinning forever.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Cap on a relayed response we'll buffer in memory to hand to the
/// webview. The tunnel itself is unbounded; this is only what the
/// *inspector* holds.
const FETCH_MAX_BYTES: usize = 2 * 1024 * 1024;
const LOG_CAPACITY: usize = 600;

// ---------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------

/// The relay half of gateway sharing, when it's running.
struct GatewayHandle {
    addr: SocketAddr,
    started_at: Instant,
    task: tokio::task::JoinHandle<gabriel_core::Result<()>>,
}

struct Node {
    runtime: tokio::runtime::Runtime,
    identity: Arc<Identity>,
    discovery: Arc<DiscoveryService>,
    router: Arc<MeshRouter>,
    neighbors: NeighborTable,
    store: Arc<Store>,
    inbox: Arc<Mutex<Vec<InboxMessage>>>,
    mesh_addr: SocketAddr,
    data_dir: PathBuf,
    started_at: Instant,
    /// Device ids the user wired up by hand. Discovery writes into the same
    /// table, so without this the UI couldn't tell a hand-entered neighbor
    /// from an automatically discovered one -- which matters, because
    /// removing a discovered neighbor only sticks until the next sync pass.
    manual_neighbors: Arc<Mutex<HashSet<[u8; 32]>>>,
    gateway: Mutex<Option<GatewayHandle>>,
    /// Byte accounting for the gateway relay. Built whether or not the
    /// relay is running, so usage from previous runs is readable at any
    /// time -- it lives in the same SQLite file as everything else.
    ledger: Arc<UsageLedger>,
}

impl Node {
    /// Stops everything. Dropping the runtime is what aborts the
    /// discovery/mesh/retry tasks, but the relay gets an explicit abort
    /// first so its listening socket is released before a new node tries
    /// to bind the same port.
    fn shutdown(self) {
        if let Some(gw) = self.gateway.lock().unwrap().take() {
            gw.task.abort();
        }
        self.runtime.shutdown_timeout(Duration::from_secs(3));
    }
}

// ---------------------------------------------------------------------
// Event log
// ---------------------------------------------------------------------

#[derive(Serialize, Clone)]
struct LogEntry {
    ts_unix: u64,
    level: String,
    text: String,
}

/// A bounded, shared ring of what the node has been doing. Background
/// tasks write to it as well as commands, so it's a cloneable type of its
/// own rather than just another field on `AppState`.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<VecDeque<LogEntry>>>);

impl Log {
    fn push(&self, level: &str, text: impl Into<String>) {
        let entry = LogEntry {
            ts_unix: now_unix(),
            level: level.to_string(),
            text: text.into(),
        };
        let mut buf = self.0.lock().unwrap();
        if buf.len() >= LOG_CAPACITY {
            buf.pop_front();
        }
        buf.push_back(entry);
    }

    fn entries(&self) -> Vec<LogEntry> {
        self.0.lock().unwrap().iter().cloned().collect()
    }

    fn clear(&self) {
        self.0.lock().unwrap().clear();
    }
}

// ---------------------------------------------------------------------
// App state
// ---------------------------------------------------------------------

#[derive(Default)]
struct AppState {
    node: Mutex<Option<Node>>,
    /// Why startup failed, if it did -- surfaced in the UI rather than
    /// leaving the window looking merely empty.
    error: Mutex<Option<String>>,
    log: Log,
    /// The full send/receive transcript, kept here rather than in the page
    /// so switching tabs doesn't lose it.
    history: Mutex<Vec<ChatMessage>>,
    /// Scratch keys for the crypto tab. Private key material never leaves
    /// this map -- `KeyView` carries the public half only.
    keyring: Mutex<HashMap<String, AgileSigningKey>>,
    key_seq: AtomicU64,
}

// ---------------------------------------------------------------------
// Views (what crosses into the webview)
// ---------------------------------------------------------------------

#[derive(Clone)]
struct InboxMessage {
    from: String,
    text: String,
    received_unix: u64,
}

#[derive(Serialize, Clone)]
struct ChatMessage {
    /// "in", "out" or "system"
    direction: String,
    peer: String,
    text: String,
    ts_unix: u64,
    note: Option<String>,
}

#[derive(Serialize)]
struct PeerView {
    device_id: String,
    display_name: String,
    address: String,
    /// ip:port the peer's beacon came from.
    source_addr: String,
    /// The mesh port the peer advertises. 0 means "discovery only".
    gnp_port: u16,
    /// Where we'd actually dial this peer's mesh router, if anywhere.
    mesh_addr: Option<String>,
    offers_gateway: bool,
    routable: bool,
    /// Whether this peer is in the mesh neighbor table right now.
    is_neighbor: bool,
    last_seen_secs: f32,
}

#[derive(Serialize)]
struct NeighborView {
    device_id: String,
    address: String,
    /// "manual" when the user typed it in, "discovered" otherwise.
    origin: String,
    /// The discovery display name, when we've also seen a beacon from it.
    display_name: Option<String>,
}

#[derive(Serialize)]
struct StatusView {
    running: bool,
    version: String,
    device_id: String,
    display_name: String,
    mesh_addr: String,
    mesh_port: u16,
    discovery_group: String,
    data_dir: String,
    identity_path: String,
    store_path: String,
    uptime_secs: u64,
    peer_count: usize,
    routable_peer_count: usize,
    gateway_peer_count: usize,
    neighbor_count: usize,
    outbox_count: usize,
    gateway_sharing: bool,
    gateway_addr: Option<String>,
    gateway_uptime_secs: u64,
    default_gateway_port: u16,
    /// Whether the relay is counting bytes, and whether it turns away
    /// devices that have no grant.
    metered: bool,
    require_grant: bool,
    total_relayed_bytes: u64,
    metered_device_count: usize,
    error: Option<String>,
}

#[derive(Serialize)]
struct SendResult {
    reached: usize,
    queued: bool,
}

#[derive(Serialize)]
struct BroadcastResult {
    targets: usize,
    reached: usize,
    queued: usize,
}

#[derive(Serialize)]
struct OutboxView {
    message_id: String,
    destination_id: String,
    destination_name: Option<String>,
    body: String,
    created_at: i64,
    expires_at: i64,
    expires_in_secs: i64,
    attempts: i64,
}

#[derive(Serialize)]
struct FetchResult {
    via: String,
    target: String,
    status_line: String,
    headers: Vec<String>,
    body: String,
    total_bytes: usize,
    elapsed_ms: u64,
    truncated: bool,
}

#[derive(Serialize)]
struct AlgorithmInfo {
    id: String,
    label: String,
    post_quantum: bool,
    public_key_bytes: usize,
    signature_bytes: usize,
    note: String,
}

#[derive(Serialize, Clone)]
struct KeyView {
    key_id: String,
    algorithm: String,
    public_key: String,
    public_key_bytes: usize,
}

#[derive(Serialize)]
struct SignView {
    algorithm: String,
    public_key: String,
    signature: String,
    signature_bytes: usize,
}

#[derive(Serialize)]
struct GnpView {
    version: u8,
    packet_type: String,
    source_identity: String,
    destination_identity: String,
    sequence_number: u64,
    expiration: u64,
    payload_utf8: Option<String>,
    payload_bytes: usize,
    authentication_tag: String,
    encoded_hex: String,
    encoded_bytes: usize,
}

#[derive(Serialize)]
struct UsageView {
    device_id: String,
    display_name: Option<String>,
    consumed_bytes: u64,
    granted_bytes: Option<u64>,
    remaining_bytes: Option<u64>,
    /// 0..=100, or None when the device has no grant.
    percent_used: Option<u8>,
    sessions: u64,
    last_seen_unix: Option<i64>,
}

#[derive(Serialize)]
struct SessionView {
    session_id: String,
    device_id: String,
    display_name: Option<String>,
    target: String,
    bytes_up: u64,
    bytes_down: u64,
    started_at: i64,
    ended_at: Option<i64>,
    closed: bool,
}

#[derive(Serialize)]
struct TableCount {
    name: String,
    rows: i64,
    /// Whether anything in the build actually writes to this table yet.
    written_by_v01: bool,
}

// ---------------------------------------------------------------------
// Node lifecycle
// ---------------------------------------------------------------------

#[tauri::command]
fn node_status(state: State<AppState>) -> StatusView {
    let node = state.node.lock().unwrap();
    let Some(node) = node.as_ref() else {
        return StatusView {
            running: false,
            version: env!("CARGO_PKG_VERSION").to_string(),
            device_id: String::new(),
            display_name: String::new(),
            mesh_addr: String::new(),
            mesh_port: 0,
            discovery_group: discovery_group(),
            data_dir: data_dir().display().to_string(),
            identity_path: String::new(),
            store_path: String::new(),
            uptime_secs: 0,
            peer_count: 0,
            routable_peer_count: 0,
            gateway_peer_count: 0,
            neighbor_count: 0,
            outbox_count: 0,
            gateway_sharing: false,
            gateway_addr: None,
            gateway_uptime_secs: 0,
            default_gateway_port: DEFAULT_GATEWAY_PORT,
            metered: false,
            require_grant: false,
            total_relayed_bytes: 0,
            metered_device_count: 0,
            error: state.error.lock().unwrap().clone(),
        };
    };

    let peers = node.discovery.peers();
    let gateway = node.gateway.lock().unwrap();
    let devices = node.ledger.all_device_usage().unwrap_or_default();

    StatusView {
        running: true,
        version: env!("CARGO_PKG_VERSION").to_string(),
        device_id: gabriel_core::hex_encode(&node.identity.public_key()),
        display_name: node.discovery.display_name(),
        mesh_addr: node.mesh_addr.to_string(),
        mesh_port: node.mesh_addr.port(),
        discovery_group: discovery_group(),
        data_dir: node.data_dir.display().to_string(),
        identity_path: node.data_dir.join("identity.key").display().to_string(),
        store_path: node.data_dir.join("gabriel.sqlite").display().to_string(),
        uptime_secs: node.started_at.elapsed().as_secs(),
        peer_count: peers.len(),
        routable_peer_count: peers.iter().filter(|p| p.mesh_addr().is_some()).count(),
        gateway_peer_count: peers.iter().filter(|p| p.offers_gateway).count(),
        neighbor_count: node.neighbors.len(),
        outbox_count: node.store.list_pending_outbound().map(|v| v.len()).unwrap_or(0),
        gateway_sharing: gateway.is_some(),
        gateway_addr: gateway.as_ref().map(|g| g.addr.to_string()),
        gateway_uptime_secs: gateway.as_ref().map(|g| g.started_at.elapsed().as_secs()).unwrap_or(0),
        default_gateway_port: DEFAULT_GATEWAY_PORT,
        metered: true,
        require_grant: node.ledger.policy() == QuotaPolicy::RequireGrant,
        total_relayed_bytes: devices.iter().map(|d| d.consumed_bytes).sum(),
        metered_device_count: devices.len(),
        error: state.error.lock().unwrap().clone(),
    }
}

/// Renames this device. Discovery picks it up on its next beacon, so no
/// restart -- see `DiscoveryService::set_display_name`.
#[tauri::command]
fn set_display_name(state: State<AppState>, name: String) -> Result<(), String> {
    let name = name.trim().to_string();
    if name.is_empty() {
        return Err("name can't be empty".into());
    }
    if name.len() > 64 {
        // Announcements ride in a single UDP datagram with a 1KB ceiling;
        // a runaway name would push the beacon past it.
        return Err("name must be 64 characters or fewer".into());
    }
    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;
    node.discovery.set_display_name(name.clone());
    save_settings(&node.data_dir, &name);
    state.log.push("info", format!("renamed this device to \"{name}\""));
    Ok(())
}

/// Tears the node down and starts a fresh one against the same data
/// directory. The identity key is loaded from disk, so the device id
/// survives -- this is a reconnect, not a new identity.
#[tauri::command]
fn restart_node(state: State<AppState>) -> Result<(), String> {
    let previous_name = {
        let node = state.node.lock().unwrap();
        node.as_ref().map(|n| n.discovery.display_name())
    };

    if let Some(node) = state.node.lock().unwrap().take() {
        state.log.push("warn", "stopping node");
        node.shutdown();
    }
    *state.error.lock().unwrap() = None;

    let name = previous_name.unwrap_or_else(default_display_name);
    match start_node(name, state.log.clone()) {
        Ok(node) => {
            state.log.push("info", "node restarted");
            *state.node.lock().unwrap() = Some(node);
            Ok(())
        }
        Err(err) => {
            let msg = format!("{err:#}");
            state.log.push("error", format!("restart failed: {msg}"));
            *state.error.lock().unwrap() = Some(msg.clone());
            Err(msg)
        }
    }
}

// ---------------------------------------------------------------------
// Network: peers and the neighbor table
// ---------------------------------------------------------------------

#[tauri::command]
fn list_peers(state: State<AppState>) -> Vec<PeerView> {
    let node = state.node.lock().unwrap();
    let Some(node) = node.as_ref() else {
        return Vec::new();
    };
    let neighbor_ids: HashSet<[u8; 32]> = node.neighbors.list().into_iter().map(|(id, _)| id).collect();

    node.discovery
        .peers()
        .into_iter()
        .map(|p| PeerView {
            device_id: gabriel_core::hex_encode(&p.device_id),
            address: p.addr.ip().to_string(),
            source_addr: p.addr.to_string(),
            gnp_port: p.gnp_port,
            mesh_addr: p.mesh_addr().map(|a| a.to_string()),
            offers_gateway: p.offers_gateway,
            routable: p.mesh_addr().is_some(),
            is_neighbor: neighbor_ids.contains(&p.device_id),
            last_seen_secs: p.last_seen.elapsed().as_secs_f32(),
            // Moved last: mesh_addr() borrows p, so taking the String out
            // before that call would partially move it.
            display_name: p.display_name,
        })
        .collect()
}

#[tauri::command]
fn list_neighbors(state: State<AppState>) -> Vec<NeighborView> {
    let node = state.node.lock().unwrap();
    let Some(node) = node.as_ref() else {
        return Vec::new();
    };
    let manual = node.manual_neighbors.lock().unwrap().clone();
    let names: HashMap<[u8; 32], String> = node
        .discovery
        .peers()
        .into_iter()
        .map(|p| (p.device_id, p.display_name))
        .collect();

    let mut out: Vec<NeighborView> = node
        .neighbors
        .list()
        .into_iter()
        .map(|(id, addr)| NeighborView {
            device_id: gabriel_core::hex_encode(&id),
            address: addr.to_string(),
            origin: if manual.contains(&id) { "manual" } else { "discovered" }.to_string(),
            display_name: names.get(&id).cloned(),
        })
        .collect();
    out.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    out
}

/// The `--neighbor <hex-device-id>@<ip:port>` flag, as a form. Lets the UI
/// build a multi-hop topology by hand -- which is the only way to get one
/// on a single LAN segment, since multicast makes every local node a
/// direct neighbor of every other.
#[tauri::command]
fn add_neighbor(state: State<AppState>, device_id: String, address: String) -> Result<(), String> {
    let id = parse_device_id(&device_id).ok_or("device id must be 64 hex characters")?;
    let addr: SocketAddr = address
        .trim()
        .parse()
        .map_err(|_| "address must look like 192.168.1.5:42426".to_string())?;

    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;
    if id == node.identity.public_key() {
        return Err("that's this device's own id".into());
    }
    if addr.port() == 0 {
        return Err("port 0 isn't a connectable address".into());
    }
    node.neighbors.set(id, addr);
    node.manual_neighbors.lock().unwrap().insert(id);
    state.log.push("info", format!("added neighbour {} @ {addr}", short(&device_id)));
    Ok(())
}

#[tauri::command]
fn remove_neighbor(state: State<AppState>, device_id: String) -> Result<(), String> {
    let id = parse_device_id(&device_id).ok_or("device id must be 64 hex characters")?;
    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;
    node.neighbors.remove(&id);
    let was_manual = node.manual_neighbors.lock().unwrap().remove(&id);
    if was_manual {
        state.log.push("info", format!("removed neighbour {}", short(&device_id)));
    } else {
        // Worth saying out loud: the discovery sync task re-adds anything
        // still announcing itself, within a couple of seconds.
        state.log.push(
            "warn",
            format!(
                "removed discovered neighbour {} -- discovery will re-add it while that peer keeps announcing",
                short(&device_id)
            ),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Messaging
// ---------------------------------------------------------------------

#[tauri::command]
fn send_message(state: State<AppState>, destination: String, text: String) -> Result<SendResult, String> {
    if text.is_empty() {
        return Err("nothing to send".into());
    }
    let dest = parse_device_id(&destination).ok_or("device id must be 64 hex characters")?;

    let (reached, peer_name) = {
        let node = state.node.lock().unwrap();
        let node = node.as_ref().ok_or("node is not running")?;
        let name = node
            .discovery
            .peers()
            .into_iter()
            .find(|p| p.device_id == dest)
            .map(|p| p.display_name)
            .unwrap_or_else(|| short(&destination));
        let reached = node
            .runtime
            .block_on(node.router.send(dest, text.clone().into_bytes()))
            .map_err(|e| e.to_string())?;
        (reached, name)
    };

    let note = if reached > 0 {
        format!("flooded to {reached} neighbour(s)")
    } else {
        "no neighbours reachable -- queued in the outbox for retry".to_string()
    };
    state.log.push(
        if reached > 0 { "info" } else { "warn" },
        format!("send to {peer_name}: {note}"),
    );
    push_history(&state, "out", &peer_name, &text, Some(note));

    Ok(SendResult { reached, queued: reached == 0 })
}

/// Sends the same message to every routable peer. Not a mesh broadcast
/// primitive -- routing has no such packet type -- just one addressed send
/// per peer, which is what "message everyone" honestly amounts to here.
#[tauri::command]
fn broadcast_message(state: State<AppState>, text: String) -> Result<BroadcastResult, String> {
    if text.is_empty() {
        return Err("nothing to send".into());
    }
    let targets: Vec<([u8; 32], String)> = {
        let node = state.node.lock().unwrap();
        let node = node.as_ref().ok_or("node is not running")?;
        node.discovery
            .peers()
            .into_iter()
            .filter(|p| p.mesh_addr().is_some())
            .map(|p| (p.device_id, p.display_name))
            .collect()
    };
    if targets.is_empty() {
        return Err("no routable peers to send to".into());
    }

    let mut reached = 0usize;
    let mut queued = 0usize;
    for (id, name) in &targets {
        let sent = {
            let node = state.node.lock().unwrap();
            let node = node.as_ref().ok_or("node is not running")?;
            node.runtime
                .block_on(node.router.send(*id, text.clone().into_bytes()))
                .map_err(|e| e.to_string())?
        };
        if sent > 0 {
            reached += 1;
        } else {
            queued += 1;
        }
        push_history(
            &state,
            "out",
            name,
            &text,
            Some(if sent > 0 {
                format!("flooded to {sent} neighbour(s)")
            } else {
                "queued".to_string()
            }),
        );
    }
    state.log.push(
        "info",
        format!("broadcast to {} peer(s): {reached} sent, {queued} queued", targets.len()),
    );
    Ok(BroadcastResult { targets: targets.len(), reached, queued })
}

#[tauri::command]
fn poll_inbox(state: State<AppState>) -> Vec<ChatMessage> {
    let drained: Vec<InboxMessage> = {
        let node = state.node.lock().unwrap();
        let Some(node) = node.as_ref() else {
            return Vec::new();
        };
        let mut inbox = node.inbox.lock().unwrap();
        std::mem::take(&mut *inbox)
    };
    if drained.is_empty() {
        return Vec::new();
    }

    let names: HashMap<String, String> = {
        let node = state.node.lock().unwrap();
        match node.as_ref() {
            Some(node) => node
                .discovery
                .peers()
                .into_iter()
                .map(|p| (gabriel_core::hex_encode(&p.device_id), p.display_name))
                .collect(),
            None => HashMap::new(),
        }
    };

    let mut new = Vec::new();
    for msg in drained {
        let peer = names.get(&msg.from).cloned().unwrap_or_else(|| short(&msg.from));
        state.log.push("info", format!("message received from {peer}"));
        let entry = ChatMessage {
            direction: "in".to_string(),
            peer,
            text: msg.text,
            ts_unix: msg.received_unix,
            note: None,
        };
        state.history.lock().unwrap().push(entry.clone());
        new.push(entry);
    }
    new
}

#[tauri::command]
fn message_history(state: State<AppState>) -> Vec<ChatMessage> {
    state.history.lock().unwrap().clone()
}

#[tauri::command]
fn clear_history(state: State<AppState>) {
    state.history.lock().unwrap().clear();
}

// ---------------------------------------------------------------------
// Store-and-forward outbox
// ---------------------------------------------------------------------

#[tauri::command]
fn list_outbox(state: State<AppState>) -> Result<Vec<OutboxView>, String> {
    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;
    let names: HashMap<[u8; 32], String> = node
        .discovery
        .peers()
        .into_iter()
        .map(|p| (p.device_id, p.display_name))
        .collect();
    let now = now_unix() as i64;

    Ok(node
        .store
        .list_pending_outbound()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|m| OutboxView {
            message_id: gabriel_core::hex_encode(&m.message_id),
            destination_id: gabriel_core::hex_encode(&m.destination_id),
            destination_name: names.get(&m.destination_id).cloned(),
            body: String::from_utf8_lossy(&m.body).into_owned(),
            created_at: m.created_at,
            expires_at: m.expires_at,
            expires_in_secs: m.expires_at - now,
            attempts: m.attempts,
        })
        .collect())
}

/// Runs one flush pass now instead of waiting for the background ticker.
#[tauri::command]
fn retry_outbox(state: State<AppState>) -> Result<usize, String> {
    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;
    let sent = node
        .runtime
        .block_on(node.router.retry_pending())
        .map_err(|e| e.to_string())?;
    state.log.push("info", format!("manual outbox flush: {sent} message(s) went out"));
    Ok(sent)
}

#[tauri::command]
fn prune_outbox(state: State<AppState>) -> Result<usize, String> {
    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;
    let removed = node
        .store
        .prune_expired_outbound(now_unix() as i64)
        .map_err(|e| e.to_string())?;
    state.log.push("info", format!("pruned {removed} expired message(s)"));
    Ok(removed)
}

#[tauri::command]
fn cancel_outbound(state: State<AppState>, message_id: String) -> Result<(), String> {
    let id = parse_id16(&message_id).ok_or("message id must be 32 hex characters")?;
    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;
    node.store.remove_outbound(&id).map_err(|e| e.to_string())?;
    state.log.push("warn", format!("cancelled queued message {}", short(&message_id)));
    Ok(())
}

// ---------------------------------------------------------------------
// Gateway: sharing this device's internet connection
// ---------------------------------------------------------------------

/// Starts the relay and flips the discovery beacon's `offers_gateway` flag
/// so peers see this device as usable. This is what `gabriel-gatewayd`
/// does, minus the separate process.
#[tauri::command]
fn start_gateway(state: State<AppState>, port: u16) -> Result<String, String> {
    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;

    if node.gateway.lock().unwrap().is_some() {
        return Err("gateway sharing is already running".into());
    }

    let bind: SocketAddr = format!("0.0.0.0:{port}")
        .parse()
        .map_err(|_| "invalid port".to_string())?;

    // Bound here rather than inside GatewayServer::run so the real port is
    // known before the accept loop starts -- which is what makes port 0
    // ("pick one for me") usable from the UI.
    let listener = node
        .runtime
        .block_on(TcpListener::bind(bind))
        .map_err(|e| format!("couldn't bind {bind}: {e}"))?;
    let addr = listener.local_addr().map_err(|e| e.to_string())?;

    // Always metered: a gateway that cannot say who used what is not
    // something anyone should share a connection through.
    let task = node
        .runtime
        .spawn(GatewayServer::metered(node.ledger.clone()).serve(listener));
    *node.gateway.lock().unwrap() = Some(GatewayHandle {
        addr,
        started_at: Instant::now(),
        task,
    });
    node.discovery.set_offers_gateway(true);

    state
        .log
        .push("info", format!("gateway sharing started on {addr}; now announcing [gateway]"));
    Ok(addr.to_string())
}

#[tauri::command]
fn stop_gateway(state: State<AppState>) -> Result<(), String> {
    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;
    let handle = node.gateway.lock().unwrap().take();
    match handle {
        Some(gw) => {
            gw.task.abort();
            node.discovery.set_offers_gateway(false);
            state.log.push("warn", format!("gateway sharing on {} stopped", gw.addr));
            Ok(())
        }
        None => Err("gateway sharing isn't running".into()),
    }
}

// ---------------------------------------------------------------------
// Gateway: who used how much
// ---------------------------------------------------------------------

/// Per-device usage against this gateway. The whole point of metering:
/// shared bandwidth you can actually account for.
#[tauri::command]
fn list_usage(state: State<AppState>) -> Result<Vec<UsageView>, String> {
    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;
    let names: HashMap<[u8; 32], String> = node
        .discovery
        .peers()
        .into_iter()
        .map(|p| (p.device_id, p.display_name))
        .collect();

    Ok(node
        .ledger
        .all_device_usage()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|d| {
            let remaining = d.remaining();
            UsageView {
                device_id: gabriel_core::hex_encode(&d.device_id),
                display_name: names.get(&d.device_id).cloned(),
                consumed_bytes: d.consumed_bytes,
                granted_bytes: d.granted_bytes,
                remaining_bytes: remaining,
                percent_used: d.granted_bytes.map(|g| {
                    if g == 0 {
                        100
                    } else {
                        ((d.consumed_bytes.min(g) as f64 / g as f64) * 100.0) as u8
                    }
                }),
                sessions: d.sessions,
                last_seen_unix: d.last_seen_at,
            }
        })
        .collect())
}

#[tauri::command]
fn list_sessions(state: State<AppState>) -> Result<Vec<SessionView>, String> {
    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;
    let names: HashMap<[u8; 32], String> = node
        .discovery
        .peers()
        .into_iter()
        .map(|p| (p.device_id, p.display_name))
        .collect();

    Ok(node
        .ledger
        .recent_sessions(100)
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|s| SessionView {
            session_id: gabriel_core::hex_encode(&s.session_id),
            display_name: names.get(&s.device_id).cloned(),
            device_id: gabriel_core::hex_encode(&s.device_id),
            target: s.target,
            bytes_up: s.bytes_up,
            bytes_down: s.bytes_down,
            started_at: s.started_at,
            ended_at: s.ended_at,
            closed: s.closed,
        })
        .collect())
}

/// Gives a device an allowance. `bytes` is absolute, not an increment, so
/// setting it twice does not stack -- the second value replaces the first.
#[tauri::command]
fn grant_data(state: State<AppState>, device_id: String, bytes: u64) -> Result<(), String> {
    let id = parse_device_id(&device_id).ok_or("device id must be 64 hex characters")?;
    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;
    node.ledger.grant(&id, bytes, None).map_err(|e| e.to_string())?;
    state.log.push(
        "info",
        format!("granted {} bytes to {}", bytes, short(&device_id)),
    );
    Ok(())
}

#[tauri::command]
fn revoke_data(state: State<AppState>, device_id: String) -> Result<(), String> {
    let id = parse_device_id(&device_id).ok_or("device id must be 64 hex characters")?;
    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;
    node.ledger.revoke(&id).map_err(|e| e.to_string())?;
    state.log.push("warn", format!("revoked the grant for {}", short(&device_id)));
    Ok(())
}

// ---------------------------------------------------------------------
// Gateway: using someone else's
// ---------------------------------------------------------------------

/// `gabriel-client fetch --via`, as a form. Opens an authenticated tunnel
/// through `gateway_addr`, sends an HTTP/1.1 request down it, and shows
/// what comes back. This process never resolves or connects to the target
/// itself -- that is the whole point of the relay.
#[tauri::command]
fn gateway_fetch(
    state: State<AppState>,
    gateway_addr: String,
    host: String,
    port: u16,
    path: String,
) -> Result<FetchResult, String> {
    let gw: SocketAddr = gateway_addr
        .trim()
        .parse()
        .map_err(|_| "gateway address must look like 192.168.1.5:42425".to_string())?;
    let host = host.trim().to_string();
    if host.is_empty() {
        return Err("host can't be empty".into());
    }
    let path = if path.trim().is_empty() {
        "/".to_string()
    } else {
        path.trim().to_string()
    };

    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;
    let identity = node.identity.clone();
    let started = Instant::now();

    state
        .log
        .push("info", format!("fetching {host}:{port}{path} via gateway {gw}"));

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: Gabriel/{}\r\n\r\n",
        env!("CARGO_PKG_VERSION")
    );
    let host_for_task = host.clone();

    let bytes = node
        .runtime
        .block_on(async move {
            tokio::time::timeout(FETCH_TIMEOUT, async move {
                let mut tunnel = GatewayClient::connect_via(&identity, gw, &host_for_task, port).await?;
                tunnel.write_all(request.as_bytes()).await?;
                let mut buf = Vec::new();
                // take() rather than read_to_end, so a target that streams
                // forever can't grow this buffer without bound.
                tunnel.take(FETCH_MAX_BYTES as u64 + 1).read_to_end(&mut buf).await?;
                Ok::<Vec<u8>, anyhow::Error>(buf)
            })
            .await
            .map_err(|_| anyhow::anyhow!("timed out after {}s", FETCH_TIMEOUT.as_secs()))?
        })
        .map_err(|e: anyhow::Error| format!("{e:#}"))?;

    let elapsed_ms = started.elapsed().as_millis() as u64;
    let truncated = bytes.len() > FETCH_MAX_BYTES;
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(FETCH_MAX_BYTES)]).into_owned();

    // Split the HTTP head from the body for display. A target that isn't
    // speaking HTTP just ends up with everything in `body`, which is the
    // honest rendering of "we relayed bytes and they weren't HTTP".
    let (head, body) = match text.split_once("\r\n\r\n") {
        Some((h, b)) => (h.to_string(), b.to_string()),
        None => (String::new(), text.clone()),
    };
    let mut lines = head.lines().map(|s| s.to_string()).collect::<Vec<_>>();
    let status_line = if lines.is_empty() { String::new() } else { lines.remove(0) };

    state.log.push(
        "info",
        format!("gateway fetch returned {} bytes in {elapsed_ms}ms ({status_line})", bytes.len()),
    );

    Ok(FetchResult {
        via: gw.to_string(),
        target: format!("{host}:{port}{path}"),
        status_line,
        headers: lines,
        body,
        total_bytes: bytes.len(),
        elapsed_ms,
        truncated,
    })
}

// ---------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------

#[tauri::command]
fn identity_sign(state: State<AppState>, message: String) -> Result<String, String> {
    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;
    Ok(gabriel_core::hex_encode(&node.identity.sign(message.as_bytes())))
}

/// Verifies an Ed25519 signature against a claimed device id -- the exact
/// check discovery runs on every beacon it receives.
#[tauri::command]
fn identity_verify(public_key: String, message: String, signature: String) -> Result<bool, String> {
    let key = parse_device_id(&public_key).ok_or("device id must be 64 hex characters")?;
    let sig_bytes = parse_hex(&signature).ok_or("signature must be hex")?;
    let sig: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| "an Ed25519 signature is 64 bytes (128 hex characters)".to_string())?;
    Ok(Identity::verify(&key, message.as_bytes(), &sig))
}

// ---------------------------------------------------------------------
// Crypto agility layer
// ---------------------------------------------------------------------

#[tauri::command]
fn crypto_algorithms() -> Vec<AlgorithmInfo> {
    vec![
        AlgorithmInfo {
            id: "Ed25519".into(),
            label: "Ed25519".into(),
            post_quantum: false,
            public_key_bytes: 32,
            signature_bytes: 64,
            note: "What every device identity, discovery beacon and mesh message uses today. Fast and small, but not post-quantum secure.".into(),
        },
        AlgorithmInfo {
            id: "MlDsa44".into(),
            label: "ML-DSA-44 (FIPS 204)".into(),
            post_quantum: true,
            public_key_bytes: 1312,
            signature_bytes: 2420,
            note: "Post-quantum, via RustCrypto's pure-Rust ml-dsa. Works here, but nothing on the wire uses it yet -- migrating the wire formats onto this layer is still to do.".into(),
        },
    ]
}

#[tauri::command]
fn crypto_generate(state: State<AppState>, algorithm: String) -> Result<KeyView, String> {
    let algo = parse_algorithm(&algorithm)?;
    let key = AgileSigningKey::generate(algo);
    let public = key.public_key();
    let key_id = format!("key-{}", state.key_seq.fetch_add(1, Ordering::Relaxed) + 1);

    let view = KeyView {
        key_id: key_id.clone(),
        algorithm: algorithm.clone(),
        public_key: gabriel_core::hex_encode(&public.bytes),
        public_key_bytes: public.bytes.len(),
    };
    state.keyring.lock().unwrap().insert(key_id, key);
    state.log.push(
        "info",
        format!("generated a {algorithm} keypair ({} byte public key)", view.public_key_bytes),
    );
    Ok(view)
}

#[tauri::command]
fn crypto_list_keys(state: State<AppState>) -> Vec<KeyView> {
    let keyring = state.keyring.lock().unwrap();
    let mut out: Vec<KeyView> = keyring
        .iter()
        .map(|(id, key)| {
            let public = key.public_key();
            KeyView {
                key_id: id.clone(),
                algorithm: algorithm_name(key.algorithm()).to_string(),
                public_key: gabriel_core::hex_encode(&public.bytes),
                public_key_bytes: public.bytes.len(),
            }
        })
        .collect();
    out.sort_by(|a, b| a.key_id.cmp(&b.key_id));
    out
}

#[tauri::command]
fn crypto_delete_key(state: State<AppState>, key_id: String) {
    state.keyring.lock().unwrap().remove(&key_id);
}

#[tauri::command]
fn crypto_sign(state: State<AppState>, key_id: String, message: String) -> Result<SignView, String> {
    let keyring = state.keyring.lock().unwrap();
    let key = keyring.get(&key_id).ok_or("no such key -- generate one first")?;
    let signature = key.sign(message.as_bytes());
    let public = key.public_key();
    Ok(SignView {
        algorithm: algorithm_name(key.algorithm()).to_string(),
        public_key: gabriel_core::hex_encode(&public.bytes),
        signature_bytes: signature.bytes.len(),
        signature: gabriel_core::hex_encode(&signature.bytes),
    })
}

/// The agility layer's actual point: one call site, dispatching on the
/// algorithm tag carried by both the key and the signature. A mismatched
/// pairing fails closed rather than guessing which side to trust.
#[tauri::command]
fn crypto_verify(
    key_algorithm: String,
    public_key: String,
    message: String,
    signature_algorithm: String,
    signature: String,
) -> Result<bool, String> {
    let key_algo = parse_algorithm(&key_algorithm)?;
    let sig_algo = parse_algorithm(&signature_algorithm)?;
    let key_bytes = parse_hex(&public_key).ok_or("public key must be hex")?;
    let sig_bytes = parse_hex(&signature).ok_or("signature must be hex")?;

    Ok(crypto::verify(
        &AgilePublicKey { algorithm: key_algo, bytes: key_bytes },
        message.as_bytes(),
        &AgileSignature { algorithm: sig_algo, bytes: sig_bytes },
    ))
}

// ---------------------------------------------------------------------
// GNP packets
// ---------------------------------------------------------------------

#[tauri::command]
fn gnp_packet_types() -> Vec<String> {
    PACKET_TYPES.iter().map(|(name, _)| name.to_string()).collect()
}

/// Builds a GNP packet and shows both the decoded view and the bytes.
///
/// Honest caveat the UI repeats: `encrypted_payload` is named for what it
/// will hold once MLS lands. Nothing encrypts it today, so what goes in is
/// what comes out.
#[tauri::command]
fn gnp_build(
    state: State<AppState>,
    packet_type: String,
    destination: String,
    sequence_number: u64,
    expires_in_secs: u64,
    payload: String,
) -> Result<GnpView, String> {
    let ptype = parse_packet_type(&packet_type)?;
    let dest = parse_device_id(&destination).ok_or("destination must be 64 hex characters")?;
    let source = {
        let node = state.node.lock().unwrap();
        match node.as_ref() {
            Some(node) => node.identity.public_key(),
            None => [0u8; 32],
        }
    };

    let packet = GnpPacket::new(
        ptype,
        source,
        dest,
        sequence_number,
        now_unix() + expires_in_secs,
        payload.into_bytes(),
        [0u8; 16],
    );
    let encoded = bincode::serialize(&packet).map_err(|e| e.to_string())?;
    Ok(view_packet(&packet, &encoded))
}

#[tauri::command]
fn gnp_decode(hex: String) -> Result<GnpView, String> {
    let bytes = parse_hex(&hex).ok_or("that isn't valid hex")?;
    let packet: GnpPacket =
        bincode::deserialize(&bytes).map_err(|e| format!("not a valid GNP packet: {e}"))?;
    Ok(view_packet(&packet, &bytes))
}

// ---------------------------------------------------------------------
// Local schema
// ---------------------------------------------------------------------

#[tauri::command]
fn table_counts(state: State<AppState>) -> Result<Vec<TableCount>, String> {
    let node = state.node.lock().unwrap();
    let node = node.as_ref().ok_or("node is not running")?;
    Ok(node
        .store
        .table_counts()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|(name, rows)| TableCount {
            written_by_v01: name == "mesh_outbox",
            name,
            rows,
        })
        .collect())
}

// ---------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------

#[tauri::command]
fn event_log(state: State<AppState>) -> Vec<LogEntry> {
    state.log.entries()
}

#[tauri::command]
fn clear_log(state: State<AppState>) {
    state.log.clear();
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

const PACKET_TYPES: &[(&str, PacketType)] = &[
    ("Identity", PacketType::Identity),
    ("Discovery", PacketType::Discovery),
    ("Pairing", PacketType::Pairing),
    ("Routing", PacketType::Routing),
    ("Messaging", PacketType::Messaging),
    ("Sync", PacketType::Sync),
    ("ServiceDiscovery", PacketType::ServiceDiscovery),
    ("Capability", PacketType::Capability),
    ("Payment", PacketType::Payment),
    ("FileTransfer", PacketType::FileTransfer),
];

fn parse_packet_type(name: &str) -> Result<PacketType, String> {
    PACKET_TYPES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, t)| *t)
        .ok_or_else(|| format!("unknown packet type {name:?}"))
}

fn packet_type_name(t: PacketType) -> &'static str {
    PACKET_TYPES
        .iter()
        .find(|(_, candidate)| *candidate == t)
        .map(|(n, _)| *n)
        .unwrap_or("Unknown")
}

fn view_packet(packet: &GnpPacket, encoded: &[u8]) -> GnpView {
    GnpView {
        version: packet.version,
        packet_type: packet_type_name(packet.packet_type).to_string(),
        source_identity: gabriel_core::hex_encode(&packet.source_identity),
        destination_identity: gabriel_core::hex_encode(&packet.destination_identity),
        sequence_number: packet.sequence_number,
        expiration: packet.expiration,
        payload_utf8: String::from_utf8(packet.encrypted_payload.clone()).ok(),
        payload_bytes: packet.encrypted_payload.len(),
        authentication_tag: gabriel_core::hex_encode(&packet.authentication_tag),
        encoded_hex: gabriel_core::hex_encode(encoded),
        encoded_bytes: encoded.len(),
    }
}

fn algorithm_name(algo: AlgorithmId) -> &'static str {
    match algo {
        AlgorithmId::Ed25519 => "Ed25519",
        AlgorithmId::MlDsa44 => "MlDsa44",
    }
}

fn parse_algorithm(name: &str) -> Result<AlgorithmId, String> {
    match name {
        "Ed25519" => Ok(AlgorithmId::Ed25519),
        "MlDsa44" => Ok(AlgorithmId::MlDsa44),
        other => Err(format!("unknown algorithm {other:?}")),
    }
}

fn discovery_group() -> String {
    format!("{DISCOVERY_MULTICAST_ADDR}:{DISCOVERY_PORT}")
}

fn short(hex: &str) -> String {
    if hex.len() > 12 {
        format!("{}...", &hex[..12])
    } else {
        hex.to_string()
    }
}

fn push_history(state: &State<AppState>, direction: &str, peer: &str, text: &str, note: Option<String>) {
    state.history.lock().unwrap().push(ChatMessage {
        direction: direction.to_string(),
        peer: peer.to_string(),
        text: text.to_string(),
        ts_unix: now_unix(),
        note,
    });
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_hex(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() % 2 != 0 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

fn parse_device_id(hex: &str) -> Option<[u8; 32]> {
    parse_hex(hex)?.try_into().ok()
}

fn parse_id16(hex: &str) -> Option<[u8; 16]> {
    parse_hex(hex)?.try_into().ok()
}

// ---------------------------------------------------------------------
// Settings + startup
// ---------------------------------------------------------------------

/// Where this node's identity, database and settings live.
/// `GABRIEL_DATA_DIR` overrides it, which is how you run a second instance
/// on one machine to watch two nodes find each other.
fn data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("GABRIEL_DATA_DIR") {
        return PathBuf::from(dir);
    }
    std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("Gabriel")
}

fn default_display_name() -> String {
    std::env::var("GABRIEL_NAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "gabriel-desktop".into())
}

/// The display name survives a restart because it's written here. Failing
/// to save isn't worth failing the rename over -- the name still applies
/// to this session either way.
fn save_settings(data_dir: &Path, display_name: &str) {
    let json = serde_json::json!({ "display_name": display_name });
    let _ = std::fs::write(data_dir.join("settings.json"), json.to_string());
}

fn load_display_name(data_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(data_dir.join("settings.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&text).ok()?;
    value.get("display_name")?.as_str().map(|s| s.to_string())
}

fn start_node(display_name: String, log: Log) -> anyhow::Result<Node> {
    let data_dir = data_dir();
    std::fs::create_dir_all(&data_dir)?;

    let identity = Arc::new(Identity::load_or_create(&data_dir.join("identity.key"))?);
    let store = Arc::new(Store::open(
        data_dir
            .join("gabriel.sqlite")
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("data path is not valid UTF-8"))?,
    )?);

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

    // Open by default: turning metering on should not silently cut off
    // peers that were already using this gateway. The UI can switch to
    // requiring a grant.
    let ledger = UsageLedger::new(store.clone(), QuotaPolicy::Open);
    match ledger.close_orphaned_sessions() {
        Ok(n) if n > 0 => log.push("warn", format!("closed {n} relay session(s) left open by a previous run")),
        Err(err) => log.push("error", format!("could not reconcile old relay sessions: {err:#}")),
        _ => {}
    }

    let neighbors = NeighborTable::new();
    let (router, mut inbox_rx) = MeshRouter::new(identity.clone(), neighbors.clone(), store.clone());

    // Port 0 lets the OS pick, so two instances on one machine don't
    // collide; the real port is what discovery advertises to peers.
    let mesh_addr = runtime.block_on(router.clone().listen("0.0.0.0:0".parse()?))?;
    // spawn_retry_task calls tokio::spawn internally, so it needs to run
    // inside the runtime's context -- calling it bare panics with "there
    // is no reactor running".
    runtime.block_on(async { router.clone().spawn_retry_task() });

    let discovery = Arc::new(DiscoveryService::new(
        identity.clone(),
        display_name.clone(),
        mesh_addr.port(),
        false, // flipped on by start_gateway, once the relay actually runs
    ));
    runtime.block_on(async { discovery.clone().spawn() })?;

    log.push(
        "info",
        format!(
            "node up as \"{display_name}\" -- mesh on {mesh_addr}, announcing on {}",
            discovery_group()
        ),
    );
    log.push(
        "info",
        format!("device id {}", gabriel_core::hex_encode(&identity.public_key())),
    );

    // Keep the neighbour table in step with what discovery can see, and
    // narrate peers arriving/leaving so the log is useful on its own.
    let manual_neighbors: Arc<Mutex<HashSet<[u8; 32]>>> = Arc::new(Mutex::new(HashSet::new()));
    runtime.spawn({
        let discovery = discovery.clone();
        let neighbors = neighbors.clone();
        let log = log.clone();
        async move {
            let mut known: HashSet<[u8; 32]> = HashSet::new();
            loop {
                let peers = discovery.peers();
                let current: HashSet<[u8; 32]> = peers.iter().map(|p| p.device_id).collect();
                for peer in &peers {
                    if let Some(addr) = peer.mesh_addr() {
                        neighbors.set(peer.device_id, addr);
                    }
                    if !known.contains(&peer.device_id) {
                        let tag = if peer.offers_gateway { " [gateway]" } else { "" };
                        let routable = if peer.mesh_addr().is_some() {
                            "routable"
                        } else {
                            "discovery-only"
                        };
                        log.push(
                            "info",
                            format!(
                                "peer appeared: \"{}\"{tag} at {} ({routable})",
                                peer.display_name, peer.addr
                            ),
                        );
                    }
                }
                for gone in known.difference(&current) {
                    log.push(
                        "warn",
                        format!("peer went quiet: {}", short(&gabriel_core::hex_encode(gone))),
                    );
                }
                known = current;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    });

    // Buffer anything addressed to us until the UI polls for it.
    let inbox = Arc::new(Mutex::new(Vec::new()));
    runtime.spawn({
        let inbox = inbox.clone();
        async move {
            while let Some(msg) = inbox_rx.recv().await {
                if let Ok(mut inbox) = inbox.lock() {
                    inbox.push(InboxMessage {
                        from: gabriel_core::hex_encode(&msg.source_id),
                        text: String::from_utf8_lossy(&msg.body).into_owned(),
                        received_unix: now_unix(),
                    });
                }
            }
        }
    });

    Ok(Node {
        runtime,
        identity,
        discovery,
        router,
        neighbors,
        store,
        inbox,
        mesh_addr,
        data_dir,
        started_at: Instant::now(),
        manual_neighbors,
        gateway: Mutex::new(None),
        ledger,
    })
}

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .setup(move |app| {
            let state = app.state::<AppState>();
            let name = load_display_name(&data_dir()).unwrap_or_else(default_display_name);
            match start_node(name, state.log.clone()) {
                Ok(node) => *state.node.lock().unwrap() = Some(node),
                Err(err) => {
                    let msg = format!("{err:#}");
                    state.log.push("error", format!("node failed to start: {msg}"));
                    *state.error.lock().unwrap() = Some(msg);
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            node_status,
            set_display_name,
            restart_node,
            list_peers,
            list_neighbors,
            add_neighbor,
            remove_neighbor,
            send_message,
            broadcast_message,
            poll_inbox,
            message_history,
            clear_history,
            list_outbox,
            retry_outbox,
            prune_outbox,
            cancel_outbound,
            start_gateway,
            stop_gateway,
            gateway_fetch,
            list_usage,
            list_sessions,
            grant_data,
            revoke_data,
            identity_sign,
            identity_verify,
            crypto_algorithms,
            crypto_generate,
            crypto_list_keys,
            crypto_delete_key,
            crypto_sign,
            crypto_verify,
            gnp_packet_types,
            gnp_build,
            gnp_decode,
            table_counts,
            event_log,
            clear_log
        ])
        .run(tauri::generate_context!())
        .expect("error while running Gabriel");
}
