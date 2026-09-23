//! C ABI over `gabriel-core`, so a non-Rust UI can drive a Gabriel node.
//!
//! The WinUI 3 client is C#, which cannot call Rust directly -- it calls
//! `extern "C"` functions in a DLL via P/Invoke. This crate is that DLL.
//!
//! **This is the one place in the project that uses `unsafe`.** Everything
//! else is safe Rust (`fuzz_support.rs` says as much, and that's still
//! true of the rest). Crossing a C ABI is inherently unsafe -- raw
//! pointers from another language, manual string lifetimes -- so the rule
//! here is to keep that surface small, obvious, and defensive:
//!
//!   - Every pointer from the caller is null-checked before use.
//!   - Every entry point catches panics. A Rust panic unwinding across an
//!     FFI boundary into the CLR is undefined behavior, so a panic becomes
//!     a null/error return instead.
//!   - Strings cross as UTF-8 C strings that Rust allocated and that the
//!     caller hands back to `gabriel_free_string`. C# never frees Rust
//!     memory itself, and Rust never frees C#'s.
//!   - Structured data (peer lists, inbox contents) crosses as JSON rather
//!     than as repr(C) structs. It costs a serialize/parse per call, which
//!     is nothing next to the UI's refresh interval, and it means adding a
//!     field never silently corrupts the other side's struct layout.
//!
//! Threading: the UI thread is synchronous, the core is async, so the node
//! owns a tokio runtime and every exported function is blocking and
//! returns promptly. Received messages accumulate in a buffer that the UI
//! drains by polling (`gabriel_take_inbox_json`), because a callback from
//! a Rust thread into managed code would need far more care than polling
//! a few times a second is worth.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use gabriel_core::discovery::DiscoveryService;
use gabriel_core::identity::Identity;
use gabriel_core::routing::{MeshRouter, NeighborTable};
use gabriel_core::store::Store;
use serde::Serialize;
use tokio::runtime::Runtime;

/// A running node: discovery + mesh router + the runtime driving them.
/// The UI holds this as an opaque pointer.
pub struct GabrielNode {
    runtime: Runtime,
    identity: Arc<Identity>,
    discovery: Arc<DiscoveryService>,
    router: Arc<MeshRouter>,
    neighbors: NeighborTable,
    /// Messages addressed to us, buffered until the UI drains them.
    inbox: Arc<Mutex<Vec<InboxMessage>>>,
}

#[derive(Serialize, Clone)]
struct InboxMessage {
    from: String,
    text: String,
    received_unix: u64,
}

#[derive(Serialize)]
struct PeerView {
    device_id: String,
    display_name: String,
    address: String,
    offers_gateway: bool,
    /// Whether this peer runs a mesh listener we could actually route to.
    /// Mirrors PeerInfo::mesh_addr being Some.
    routable: bool,
    last_seen_secs: f32,
}

// ---------------------------------------------------------------------
// Exported C ABI
// ---------------------------------------------------------------------

/// Starts a node. `data_dir` is where the identity key and outbox database
/// live; `display_name` is what other peers see. Returns null on failure.
///
/// # Safety
/// `data_dir` and `display_name` must be valid, NUL-terminated UTF-8 C
/// strings, or null.
#[no_mangle]
pub unsafe extern "C" fn gabriel_start(
    data_dir: *const c_char,
    display_name: *const c_char,
) -> *mut GabrielNode {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let data_dir = cstr_to_string(data_dir)?;
        let display_name = cstr_to_string(display_name)?;
        start_node(PathBuf::from(data_dir), display_name).ok()
    }));
    match result {
        Ok(Some(node)) => Box::into_raw(Box::new(node)),
        _ => std::ptr::null_mut(),
    }
}

/// Stops a node and frees it. The pointer must not be used afterwards.
///
/// # Safety
/// `node` must be a pointer returned by `gabriel_start` and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn gabriel_stop(node: *mut GabrielNode) {
    if node.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // Dropping the Box drops the runtime, which shuts down the
        // discovery/mesh/retry tasks with it.
        drop(Box::from_raw(node));
    }));
}

/// This device's identity, as a 64-character hex string. Caller frees with
/// `gabriel_free_string`.
///
/// # Safety
/// `node` must be a live pointer from `gabriel_start`.
#[no_mangle]
pub unsafe extern "C" fn gabriel_device_id(node: *const GabrielNode) -> *mut c_char {
    with_node(node, |node| {
        Some(gabriel_core::hex_encode(&node.identity.public_key()))
    })
}

/// The mesh port this node is listening on, or -1 on error. Useful for the
/// UI to show, and for running two nodes on one machine.
///
/// # Safety
/// `node` must be a live pointer from `gabriel_start`.
#[no_mangle]
pub unsafe extern "C" fn gabriel_neighbor_count(node: *const GabrielNode) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let node = node.as_ref()?;
        Some(node.neighbors.len() as c_int)
    }));
    match result {
        Ok(Some(count)) => count,
        _ => -1,
    }
}

/// Currently visible peers, as a JSON array. Caller frees with
/// `gabriel_free_string`.
///
/// # Safety
/// `node` must be a live pointer from `gabriel_start`.
#[no_mangle]
pub unsafe extern "C" fn gabriel_peers_json(node: *const GabrielNode) -> *mut c_char {
    with_node(node, |node| {
        let peers: Vec<PeerView> = node
            .discovery
            .peers()
            .into_iter()
            .map(|p| PeerView {
                device_id: gabriel_core::hex_encode(&p.device_id),
                address: p.addr.ip().to_string(),
                offers_gateway: p.offers_gateway,
                routable: p.mesh_addr().is_some(),
                last_seen_secs: p.last_seen.elapsed().as_secs_f32(),
                // Moved last: mesh_addr() borrows p, so taking the String
                // out of it before that call partially moves p.
                display_name: p.display_name,
            })
            .collect();
        serde_json::to_string(&peers).ok()
    })
}

/// Sends a message to `destination_hex`. Returns how many neighbors it was
/// handed to (0 means it was queued for later retry), or -1 on error.
///
/// # Safety
/// `node` must be live; `destination_hex` and `text` must be valid C
/// strings.
#[no_mangle]
pub unsafe extern "C" fn gabriel_send_message(
    node: *const GabrielNode,
    destination_hex: *const c_char,
    text: *const c_char,
) -> c_int {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let node = node.as_ref()?;
        let destination = parse_device_id(&cstr_to_string(destination_hex)?)?;
        let text = cstr_to_string(text)?;
        node.runtime
            .block_on(node.router.send(destination, text.into_bytes()))
            .ok()
            .map(|sent| sent as c_int)
    }));
    match result {
        Ok(Some(sent)) => sent,
        _ => -1,
    }
}

/// Drains messages received since the last call, as a JSON array. Caller
/// frees with `gabriel_free_string`.
///
/// # Safety
/// `node` must be a live pointer from `gabriel_start`.
#[no_mangle]
pub unsafe extern "C" fn gabriel_take_inbox_json(node: *const GabrielNode) -> *mut c_char {
    with_node(node, |node| {
        let drained: Vec<InboxMessage> = {
            let mut inbox = node.inbox.lock().ok()?;
            std::mem::take(&mut *inbox)
        };
        serde_json::to_string(&drained).ok()
    })
}

/// Frees a string returned by this library. Passing anything else is
/// undefined behavior.
///
/// # Safety
/// `ptr` must have come from one of this library's string-returning
/// functions, and must not be freed twice.
#[no_mangle]
pub unsafe extern "C" fn gabriel_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        drop(CString::from_raw(ptr));
    }));
}

// ---------------------------------------------------------------------
// Internals (safe Rust from here down, apart from the pointer reads)
// ---------------------------------------------------------------------

/// Shared shape of "read the node, produce a string, hand it to C".
unsafe fn with_node<F>(node: *const GabrielNode, f: F) -> *mut c_char
where
    F: FnOnce(&GabrielNode) -> Option<String>,
{
    let result = catch_unwind(AssertUnwindSafe(|| {
        let node = node.as_ref()?;
        let text = f(node)?;
        CString::new(text).ok()
    }));
    match result {
        Ok(Some(cstring)) => cstring.into_raw(),
        _ => std::ptr::null_mut(),
    }
}

unsafe fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_owned())
}

fn parse_device_id(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

fn start_node(data_dir: PathBuf, display_name: String) -> anyhow::Result<GabrielNode> {
    std::fs::create_dir_all(&data_dir)?;
    let identity = Arc::new(Identity::load_or_create(&data_dir.join("identity.key"))?);
    let store = Arc::new(Store::open(
        data_dir
            .join("gabriel.sqlite")
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("data_dir is not valid UTF-8"))?,
    )?);

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

    let neighbors = NeighborTable::new();
    let (router, mut inbox_rx) = MeshRouter::new(identity.clone(), neighbors.clone(), store);

    // Port 0: let the OS pick, so two UI instances on one machine don't
    // collide. The real port is then announced via discovery, which is
    // what other peers use to reach us.
    let mesh_addr = runtime.block_on(router.clone().listen("0.0.0.0:0".parse()?))?;
    // spawn_retry_task calls tokio::spawn internally, so it needs to run
    // inside the runtime's context -- calling it bare panics with "there
    // is no reactor running".
    runtime.block_on(async { router.clone().spawn_retry_task() });

    let discovery = Arc::new(DiscoveryService::new(
        identity.clone(),
        display_name,
        mesh_addr.port(),
        false, // the desktop client doesn't offer gateway sharing; gatewayd does
    ));
    runtime.block_on(async { discovery.clone().spawn() })?;

    // Keep the neighbor table in sync with what discovery sees.
    runtime.spawn({
        let discovery = discovery.clone();
        let neighbors = neighbors.clone();
        async move {
            loop {
                for peer in discovery.peers() {
                    if let Some(addr) = peer.mesh_addr() {
                        neighbors.set(peer.device_id, addr);
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
    });

    // Buffer anything addressed to us until the UI polls for it.
    let inbox = Arc::new(Mutex::new(Vec::new()));
    runtime.spawn({
        let inbox = inbox.clone();
        async move {
            while let Some(msg) = inbox_rx.recv().await {
                let received_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                if let Ok(mut inbox) = inbox.lock() {
                    inbox.push(InboxMessage {
                        from: gabriel_core::hex_encode(&msg.source_id),
                        text: String::from_utf8_lossy(&msg.body).into_owned(),
                        received_unix,
                    });
                }
            }
        }
    });

    Ok(GabrielNode {
        runtime,
        identity,
        discovery,
        router,
        neighbors,
        inbox,
    })
}
