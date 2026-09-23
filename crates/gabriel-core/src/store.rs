//! Local-first data store.
//!
//! v0.1 tables, per the blueprint's "Local data model": users, devices,
//! contacts, messages, rooms, routes, network_peers, gateway_sessions,
//! sync_records. Plus `mesh_outbox`, which isn't in the original blueprint
//! table list but is the concrete on-disk piece of "store-and-forward":
//! routing's outbound queue for messages that couldn't be flooded to any
//! neighbor yet. No payments tables in v0.1 -- that module is deferred to
//! v0.3 and stays out of the schema until it's actually scheduled.
//!
//! The connection is wrapped in a `Mutex` so `Store` can be shared as
//! `Arc<Store>` across tokio tasks. rusqlite is synchronous; each call here
//! takes the lock, runs one quick query, and releases it -- never held
//! across an `.await`. That's a fine v0.1 tradeoff for the small,
//! infrequent queries this crate makes so far (a busy write-heavy future
//! version would want `spawn_blocking` or a dedicated DB task instead of a
//! shared lock, but that's not needed yet).

use std::sync::Mutex;

use rusqlite::{params, Connection, OptionalExtension};

use crate::Result;

pub struct Store {
    conn: Mutex<Connection>,
}

/// A message queued in `mesh_outbox`, waiting for a neighbor to appear.
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    pub message_id: [u8; 16],
    pub destination_id: [u8; 32],
    pub body: Vec<u8>,
    pub created_at: i64,
    pub expires_at: i64,
    pub attempts: i64,
}

impl Store {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        let store = Self { conn: Mutex::new(conn) };
        store.migrate()?;
        Ok(store)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn: Mutex::new(conn) };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.lock().unwrap().execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id),
                public_key BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS contacts (
                id TEXT PRIMARY KEY,
                owner_user_id TEXT NOT NULL REFERENCES users(id),
                contact_user_id TEXT NOT NULL,
                added_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS rooms (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                room_id TEXT NOT NULL REFERENCES rooms(id),
                sender_device_id TEXT NOT NULL REFERENCES devices(id),
                encrypted_body BLOB NOT NULL,
                sequence_number INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                delivered INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS routes (
                id TEXT PRIMARY KEY,
                peer_device_id TEXT NOT NULL,
                path_type TEXT NOT NULL,
                score REAL NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS network_peers (
                id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                last_seen_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS gateway_sessions (
                id TEXT PRIMARY KEY,
                gateway_peer_id TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                ended_at INTEGER
            );

            CREATE TABLE IF NOT EXISTS sync_records (
                id TEXT PRIMARY KEY,
                table_name TEXT NOT NULL,
                row_id TEXT NOT NULL,
                version_vector TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS gateway_usage (
                session_id BLOB PRIMARY KEY,
                device_id BLOB NOT NULL,
                target TEXT NOT NULL,
                bytes_up INTEGER NOT NULL,
                bytes_down INTEGER NOT NULL,
                started_at INTEGER NOT NULL,
                ended_at INTEGER,
                closed INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS gateway_usage_device
                ON gateway_usage(device_id);

            CREATE TABLE IF NOT EXISTS gateway_quotas (
                device_id BLOB PRIMARY KEY,
                granted_bytes INTEGER NOT NULL,
                granted_at INTEGER NOT NULL,
                note TEXT
            );

            CREATE TABLE IF NOT EXISTS mesh_outbox (
                message_id BLOB PRIMARY KEY,
                destination_id BLOB NOT NULL,
                body BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_attempt_at INTEGER
            );
            "#,
        )?;
        Ok(())
    }

    /// Queues a message for later delivery. `INSERT OR REPLACE` so calling
    /// this twice for the same `message_id` (shouldn't happen in practice,
    /// message ids are random) just overwrites rather than erroring.
    pub fn enqueue_outbound(
        &self,
        message_id: &[u8; 16],
        destination_id: &[u8; 32],
        body: &[u8],
        created_at: i64,
        expires_at: i64,
    ) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT OR REPLACE INTO mesh_outbox
                (message_id, destination_id, body, created_at, expires_at, attempts, last_attempt_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, NULL)",
            params![&message_id[..], &destination_id[..], body, created_at, expires_at],
        )?;
        Ok(())
    }

    /// Everything currently queued, oldest first (so retries are roughly
    /// FIFO rather than favoring whatever was enqueued most recently).
    pub fn list_pending_outbound(&self) -> Result<Vec<OutboundMessage>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT message_id, destination_id, body, created_at, expires_at, attempts
             FROM mesh_outbox ORDER BY created_at ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let message_id: Vec<u8> = row.get(0)?;
            let destination_id: Vec<u8> = row.get(1)?;
            Ok(OutboundMessage {
                message_id: to_array16(message_id),
                destination_id: to_array32(destination_id),
                body: row.get(2)?,
                created_at: row.get(3)?,
                expires_at: row.get(4)?,
                attempts: row.get(5)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Removes a message from the queue -- called once it's actually been
    /// handed to at least one neighbor.
    pub fn remove_outbound(&self, message_id: &[u8; 16]) -> Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM mesh_outbox WHERE message_id = ?1", params![&message_id[..]])?;
        Ok(())
    }

    /// Bumps the attempt counter after a retry that still found no
    /// neighbors to flood to.
    pub fn record_attempt(&self, message_id: &[u8; 16], attempted_at: i64) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "UPDATE mesh_outbox SET attempts = attempts + 1, last_attempt_at = ?2 WHERE message_id = ?1",
            params![&message_id[..], attempted_at],
        )?;
        Ok(())
    }

    /// Drops anything past its `expires_at`. Returns how many rows were
    /// removed, so callers can log when messages actually get given up on.
    pub fn prune_expired_outbound(&self, now: i64) -> Result<usize> {
        let removed = self
            .conn
            .lock()
            .unwrap()
            .execute("DELETE FROM mesh_outbox WHERE expires_at < ?1", params![now])?;
        Ok(removed)
    }

    /// Row counts for every table in the local schema, name-ordered.
    ///
    /// The blueprint lists the local data model as a first-class piece of
    /// the platform, but most of those tables have no write path yet (only
    /// `mesh_outbox` does). The desktop client shows these counts rather
    /// than pretending the empty ones are features -- an empty `contacts`
    /// table is honest information about where the build actually is.
    pub fn table_counts(&self) -> Result<Vec<(String, i64)>> {
        let conn = self.conn.lock().unwrap();
        let names: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT name FROM sqlite_master WHERE type = 'table'
                   AND name NOT LIKE 'sqlite_%' ORDER BY name",
            )?;
            let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };

        let mut out = Vec::with_capacity(names.len());
        for name in names {
            // A table name can't be bound as a query parameter. These come
            // from sqlite_master rather than from a caller, so they aren't
            // attacker-controlled, but they're still quoted rather than
            // interpolated bare.
            let sql = format!("SELECT COUNT(*) FROM \"{name}\"");
            let count: i64 = conn.query_row(&sql, [], |row| row.get(0))?;
            out.push((name, count));
        }
        Ok(out)
    }

    // -----------------------------------------------------------------
    // Gateway metering
    // -----------------------------------------------------------------

    /// Inserts or updates one relay session's accounting. Keyed on
    /// `session_id`, so the periodic checkpoint and the final close write
    /// to the same row rather than accumulating duplicates.
    pub fn upsert_usage(&self, record: &crate::metering::UsageRecord) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO gateway_usage
                (session_id, device_id, target, bytes_up, bytes_down, started_at, ended_at, closed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(session_id) DO UPDATE SET
                bytes_up = excluded.bytes_up,
                bytes_down = excluded.bytes_down,
                ended_at = excluded.ended_at,
                closed = excluded.closed",
            params![
                &record.session_id[..],
                &record.device_id[..],
                record.target,
                record.bytes_up as i64,
                record.bytes_down as i64,
                record.started_at,
                record.ended_at,
                record.closed as i64,
            ],
        )?;
        Ok(())
    }

    /// What one device has been granted and has used. Returns a zeroed
    /// record rather than an error for a device that has never connected,
    /// because "never seen" and "seen, used nothing" are the same answer
    /// to the question the gateway is asking.
    pub fn device_usage(&self, device_id: &[u8; 32]) -> Result<crate::metering::DeviceUsage> {
        let conn = self.conn.lock().unwrap();

        let granted: Option<i64> = conn
            .query_row(
                "SELECT granted_bytes FROM gateway_quotas WHERE device_id = ?1",
                params![&device_id[..]],
                |row| row.get(0),
            )
            .optional()?;

        let (consumed, sessions, last_seen): (i64, i64, Option<i64>) = conn.query_row(
            "SELECT COALESCE(SUM(bytes_up + bytes_down), 0), COUNT(*), MAX(started_at)
             FROM gateway_usage WHERE device_id = ?1",
            params![&device_id[..]],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;

        Ok(crate::metering::DeviceUsage {
            device_id: *device_id,
            granted_bytes: granted.map(|g| g.max(0) as u64),
            consumed_bytes: consumed.max(0) as u64,
            sessions: sessions.max(0) as u64,
            last_seen_at: last_seen,
        })
    }

    /// Every device that has either used the gateway or been granted an
    /// allowance, heaviest user first. A device with a grant it has never
    /// touched still appears, which is what makes the list usable for
    /// managing grants rather than only for reviewing traffic.
    pub fn all_device_usage(&self) -> Result<Vec<crate::metering::DeviceUsage>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT d.device_id,
                    q.granted_bytes,
                    COALESCE(u.consumed, 0),
                    COALESCE(u.sessions, 0),
                    u.last_seen
             FROM (SELECT device_id FROM gateway_usage
                   UNION SELECT device_id FROM gateway_quotas) AS d
             LEFT JOIN gateway_quotas q ON q.device_id = d.device_id
             LEFT JOIN (SELECT device_id,
                               SUM(bytes_up + bytes_down) AS consumed,
                               COUNT(*) AS sessions,
                               MAX(started_at) AS last_seen
                        FROM gateway_usage GROUP BY device_id) AS u
                    ON u.device_id = d.device_id
             ORDER BY COALESCE(u.consumed, 0) DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let device_id: Vec<u8> = row.get(0)?;
            let granted: Option<i64> = row.get(1)?;
            let consumed: i64 = row.get(2)?;
            let sessions: i64 = row.get(3)?;
            Ok(crate::metering::DeviceUsage {
                device_id: to_array32(device_id),
                granted_bytes: granted.map(|g| g.max(0) as u64),
                consumed_bytes: consumed.max(0) as u64,
                sessions: sessions.max(0) as u64,
                last_seen_at: row.get(4)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Most recent sessions first.
    pub fn recent_usage(&self, limit: usize) -> Result<Vec<crate::metering::UsageRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT session_id, device_id, target, bytes_up, bytes_down, started_at, ended_at, closed
             FROM gateway_usage ORDER BY started_at DESC, rowid DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            let session_id: Vec<u8> = row.get(0)?;
            let device_id: Vec<u8> = row.get(1)?;
            let bytes_up: i64 = row.get(3)?;
            let bytes_down: i64 = row.get(4)?;
            let closed: i64 = row.get(7)?;
            Ok(crate::metering::UsageRecord {
                session_id: to_array16(session_id),
                device_id: to_array32(device_id),
                target: row.get(2)?,
                bytes_up: bytes_up.max(0) as u64,
                bytes_down: bytes_down.max(0) as u64,
                started_at: row.get(5)?,
                ended_at: row.get(6)?,
                closed: closed != 0,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn set_grant(&self, device_id: &[u8; 32], bytes: u64, granted_at: i64, note: Option<&str>) -> Result<()> {
        self.conn.lock().unwrap().execute(
            "INSERT INTO gateway_quotas (device_id, granted_bytes, granted_at, note)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(device_id) DO UPDATE SET
                granted_bytes = excluded.granted_bytes,
                granted_at = excluded.granted_at,
                note = excluded.note",
            params![&device_id[..], bytes as i64, granted_at, note],
        )?;
        Ok(())
    }

    pub fn clear_grant(&self, device_id: &[u8; 32]) -> Result<()> {
        self.conn
            .lock()
            .unwrap()
            .execute("DELETE FROM gateway_quotas WHERE device_id = ?1", params![&device_id[..]])?;
        Ok(())
    }

    /// Closes any session left open by a crash. Their byte counts are
    /// whatever the last checkpoint wrote, which is why the checkpoint
    /// interval bounds how much accounting a crash can lose.
    pub fn close_open_usage(&self, ended_at: i64) -> Result<usize> {
        let closed = self.conn.lock().unwrap().execute(
            "UPDATE gateway_usage SET closed = 1, ended_at = COALESCE(ended_at, ?1) WHERE closed = 0",
            params![ended_at],
        )?;
        Ok(closed)
    }
}

fn to_array16(bytes: Vec<u8>) -> [u8; 16] {
    bytes.try_into().unwrap_or([0u8; 16])
}

fn to_array32(bytes: Vec<u8>) -> [u8; 32] {
    bytes.try_into().unwrap_or([0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrates_in_memory_store() {
        let store = Store::open_in_memory();
        assert!(store.is_ok());
    }

    #[test]
    fn outbox_round_trip() {
        let store = Store::open_in_memory().unwrap();
        let message_id = [7u8; 16];
        let destination_id = [9u8; 32];
        store.enqueue_outbound(&message_id, &destination_id, b"hi", 1000, 2000).unwrap();

        let pending = store.list_pending_outbound().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].message_id, message_id);
        assert_eq!(pending[0].destination_id, destination_id);
        assert_eq!(pending[0].body, b"hi");
        assert_eq!(pending[0].attempts, 0);

        store.record_attempt(&message_id, 1500).unwrap();
        let pending = store.list_pending_outbound().unwrap();
        assert_eq!(pending[0].attempts, 1);

        store.remove_outbound(&message_id).unwrap();
        assert!(store.list_pending_outbound().unwrap().is_empty());
    }

    #[test]
    fn prune_expired_outbound_removes_only_past_expiry() {
        let store = Store::open_in_memory().unwrap();
        store.enqueue_outbound(&[1u8; 16], &[0u8; 32], b"old", 100, 500).unwrap();
        store.enqueue_outbound(&[2u8; 16], &[0u8; 32], b"fresh", 100, 5000).unwrap();

        let removed = store.prune_expired_outbound(1000).unwrap();
        assert_eq!(removed, 1);

        let remaining = store.list_pending_outbound().unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].body, b"fresh");
    }

    /// Proves this actually persists across restarts, not just within one
    /// `Store` instance's lifetime -- opens a file-backed store, enqueues,
    /// drops it (closing the connection), then reopens the *same file* as
    /// a fresh `Store` and confirms the message is still there.
    #[test]
    fn outbox_survives_reopening_the_database_file() {
        let path = std::env::temp_dir().join(format!("gabriel-outbox-test-{}.sqlite", std::process::id()));
        let path_str = path.to_str().unwrap();

        {
            let store = Store::open(path_str).unwrap();
            store.enqueue_outbound(&[3u8; 16], &[4u8; 32], b"still here after restart", 100, 999_999_999).unwrap();
        } // store (and its Connection) dropped here -- simulates a process exit

        {
            let store = Store::open(path_str).unwrap();
            let pending = store.list_pending_outbound().unwrap();
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].body, b"still here after restart");
        }

        let _ = std::fs::remove_file(&path);
    }
    /// The Storage screen reads this directly, so it has to name every
    /// table the migration creates and count rows that actually exist.
    #[test]
    fn table_counts_covers_the_schema_and_tracks_writes() {
        let store = Store::open_in_memory().unwrap();
        let counts = store.table_counts().unwrap();

        let names: Vec<&str> = counts.iter().map(|(n, _)| n.as_str()).collect();
        for expected in [
            "contacts", "devices", "gateway_sessions", "mesh_outbox", "messages",
            "network_peers", "rooms", "routes", "sync_records", "users",
        ] {
            assert!(names.contains(&expected), "table_counts is missing {expected}: {names:?}");
        }
        assert!(counts.iter().all(|(_, rows)| *rows == 0), "a fresh store should be empty");

        store.enqueue_outbound(&[5u8; 16], &[6u8; 32], b"queued", 100, 999_999).unwrap();
        let counts = store.table_counts().unwrap();
        let outbox = counts.iter().find(|(n, _)| n == "mesh_outbox").unwrap();
        assert_eq!(outbox.1, 1, "the count should follow a real write");
    }

}
