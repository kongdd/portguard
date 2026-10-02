use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct Database(PathBuf);
impl Database {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "portguard-index-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        Self(directory.join("audit.sqlite3"))
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(self.0.parent().unwrap());
    }
}

fn insert(conn: &Connection, cursor: &str, time: u64, event: Option<(IpAddr, Event)>) -> usize {
    let (ip, kind, port) = event_columns(event);
    conn.execute(
        "INSERT INTO audit_records(cursor,ts,ip,kind,port) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(cursor) DO NOTHING",
        params![cursor, time as i64, ip, kind, port],
    ).unwrap()
}

#[test]
fn exact_time_ip_port_filters_and_cursor_deduplication() {
    let db = Database::new();
    let conn = open(&db.0, false).unwrap();
    let ip: IpAddr = "192.0.2.1".parse().unwrap();
    let other: IpAddr = "2001:db8::1".parse().unwrap();
    insert(&conn, "old", 99, Some((ip, Event::Failure)));
    insert(&conn, "failed", 100, Some((ip, Event::Failure)));
    insert(&conn, "ok", 150, Some((ip, Event::Success)));
    insert(&conn, "invalid", 150, Some((ip, Event::InvalidUser)));
    insert(&conn, "closed", 160, Some((ip, Event::ConnectionClosed)));
    insert(&conn, "reset", 170, Some((ip, Event::ConnectionReset)));
    insert(&conn, "drop", 200, Some((ip, Event::Denied(Some(5202)))));
    insert(
        &conn,
        "drop-no-port",
        200,
        Some((other, Event::Denied(None))),
    );
    insert(&conn, "ignored", 190, None);
    insert(&conn, "future", 201, Some((ip, Event::Denied(Some(9999)))));
    assert_eq!(insert(&conn, "failed", 100, Some((ip, Event::Failure))), 0);
    let summary = summarize(&conn, 100, 200, None).unwrap();
    assert_eq!(summary.scanned_records, 8);
    assert_eq!(summary.entries.len(), 2);
    let entry = &summary.entries[&ip];
    assert_eq!(entry.ssh_failures, 1);
    assert_eq!(entry.ssh_successes, 1);
    assert_eq!(entry.ssh_invalid_users, 1);
    assert_eq!(entry.ssh_connection_closed, 1);
    assert_eq!(entry.ssh_connection_reset, 1);
    assert_eq!(entry.denied_packets_logged, 1);
    assert_eq!(entry.destination_ports, [5202].into_iter().collect());
    assert_eq!(entry.first_seen_unix, 100);
    assert_eq!(entry.last_seen_unix, 200);
    let filtered = summarize(&conn, 100, 200, Some(other)).unwrap();
    assert_eq!(filtered.scanned_records, 8);
    assert_eq!(filtered.entries.len(), 1);
    assert!(filtered.entries[&other].destination_ports.is_empty());
    assert!(summarize(&conn, 202, 300, None).unwrap().entries.is_empty());
}

#[test]
fn failed_updates_and_rebuilds_rollback_atomically() {
    let db = Database::new();
    let ip = "192.0.2.1".parse().unwrap();
    {
        let conn = open(&db.0, false).unwrap();
        insert(&conn, "original", 100, Some((ip, Event::Failure)));
        conn.execute_batch("INSERT INTO audit_coverage VALUES(1,0,100); COMMIT;")
            .unwrap();
    }
    {
        let conn = open(&db.0, false).unwrap();
        insert(&conn, "uncommitted", 101, Some((ip, Event::Success)));
        conn.execute("UPDATE audit_coverage SET until=101", [])
            .unwrap();
        // Dropping the connection after journal failure must roll back both data and coverage.
    }
    {
        let conn = open(&db.0, true).unwrap();
        insert(&conn, "failed-rebuild", 102, Some((ip, Event::Success)));
        // A failed rebuild must preserve the previously committed index too.
    }
    let conn = open(&db.0, false).unwrap();
    let summary = summarize(&conn, 0, 200, None).unwrap();
    assert_eq!(summary.scanned_records, 1);
    assert_eq!(summary.entries[&ip].ssh_failures, 1);
    assert_eq!(summary.entries[&ip].ssh_successes, 0);
    let end: i64 = conn
        .query_row("SELECT until FROM audit_coverage", [], |row| row.get(0))
        .unwrap();
    assert_eq!(end, 100);
}

#[test]
fn initialization_waits_for_wal_mode_lock() {
    let db = Database::new();
    let blocker = Connection::open(&db.0).unwrap();
    // Create a valid SQLite file with an empty, unclaimed schema, then hold
    // a reader snapshot that prevents conversion from DELETE mode to WAL.
    blocker
        .execute_batch("CREATE TABLE held(value); DROP TABLE held;")
        .unwrap();
    blocker
        .execute_batch("BEGIN; SELECT * FROM sqlite_master;")
        .unwrap();
    let path = db.0.clone();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (finished_tx, finished_rx) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        started_tx.send(()).unwrap();
        let conn = open_with_retry(&path, false, Duration::from_secs(2)).unwrap();
        conn.execute_batch("COMMIT").unwrap();
        finished_tx.send(()).unwrap();
    });
    started_rx.recv().unwrap();
    assert!(matches!(
        finished_rx.recv_timeout(Duration::from_millis(100)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    blocker.execute_batch("COMMIT").unwrap();
    worker.join().unwrap();
    finished_rx.recv().unwrap();
    let conn = open(&db.0, false).unwrap();
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
}

#[test]
fn initialization_lock_wait_is_bounded() {
    let db = Database::new();
    let blocker = Connection::open(&db.0).unwrap();
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
    let started = Instant::now();
    let error = open_with_retry(&db.0, false, Duration::from_millis(100)).unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(error.to_string().contains("锁等待超时"));
    assert_eq!(
        error
            .downcast_ref::<rusqlite::Error>()
            .unwrap()
            .sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy)
    );
    blocker.execute_batch("ROLLBACK").unwrap();
    // A timed-out attempt must not leave a transaction or lock behind.
    let conn = open(&db.0, false).unwrap();
    conn.execute_batch("COMMIT").unwrap();
}

#[test]
fn incompatible_and_unrelated_databases_are_not_silently_reused() {
    let db = Database::new();
    {
        let conn = open(&db.0, false).unwrap();
        conn.execute_batch("PRAGMA user_version=99; COMMIT;")
            .unwrap();
    }
    assert!(open(&db.0, false).is_err());
    let conn = open(&db.0, true).unwrap();
    conn.execute_batch("COMMIT").unwrap();
    drop(conn);
    {
        let conn = open(&db.0, false).unwrap();
        conn.execute("UPDATE audit_source SET identity='another-machine:0'", [])
            .unwrap();
        conn.execute_batch("COMMIT").unwrap();
    }
    assert!(open(&db.0, false).is_err());
    let conn = open(&db.0, true).unwrap();
    conn.execute_batch("COMMIT").unwrap();
    drop(conn);
    let unrelated = Database::new();
    {
        let conn = Connection::open(&unrelated.0).unwrap();
        conn.execute_batch("CREATE TABLE unrelated(value TEXT)")
            .unwrap();
    }
    assert!(open(&unrelated.0, true).is_err());
    let conn = Connection::open(&unrelated.0).unwrap();
    assert!(conn.prepare("SELECT * FROM unrelated").is_ok());
    let mode: String = conn
        .pragma_query_value(None, "journal_mode", |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
}
