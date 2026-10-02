//! Transactional, time/IP-indexed journal records. Cursor identity prevents replay duplicates.
use super::*;
use rusqlite::{Connection, Row, params};
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

fn u64_or_zero(row: &Row, index: usize) -> rusqlite::Result<u64> {
    let value: Option<i64> = row.get(index)?;
    Ok(value.unwrap_or(0).max(0) as u64)
}

fn u16_or_zero(row: &Row, index: usize) -> rusqlite::Result<u16> {
    let value: Option<i64> = row.get(index)?;
    Ok(value.unwrap_or(0).max(0) as u16)
}

const APPLICATION_ID: i64 = 0x50474155; // PGAU
const SCHEMA_VERSION: i64 = 1;
const RETENTION: u64 = 365 * 86400;

unsafe extern "C" {
    fn geteuid() -> u32;
}

fn source_identity() -> Result<String> {
    let machine =
        fs::read_to_string("/etc/machine-id").context("无法读取 journal 所在机器的标识")?;
    Ok(format!("{}:{}", machine.trim(), unsafe { geteuid() }))
}

#[derive(Serialize)]
pub(super) struct Status {
    pub path: PathBuf,
    pub imported_records: u64,
    pub total_records: u64,
    pub since_unix: u64,
    pub until_unix: u64,
}

pub(super) fn default_path() -> PathBuf {
    geoip::default_cache_path().with_file_name("audit.sqlite3")
}

fn validate_header(conn: &Connection, rebuild: bool) -> Result<()> {
    let application: i64 = conn.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if application != APPLICATION_ID {
        let tables: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table'",
            [],
            |r| r.get(0),
        )?;
        if application != 0 || tables != 0 {
            bail!("该数据库不是 portguard 的 audit 索引，拒绝修改");
        }
    } else if version != SCHEMA_VERSION && !rebuild {
        bail!("索引版本不兼容，请执行 audit index --rebuild");
    }
    Ok(())
}

fn open(path: &Path, rebuild: bool) -> Result<Connection> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)?;
    let conn = Connection::open(path)?;
    conn.busy_timeout(Duration::from_secs(30))?;
    // Reject unrelated databases before changing their journal mode. Recheck
    // under the writer lock in case another process initialized the file.
    validate_header(&conn, rebuild)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; BEGIN IMMEDIATE;")?;
    validate_header(&conn, rebuild)?;
    if rebuild {
        conn.execute_batch("DROP TABLE IF EXISTS audit_records; DROP TABLE IF EXISTS audit_coverage; DROP TABLE IF EXISTS audit_source;")?;
    }
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS audit_records (
            cursor TEXT PRIMARY KEY NOT NULL,
            ts INTEGER NOT NULL CHECK (ts>=0),
            ip TEXT,
            kind INTEGER CHECK (kind BETWEEN 1 AND 6),
            port INTEGER CHECK (port BETWEEN 0 AND 65535)
        );
        CREATE INDEX IF NOT EXISTS audit_time ON audit_records(ts);
        CREATE INDEX IF NOT EXISTS audit_ip_time ON audit_records(ip, ts);
        CREATE TABLE IF NOT EXISTS audit_coverage (
            id INTEGER PRIMARY KEY CHECK (id=1),
            since INTEGER NOT NULL CHECK (since>=0),
            until INTEGER NOT NULL CHECK (until>=since)
        );
        CREATE TABLE IF NOT EXISTS audit_source (
            id INTEGER PRIMARY KEY CHECK (id=1),
            identity TEXT NOT NULL
        );",
    )?;
    let identity = source_identity()?;
    conn.execute(
        "INSERT INTO audit_source(id,identity) VALUES(1,?1) ON CONFLICT(id) DO NOTHING",
        [&identity],
    )?;
    let cached_identity: String =
        conn.query_row("SELECT identity FROM audit_source WHERE id=1", [], |r| {
            r.get(0)
        })?;
    if cached_identity != identity {
        bail!(
            "索引属于其他机器或用户权限范围，请使用新的 --index-path 或执行 audit index --rebuild"
        );
    }
    conn.pragma_update(None, "application_id", APPLICATION_ID)?;
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    Ok(conn)
}

fn event_columns(event: Option<(IpAddr, Event)>) -> (Option<String>, Option<i64>, Option<u16>) {
    let Some((ip, event)) = event else {
        return (None, None, None);
    };
    let (kind, port) = match event {
        Event::Failure => (1, None),
        Event::Success => (2, None),
        Event::InvalidUser => (3, None),
        Event::ConnectionClosed => (4, None),
        Event::ConnectionReset => (5, None),
        Event::Denied(port) => (6, port),
    };
    (Some(ip.to_string()), Some(kind), port)
}

fn import(conn: Connection, start: u64, end: u64) -> Result<(Connection, u64)> {
    let mut command = journal_command(start, end);
    // Move the sole connection into the streaming reader; the transaction remains
    // uncommitted until all journalctl invocations succeed and coverage is updated.
    let (status, (conn, imported), errors) =
        process::run(&mut command, "", QUERY_TIMEOUT, move |stdout| {
            let mut imported = 0;
            {
                let mut insert = conn.prepare_cached(
                    "INSERT INTO audit_records(cursor,ts,ip,kind,port) VALUES(?1,?2,?3,?4,?5)
                 ON CONFLICT(cursor) DO NOTHING",
                )?;
                for line in BufReader::new(stdout).lines() {
                    let line = line?;
                    if line.trim().is_empty() {
                        continue;
                    }
                    let record = parse_record(&line)
                        .context("日志格式或时间戳无效，不能安全索引；可用 --no-index 直接查询")?;
                    if !(start..=end).contains(&record.time) {
                        continue;
                    }
                    let cursor = record.cursor.context(
                        "journal 日志缺少 __CURSOR，不能安全增量索引；可用 --no-index 直接查询",
                    )?;
                    let (ip, kind, port) = event_columns(record.event);
                    imported += insert.execute(params![
                        cursor,
                        i64::try_from(record.time)?,
                        ip,
                        kind,
                        port
                    ])? as u64;
                }
            }
            Ok((conn, imported))
        })
        .context("journalctl 索引解析失败或超过 300 秒，更新已回滚，未输出部分统计")?;
    if !status.success() || !errors.trim().is_empty() {
        bail!(
            "journalctl 索引更新失败，已回滚：{}；检查日志权限，或用 --no-index 直接查询",
            errors.trim()
        );
    }
    Ok((conn, imported))
}

fn summarize(conn: &Connection, start: u64, end: u64, ip: Option<IpAddr>) -> Result<Summary> {
    let (start, end) = (i64::try_from(start)?, i64::try_from(end)?);
    let mut summary = Summary::default();
    summary.scanned_records = conn.query_row(
        "SELECT COUNT(*) FROM audit_records WHERE ts BETWEEN ?1 AND ?2",
        params![start, end],
        |row| u64_or_zero(row, 0),
    )?;
    let filter = ip.map(|ip| ip.to_string());
    let condition = if filter.is_some() {
        "AND ip=?3"
    } else {
        "AND ?3 IS NULL"
    };
    let sql = format!(
        "SELECT ip, SUM(kind=1), SUM(kind=2), SUM(kind=3), SUM(kind=4), SUM(kind=5), SUM(kind=6), MIN(ts), MAX(ts)
         FROM audit_records WHERE ts BETWEEN ?1 AND ?2 AND ip IS NOT NULL {condition} GROUP BY ip"
    );
    let mut statement = conn.prepare(&sql)?;
    let mut rows = statement.query(params![start, end, filter])?;
    while let Some(row) = rows.next()? {
        let ip: String = row.get(0)?;
        let entry = Entry {
            ip: ip.clone(),
            ssh_failures: u64_or_zero(row, 1)?,
            ssh_successes: u64_or_zero(row, 2)?,
            ssh_invalid_users: u64_or_zero(row, 3)?,
            ssh_connection_closed: u64_or_zero(row, 4)?,
            ssh_connection_reset: u64_or_zero(row, 5)?,
            denied_packets_logged: u64_or_zero(row, 6)?,
            first_seen_unix: u64_or_zero(row, 7)?,
            last_seen_unix: u64_or_zero(row, 8)?,
            ..Entry::default()
        };
        summary
            .entries
            .insert(ip.parse().context("索引中的 IP 无效，请重建")?, entry);
    }
    let sql = format!(
        "SELECT DISTINCT ip,port FROM audit_records WHERE ts BETWEEN ?1 AND ?2 AND kind=6 AND port IS NOT NULL {condition}"
    );
    let mut statement = conn.prepare(&sql)?;
    let mut rows = statement.query(params![start, end, filter])?;
    while let Some(row) = rows.next()? {
        let ip: String = row.get(0)?;
        if let Some(entry) = summary.entries.get_mut(&ip.parse::<IpAddr>()?) {
            entry.destination_ports.insert(u16_or_zero(row, 1)?);
        }
    }
    Ok(summary)
}

pub(super) fn query(
    path: &Path,
    window: u64,
    timestamp: u64,
    ip: Option<IpAddr>,
    rebuild: bool,
) -> Result<(Summary, Status)> {
    let result = (|| -> Result<_> {
        let mut conn = open(path, rebuild)?;
        let cutoff = timestamp.saturating_sub(window);
        let coverage: Option<(u64, u64)> = {
            let mut rows = conn.prepare("SELECT since,until FROM audit_coverage WHERE id=1")?;
            let mut rows = rows.query([])?;
            rows.next()?
                .map(|row| -> rusqlite::Result<_> {
                    Ok((u64_or_zero(row, 0)?, u64_or_zero(row, 1)?))
                })
                .transpose()?
        };
        let mut imported = 0;
        let start = match coverage {
            Some((start, end)) if end <= timestamp => {
                if cutoff < start {
                    let (new_conn, count) = import(conn, cutoff, start.saturating_sub(1))?;
                    conn = new_conn;
                    imported += count;
                }
                // Replay boundary seconds: entries can arrive after the previous
                // snapshot in the same second. Cursor primary keys make this safe.
                // Fill the entire gap even when this request is narrower than
                // the cached coverage. Otherwise a later broad query misses it.
                let tail = end
                    .saturating_sub(1)
                    .max(timestamp.saturating_sub(RETENTION));
                let (new_conn, count) = import(conn, tail, timestamp)?;
                conn = new_conn;
                imported += count;
                start.min(cutoff)
            }
            _ => {
                // First use, rebuild, or clock rollback: refresh the full window.
                let (new_conn, count) = import(conn, cutoff, timestamp)?;
                conn = new_conn;
                imported += count;
                cutoff
            }
        };
        let floor = timestamp.saturating_sub(RETENTION);
        conn.execute(
            "DELETE FROM audit_records WHERE ts < ?1",
            [i64::try_from(floor)?],
        )?;
        conn.execute(
            "INSERT INTO audit_coverage(id,since,until) VALUES(1,?1,?2)
             ON CONFLICT(id) DO UPDATE SET since=excluded.since,until=excluded.until",
            params![i64::try_from(start.max(floor))?, i64::try_from(timestamp)?],
        )?;
        let summary = summarize(&conn, cutoff, timestamp, ip)?;
        let total_records = conn.query_row("SELECT COUNT(*) FROM audit_records", [], |row| {
            u64_or_zero(row, 0)
        })?;
        let status = Status {
            path: path.to_path_buf(),
            imported_records: imported,
            total_records,
            since_unix: start.max(floor),
            until_unix: timestamp,
        };
        conn.execute_batch("COMMIT")?;
        Ok((summary, status))
    })();
    result.with_context(|| format!("无法完成 audit 索引查询 {}；可用 --no-index 直接读取 journal，版本不兼容时用 audit index --rebuild", path.display()))
}

#[cfg(test)]
mod tests;
