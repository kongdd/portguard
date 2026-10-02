use crate::{geoip, process};
use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use serde::Serialize;
use serde_json::Value;
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader},
    net::IpAddr,
    path::PathBuf,
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

mod index;

const QUERY_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Args)]
pub struct Options {
    /// 查询最近多久，例如 30m、24h、7d、1y（最长 1 年，按 365 天计算）
    #[arg(long, default_value = "24h", value_parser = parse_window)]
    pub since: u64,
    /// 最多显示多少个 IP
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..=10000))]
    pub limit: u32,
    /// 只查询一个 IP
    #[arg(long)]
    pub ip: Option<IpAddr>,
    /// 至少多少条失败/异常连接/拦截日志才显示（0 可显示仅成功登录的 IP）
    #[arg(long, default_value_t = 1)]
    pub min_events: u64,
    /// 输出 JSON，时间使用 Unix 秒
    #[arg(long, global = true)]
    pub json: bool,
    /// 不联网查询 IP 属地（Address 显示 -）
    #[arg(long, global = true)]
    pub no_geo: bool,
    /// 属地缓存文件（默认 root 使用 /var/cache/portguard/geoip.json）
    #[arg(long, global = true)]
    pub geo_cache: Option<PathBuf>,
    /// 不使用持久化索引，直接解析 journal
    #[arg(long, global = true)]
    pub no_index: bool,
    /// 索引数据库路径（默认 root 使用 /var/cache/portguard/audit.sqlite3）
    #[arg(long, global = true)]
    pub index_path: Option<PathBuf>,
    /// 按列名排序（小写）：ip/address/fail/ok/invalid/closed/reset/last
    #[arg(long, global = true, default_value = "fail")]
    pub sort: String,
    #[command(subcommand)]
    pub action: Option<IndexAction>,
}

#[derive(Subcommand)]
pub enum IndexAction {
    /// 预解析 journal 并建立/更新索引，不查询属地、不改变防火墙
    Index {
        /// 预解析的历史范围（最长 365 天）
        #[arg(long, default_value = "1y", value_parser = parse_window)]
        since: u64,
        /// 清空旧索引后重新解析当前 journal
        #[arg(long)]
        rebuild: bool,
    },
}

fn parse_window(text: &str) -> Result<u64, String> {
    let index = text.char_indices().next_back().map(|(i, _)| i).unwrap_or(0);
    let (number, unit) = text.split_at(index);
    let multiplier = match unit {
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        "y" => 365 * 86400,
        _ => return Err("使用 30m、24h、7d、1y 等格式".into()),
    };
    let seconds = number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .ok_or("无效查询时长")?;
    if seconds == 0 || seconds > 365 * 86400 {
        return Err("查询时长须大于 0 且不超过 1 年（365 天）".into());
    }
    Ok(seconds)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn normalize(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(a) => a.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        _ => ip,
    }
}

#[derive(Clone, Default, Serialize)]
struct Entry {
    ip: String,
    address: String,
    ssh_failures: u64,
    ssh_successes: u64,
    ssh_invalid_users: u64,
    ssh_connection_closed: u64,
    ssh_connection_reset: u64,
    denied_packets_logged: u64,
    destination_ports: BTreeSet<u16>,
    first_seen_unix: u64,
    last_seen_unix: u64,
}
#[derive(Default)]
struct Summary {
    entries: BTreeMap<IpAddr, Entry>,
    scanned_records: u64,
    malformed_records: u64,
}

#[derive(Clone, Copy)]
enum Event {
    Failure,
    Success,
    InvalidUser,
    ConnectionClosed,
    ConnectionReset,
    Denied(Option<u16>),
}

fn field<'a>(record: &'a Value, name: &str) -> Option<&'a str> {
    record.get(name)?.as_str()
}

fn packet_field<'a>(message: &'a str, prefix: &str) -> Option<&'a str> {
    message
        .split_whitespace()
        .find_map(|word| word.strip_prefix(prefix))
}

fn ssh_ip(message: &str) -> Option<IpAddr> {
    // Parse the server-generated suffix rather than a user-controlled username.
    let (_, suffix) = message.rsplit_once(" from ")?;
    let mut words = suffix.split_whitespace();
    let ip = words.next()?.parse().ok()?;
    if words.next()? != "port" {
        return None;
    }
    let _: u16 = words.next()?.parse().ok()?;
    Some(normalize(ip))
}

fn connection_ip(message: &str) -> Option<IpAddr> {
    // The peer IP is the last word before the server-generated port suffix.
    // Usernames may contain spaces or pretend to contain another IP.
    let (prefix, suffix) = message.rsplit_once(" port ")?;
    let _: u16 = suffix.split_whitespace().next()?.parse().ok()?;
    Some(normalize(
        prefix.split_whitespace().next_back()?.parse().ok()?,
    ))
}

fn event(record: &Value) -> Option<(IpAddr, Event)> {
    let message = field(record, "MESSAGE")?;
    if matches!(
        field(record, "SYSLOG_IDENTIFIER"),
        Some("sshd" | "sshd-session")
    ) {
        let kind = if message.starts_with("Failed ") {
            Some(Event::Failure)
        } else if message.starts_with("Accepted ") {
            Some(Event::Success)
        } else if message.starts_with("Invalid user ") {
            Some(Event::InvalidUser)
        } else {
            None // PAM messages can describe the same authentication attempt.
        };
        if let Some(kind) = kind {
            return Some((ssh_ip(message)?, kind));
        }
        let connection = if message.starts_with("Connection closed by ") {
            Some(Event::ConnectionClosed)
        } else if message.starts_with("Connection reset by ") {
            Some(Event::ConnectionReset)
        } else {
            None
        };
        if let Some(kind) = connection {
            return Some((connection_ip(message)?, kind));
        }
    }
    if field(record, "_TRANSPORT") == Some("kernel") && message.starts_with("portguard DROP ") {
        let ip = packet_field(message, "SRC=")?.parse().ok()?;
        let port = packet_field(message, "DPT=").and_then(|s| s.parse().ok());
        return Some((normalize(ip), Event::Denied(port)));
    }
    None
}

struct ParsedRecord {
    time: u64,
    cursor: Option<String>,
    event: Option<(IpAddr, Event)>,
}

fn parse_record(line: &str) -> Option<ParsedRecord> {
    let record: Value = serde_json::from_str(line).ok()?;
    let time = field(&record, "__REALTIME_TIMESTAMP")?
        .parse::<u64>()
        .ok()?
        / 1_000_000;
    Some(ParsedRecord {
        time,
        cursor: field(&record, "__CURSOR")
            .filter(|s| !s.is_empty())
            .map(str::to_owned),
        event: event(&record),
    })
}

impl Summary {
    fn consume(&mut self, line: &str, cutoff: u64, current_time: u64) {
        self.scanned_records += 1;
        let Some(record) = parse_record(line) else {
            self.malformed_records += 1;
            return;
        };
        if !(cutoff..=current_time).contains(&record.time) {
            return;
        }
        let time = record.time;
        let Some((ip, event)) = record.event else {
            return;
        };
        let entry = self.entries.entry(ip).or_insert_with(|| Entry {
            ip: ip.to_string(),
            first_seen_unix: time,
            ..Entry::default()
        });
        entry.first_seen_unix = entry.first_seen_unix.min(time);
        entry.last_seen_unix = entry.last_seen_unix.max(time);
        match event {
            Event::Failure => entry.ssh_failures += 1,
            Event::Success => entry.ssh_successes += 1,
            Event::InvalidUser => entry.ssh_invalid_users += 1,
            Event::ConnectionClosed => entry.ssh_connection_closed += 1,
            Event::ConnectionReset => entry.ssh_connection_reset += 1,
            Event::Denied(port) => {
                entry.denied_packets_logged += 1;
                if let Some(port) = port {
                    entry.destination_ports.insert(port);
                }
            }
        }
    }
}

fn journal_command(start: u64, end: u64) -> Command {
    let since = format!("@{start}");
    let until = format!("@{}", end.saturating_add(1));
    // Same-field matches are ORed; '+' ORs the SSH group with kernel messages.
    let mut command = Command::new("journalctl");
    command.args([
        "--no-pager",
        "--quiet",
        "--all",
        "--output=json",
        // Stream the entire fixed window. --limit only limits displayed IPs;
        // limiting journal rows would make different windows incomparable.
        "--no-tail",
        "--reverse",
        "--since",
        &since,
        "--until",
        &until,
        "SYSLOG_IDENTIFIER=sshd",
        "SYSLOG_IDENTIFIER=sshd-session",
        "+",
        "_TRANSPORT=kernel",
    ]);
    command
}

fn query_journal(window: u64, timestamp: u64) -> Result<Summary> {
    let cutoff = timestamp.saturating_sub(window);
    let mut command = journal_command(cutoff, timestamp);
    let (status, summary, errors) = process::run(&mut command, "", QUERY_TIMEOUT, move |stdout| {
        let mut summary = Summary::default();
        for line in BufReader::new(stdout).lines() {
            let line = line?;
            if !line.trim().is_empty() {
                summary.consume(&line, cutoff, timestamp);
            }
        }
        Ok(summary)
    })
    .context(
        "无法完成 journalctl 全量查询；检查日志权限，超过 300 秒请缩短 --since；未输出部分统计",
    )?;
    if !status.success() {
        bail!("journalctl 查询失败：{}；请检查日志权限", errors.trim());
    }
    if !errors.trim().is_empty() {
        eprintln!("journalctl: {}", errors.trim());
    }
    Ok(summary)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Column {
    Ip,
    Address,
    Fail,
    Ok,
    Invalid,
    Closed,
    Reset,
    Last,
}

fn parse_column(text: &str) -> Result<Column, String> {
    match text {
        "ip" => Ok(Column::Ip),
        "address" => Ok(Column::Address),
        "fail" => Ok(Column::Fail),
        "ok" => Ok(Column::Ok),
        "invalid" => Ok(Column::Invalid),
        "closed" => Ok(Column::Closed),
        "reset" => Ok(Column::Reset),
        "last" => Ok(Column::Last),
        _ => Err("--sort 支持 ip/address/fail/ok/invalid/closed/reset/last（小写）".into()),
    }
}

fn ranked<'a>(summary: &'a Summary, options: &Options) -> Result<Vec<&'a Entry>> {
    let column = parse_column(&options.sort).map_err(anyhow::Error::msg)?;
    let mut entries: Vec<_> = summary
        .entries
        .iter()
        .filter(|(ip, entry)| {
            options.ip.is_none_or(|filter| normalize(filter) == **ip)
                && entry.ssh_failures
                    + entry.ssh_invalid_users
                    + entry.ssh_connection_closed
                    + entry.ssh_connection_reset
                    + entry.denied_packets_logged
                    >= options.min_events
        })
        .map(|(_, entry)| entry)
        .collect();
    // Reverse every count column so the user-facing order stays "most first".
    entries.sort_by(|a, b| {
        let key = |entry: &Entry| {
            Reverse(match column {
                Column::Ip | Column::Address => (0, 0),
                Column::Fail => (entry.ssh_failures, 0),
                Column::Ok => (entry.ssh_successes, 0),
                Column::Invalid => (entry.ssh_invalid_users, 0),
                Column::Closed => (entry.ssh_connection_closed, 0),
                Column::Reset => (entry.ssh_connection_reset, 0),
                Column::Last => (entry.last_seen_unix, 0),
            })
        };
        let mut order = if column == Column::Ip {
            // Entries originate from parsed IPs. Compare addresses rather than
            // their text so .10 precedes .2 in descending numeric order.
            b.ip.parse::<IpAddr>()
                .expect("entry IP is valid")
                .cmp(&a.ip.parse::<IpAddr>().expect("entry IP is valid"))
        } else {
            key(a).cmp(&key(b))
        };
        if order.is_eq() {
            // Preserve historical evidence priority for `--sort fail`; otherwise tie-break by IP.
            order = if column == Column::Fail {
                let priority = |e: &Entry| {
                    Reverse((
                        e.ssh_failures,
                        e.ssh_invalid_users,
                        e.ssh_connection_closed + e.ssh_connection_reset,
                        e.last_seen_unix,
                    ))
                };
                priority(a).cmp(&priority(b)).then_with(|| a.ip.cmp(&b.ip))
            } else {
                a.ip.cmp(&b.ip)
            };
        }
        order
    });
    // Address is populated later; all eligible candidates are needed before
    // selecting the top addresses. Other columns can limit before geolocation.
    if column != Column::Address {
        entries.truncate(options.limit as usize);
    }
    Ok(entries)
}

fn age_parts(seconds: u64) -> (u64, &'static str) {
    let (divisor, unit) = match seconds {
        0..60 => (1, "sec"),
        60..3600 => (60, "min"),
        3600..86400 => (3600, "hour"),
        86400..2592000 => (86400, "day"),
        _ => (2592000, "mon"), // Approximate month: 30 days, not calendar months.
    };
    (seconds / divisor, unit)
}

fn short_address(text: &str) -> String {
    const MAX_WIDTH: usize = 24;
    if text.width() <= MAX_WIDTH {
        return text.to_string();
    }
    let mut result = String::new();
    let mut width = 0;
    for ch in text.chars() {
        let next = ch.width().unwrap_or(0);
        if width + next > MAX_WIDTH - 1 {
            break;
        }
        result.push(ch);
        width += next;
    }
    result.push('…');
    result
}

fn render_table(entries: &[&Entry], timestamp: u64) -> String {
    let headers = [
        "ip", "address", "fail", "ok", "invalid", "closed", "reset", "last",
    ];
    let ages: Vec<_> = entries
        .iter()
        .map(|entry| age_parts(timestamp.saturating_sub(entry.last_seen_unix)))
        .collect();
    let age_number_width = ages
        .iter()
        .map(|(number, _)| number.to_string().len())
        .max()
        .unwrap_or(1);
    let rows: Vec<[String; 8]> = entries
        .iter()
        .zip(&ages)
        .map(|(entry, (number, unit))| {
            [
                entry.ip.clone(),
                short_address(if entry.address.is_empty() {
                    "-"
                } else {
                    &entry.address
                }),
                entry.ssh_failures.to_string(),
                entry.ssh_successes.to_string(),
                entry.ssh_invalid_users.to_string(),
                entry.ssh_connection_closed.to_string(),
                entry.ssh_connection_reset.to_string(),
                format!("{number:>age_number_width$} {unit:<4}"),
            ]
        })
        .collect();
    let widths: Vec<usize> = headers
        .iter()
        .enumerate()
        .map(|(i, header)| {
            rows.iter()
                .map(|row| row[i].width())
                .chain(std::iter::once(header.width()))
                .max()
                .unwrap()
        })
        .collect();
    let render_row = |cells: Vec<&str>| {
        cells
            .iter()
            .enumerate()
            .map(|(i, cell)| {
                let padding = " ".repeat(widths[i] - cell.width());
                if i == 0 || i == 1 || i == 8 {
                    format!("{cell}{padding}")
                } else {
                    format!("{padding}{cell}")
                }
            })
            .collect::<Vec<_>>()
            .join(" | ")
    };
    let mut lines = vec![
        render_row(headers.to_vec()),
        widths
            .iter()
            .map(|width| "-".repeat(*width))
            .collect::<Vec<_>>()
            .join("-+-"),
    ];
    for row in &rows {
        lines.push(render_row(row.iter().map(String::as_str).collect()));
    }
    lines.join("\n")
}

pub fn run(options: &Options) -> Result<()> {
    let timestamp = now();
    let path = options
        .index_path
        .clone()
        .unwrap_or_else(index::default_path);
    if let Some(IndexAction::Index { since, rebuild }) = &options.action {
        if options.no_index {
            bail!("audit index 不能与 --no-index 一起使用");
        }
        let (_, status) = index::query(&path, *since, timestamp, None, *rebuild)?;
        if options.json {
            println!("{}", serde_json::to_string_pretty(&status)?);
        } else {
            println!(
                "Index ready: {} records, {} newly parsed\n{}",
                status.total_records,
                status.imported_records,
                path.display()
            );
        }
        return Ok(());
    }
    let (summary, index_status) = if options.no_index {
        (query_journal(options.since, timestamp)?, None)
    } else {
        let (summary, status) = index::query(
            &path,
            options.since,
            timestamp,
            options.ip.map(normalize),
            false,
        )?;
        (summary, Some(status))
    };
    let entries = ranked(&summary, options)?;
    let mut selected: Vec<Entry> = entries.into_iter().cloned().collect();
    if options.no_geo {
        for entry in &mut selected {
            entry.address = "-".into();
        }
    } else {
        let ips: Vec<_> = selected
            .iter()
            .filter_map(|entry| entry.ip.parse().ok())
            .collect();
        let path = options
            .geo_cache
            .clone()
            .unwrap_or_else(geoip::default_cache_path);
        let addresses = geoip::addresses(&ips, &path, timestamp);
        for entry in &mut selected {
            entry.address = entry
                .ip
                .parse()
                .ok()
                .and_then(|ip| addresses.get(&ip).cloned())
                .unwrap_or_else(|| "Unknown".into());
        }
    }
    if options.sort == "address" {
        selected.sort_by(|a, b| b.address.cmp(&a.address).then_with(|| a.ip.cmp(&b.ip)));
        selected.truncate(options.limit as usize);
    }
    let entries: Vec<_> = selected.iter().collect();
    let mut notes = vec![
        "登录失败不等于恶意攻击；拦截数是限速日志中的数据包数，不是连接数，也不是完整攻击次数。",
        "无效用户、断开、重置均单独统计日志条数；同一连接可能产生多类记录，不能相加当作独立连接或攻击次数。断开/重置也可能来自正常客户端。",
        "统计来源为 journal 及已解析的索引；未启用记录、未曾索引且已过期的日志或权限不足都会使结果不完整。SSH 成功登录只统计带有认证成功记录的事件；--min-events 0 可显示仅成功登录的 IP。",
    ];
    if !options.no_geo {
        notes.push("Address 来自 ipwho.is 的 HTTPS 查询，公网 IP 会发送给该服务；属地不代表精确位置。成功缓存 7 天、失败缓存 10 分钟，每次最多查询 32 个新 IP；超时或缺失显示 Unknown。--no-geo 可禁用联网，JSON 不受表格列宽限制。");
    }
    if summary.malformed_records > 0 {
        notes.push("部分日志缺少时间戳或格式无效，已跳过。");
    }
    if options.json {
        let report = serde_json::json!({
            "since_unix": timestamp.saturating_sub(options.since), "until_unix": timestamp,
            "scanned_records": summary.scanned_records, "malformed_records": summary.malformed_records,
            "truncated": false, "entries": entries, "notes": notes, "index": index_status, "sort": options.sort,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!(
        "最近 {} 小时的 IP 记录（按 {} 列倒序，可加 --sort 切换）",
        options.since as f64 / 3600.0,
        options.sort
    );
    println!("{}", render_table(&entries, timestamp));
    if entries.is_empty() {
        println!("没有符合条件的记录。");
    }
    if summary.malformed_records > 0 {
        eprintln!(
            "Warning: skipped {} malformed journal records.",
            summary.malformed_records
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
