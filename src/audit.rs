use crate::process;
use anyhow::{Context, Result, bail};
use clap::Args;
use serde::Serialize;
use serde_json::Value;
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader},
    net::IpAddr,
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_RECORDS: u64 = 100_000;

#[derive(Args)]
pub struct Options {
    /// 查询最近多久，例如 30m、24h、7d（最长 30 天）
    #[arg(long, default_value = "24h", value_parser = parse_window)]
    pub since: u64,
    /// 最多显示多少个 IP
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..=10000))]
    pub limit: u32,
    /// 只查询一个 IP
    #[arg(long)]
    pub ip: Option<IpAddr>,
    /// 至少多少条失败/拦截记录才显示（成功登录不计入门槛）
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u64).range(1..))]
    pub min_events: u64,
    /// 输出 JSON，时间使用 Unix 秒
    #[arg(long)]
    pub json: bool,
}

fn parse_window(text: &str) -> Result<u64, String> {
    let index = text.char_indices().next_back().map(|(i, _)| i).unwrap_or(0);
    let (number, unit) = text.split_at(index);
    let multiplier = match unit {
        "m" => 60,
        "h" => 3600,
        "d" => 86400,
        _ => return Err("使用 30m、24h、7d 等格式".into()),
    };
    let seconds = number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(multiplier))
        .ok_or("无效查询时长")?;
    if seconds == 0 || seconds > 30 * 86400 {
        return Err("查询时长须大于 0 且不超过 30 天".into());
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

#[derive(Default, Serialize)]
struct Entry {
    ip: String,
    ssh_failures: u64,
    ssh_successes: u64,
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

enum Event {
    Failure,
    Success,
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
        } else {
            None // Invalid user/PAM messages can describe the same authentication attempt.
        };
        if let Some(kind) = kind {
            return Some((ssh_ip(message)?, kind));
        }
    }
    if field(record, "_TRANSPORT") == Some("kernel") && message.starts_with("portguard DROP ") {
        let ip = packet_field(message, "SRC=")?.parse().ok()?;
        let port = packet_field(message, "DPT=").and_then(|s| s.parse().ok());
        return Some((normalize(ip), Event::Denied(port)));
    }
    None
}

impl Summary {
    fn consume(&mut self, line: &str, cutoff: u64, current_time: u64) {
        self.scanned_records += 1;
        let parsed = serde_json::from_str::<Value>(line).ok().and_then(|record| {
            let time = field(&record, "__REALTIME_TIMESTAMP")?
                .parse::<u64>()
                .ok()?
                / 1_000_000;
            Some((record, time))
        });
        let Some((record, time)) = parsed else {
            self.malformed_records += 1;
            return;
        };
        if !(cutoff..=current_time).contains(&time) {
            return;
        }
        let Some((ip, event)) = event(&record) else {
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
            Event::Denied(port) => {
                entry.denied_packets_logged += 1;
                if let Some(port) = port {
                    entry.destination_ports.insert(port);
                }
            }
        }
    }
}

fn query(window: u64, timestamp: u64) -> Result<Summary> {
    let since = format!("{window} seconds ago");
    // Same-field matches are ORed; '+' ORs the SSH group with kernel messages.
    let mut command = Command::new("journalctl");
    command.args([
        "--no-pager",
        "--quiet",
        "--all",
        "--output=json",
        "--since",
        &since,
        "--lines=100000",
        "SYSLOG_IDENTIFIER=sshd",
        "SYSLOG_IDENTIFIER=sshd-session",
        "+",
        "_TRANSPORT=kernel",
    ]);
    let cutoff = timestamp.saturating_sub(window);
    let (status, summary, errors) =
        process::run(&mut command, "", Duration::from_secs(30), move |stdout| {
            let mut summary = Summary::default();
            for line in BufReader::new(stdout).lines() {
                let line = line?;
                if !line.trim().is_empty() {
                    summary.consume(&line, cutoff, timestamp);
                }
            }
            Ok(summary)
        })
        .context("无法完成 journalctl 查询；检查日志权限，超时请缩短 --since")?;
    if !status.success() {
        bail!("journalctl 查询失败：{}；请检查日志权限", errors.trim());
    }
    if !errors.trim().is_empty() {
        eprintln!("journalctl: {}", errors.trim());
    }
    Ok(summary)
}

fn ranked<'a>(summary: &'a Summary, options: &Options) -> Vec<&'a Entry> {
    let mut entries: Vec<_> = summary
        .entries
        .iter()
        .filter(|(ip, entry)| {
            options.ip.is_none_or(|filter| normalize(filter) == **ip)
                && entry.ssh_failures + entry.denied_packets_logged >= options.min_events
        })
        .map(|(_, entry)| entry)
        .collect();
    // Authentication failures are stronger evidence than dropped packet volume.
    entries.sort_by(|a, b| {
        let priority =
            |e: &Entry| Reverse((e.ssh_failures, e.denied_packets_logged, e.last_seen_unix));
        priority(a).cmp(&priority(b)).then_with(|| a.ip.cmp(&b.ip))
    });
    entries.truncate(options.limit as usize);
    entries
}

pub fn run(options: &Options) -> Result<()> {
    let timestamp = now();
    let summary = query(options.since, timestamp)?;
    let entries = ranked(&summary, options);
    let mut notes = vec![
        "登录失败不等于恶意攻击；拦截数是限速日志中的数据包数，不是连接数，也不是完整攻击次数。",
        "仅查询现有 journal 日志；未启用记录、日志过期或权限不足都会使结果不完整。SSH 成功登录只统计带有认证成功记录的事件。",
    ];
    if summary.scanned_records >= MAX_RECORDS {
        notes.push("已达到 100000 条日志上限，只分析该时间段最近的日志；请缩短 --since。");
    }
    if summary.malformed_records > 0 {
        notes.push("部分日志缺少时间戳或格式无效，已跳过。");
    }
    if options.json {
        let report = serde_json::json!({
            "since_unix": timestamp.saturating_sub(options.since), "until_unix": timestamp,
            "scanned_records": summary.scanned_records, "malformed_records": summary.malformed_records,
            "truncated": summary.scanned_records >= MAX_RECORDS, "entries": entries, "notes": notes,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!(
        "最近 {} 小时的 IP 记录（按 SSH 失败次数优先排序）",
        options.since as f64 / 3600.0
    );
    println!("IP\tSSH失败\tSSH成功\t拦截包日志\t被访问端口\t最近记录");
    for entry in &entries {
        let ports = entry
            .destination_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "{}\t{}\t{}\t{}\t{}\t{} 秒前",
            entry.ip,
            entry.ssh_failures,
            entry.ssh_successes,
            entry.denied_packets_logged,
            if ports.is_empty() { "-" } else { &ports },
            timestamp.saturating_sub(entry.last_seen_unix)
        );
    }
    if entries.is_empty() {
        println!("没有符合条件的记录（不代表没有攻击）。");
    }
    for note in notes {
        println!("\n{note}");
    }
    println!("记录拦截来源：在 TOML 顶层设置 log_denied = true 后 apply；不会追溯过去的流量。");
    Ok(())
}

#[cfg(test)]
mod tests;
