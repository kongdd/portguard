use anyhow::{Context, Result, bail};
use clap::Args;
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader, Read},
    net::IpAddr,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
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
    Failure(IpAddr),
    Success(IpAddr),
    Denied(IpAddr, Option<u16>),
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

fn event(v: &Value) -> Option<Event> {
    let message = v.get("MESSAGE")?.as_str()?;
    let identifier = v
        .get("SYSLOG_IDENTIFIER")
        .and_then(Value::as_str)
        .unwrap_or("");
    if matches!(identifier, "sshd" | "sshd-session") {
        if message.starts_with("Failed ") {
            return ssh_ip(message).map(Event::Failure);
        }
        if message.starts_with("Accepted ") {
            return ssh_ip(message).map(Event::Success);
        }
        // "Invalid user" and PAM errors can describe the SAME attempt; don't count them twice.
    }
    if v.get("_TRANSPORT").and_then(Value::as_str) == Some("kernel")
        && message.starts_with("portguard DROP ")
    {
        let source = message
            .split_whitespace()
            .find_map(|w| w.strip_prefix("SRC="))?
            .parse()
            .ok()?;
        let port = message
            .split_whitespace()
            .find_map(|w| w.strip_prefix("DPT="))
            .and_then(|s| s.parse::<u16>().ok());
        return Some(Event::Denied(normalize(source), port));
    }
    None
}

impl Summary {
    fn consume(&mut self, line: &str, cutoff: u64, current_time: u64) {
        self.scanned_records += 1;
        let Ok(v) = serde_json::from_str::<Value>(line) else {
            self.malformed_records += 1;
            return;
        };
        let Some(time) = v
            .get("__REALTIME_TIMESTAMP")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok())
            .map(|t| t / 1_000_000)
        else {
            self.malformed_records += 1;
            return;
        };
        if time < cutoff || time > current_time {
            return;
        }
        let Some(e) = event(&v) else {
            return;
        };
        let ip = match e {
            Event::Failure(ip) | Event::Success(ip) | Event::Denied(ip, _) => ip,
        };
        let entry = self.entries.entry(ip).or_insert_with(|| Entry {
            ip: ip.to_string(),
            first_seen_unix: time,
            ..Entry::default()
        });
        entry.first_seen_unix = entry.first_seen_unix.min(time);
        entry.last_seen_unix = entry.last_seen_unix.max(time);
        match e {
            Event::Failure(_) => entry.ssh_failures += 1,
            Event::Success(_) => entry.ssh_successes += 1,
            Event::Denied(_, port) => {
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
    let mut child = Command::new("journalctl")
        .args([
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
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("无法运行 journalctl；audit 当前需要 systemd journal（建议 sudo）")?;
    let stdout = child.stdout.take().unwrap();
    let cutoff = timestamp.saturating_sub(window);
    let reader = thread::spawn(move || -> Result<Summary> {
        let mut summary = Summary::default();
        for line in BufReader::new(stdout).lines() {
            let line = line?;
            if !line.trim().is_empty() {
                summary.consume(&line, cutoff, timestamp);
            }
        }
        Ok(summary)
    });
    let mut stderr = child.stderr.take().unwrap();
    let errors = thread::spawn(move || {
        let mut s = String::new();
        stderr.read_to_string(&mut s).map(|_| s)
    });
    let deadline = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if deadline.elapsed() >= Duration::from_secs(30) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("日志查询超过 30 秒，请缩短 --since");
        }
        thread::sleep(Duration::from_millis(10));
    };
    let summary = reader
        .join()
        .map_err(|_| anyhow::anyhow!("日志解析线程失败"))??;
    let errors = errors
        .join()
        .map_err(|_| anyhow::anyhow!("日志错误读取线程失败"))??;
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
        b.ssh_failures
            .cmp(&a.ssh_failures)
            .then_with(|| b.denied_packets_logged.cmp(&a.denied_packets_logged))
            .then_with(|| b.last_seen_unix.cmp(&a.last_seen_unix))
            .then_with(|| a.ip.cmp(&b.ip))
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
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "since_unix": timestamp.saturating_sub(options.since), "until_unix": timestamp,
                "scanned_records": summary.scanned_records, "malformed_records": summary.malformed_records,
                "truncated": summary.scanned_records >= MAX_RECORDS, "entries": entries, "notes": notes,
            }))?
        );
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
mod tests {
    use super::*;
    fn record(message: &str, ssh: bool, time: u64) -> String {
        serde_json::json!({"MESSAGE":message,"SYSLOG_IDENTIFIER":if ssh {"sshd"} else {"kernel"},"_TRANSPORT":if ssh {"syslog"} else {"kernel"},"__REALTIME_TIMESTAMP":(time*1_000_000).to_string()}).to_string()
    }
    #[test]
    fn windows() {
        assert_eq!(parse_window("24h").unwrap(), 86400);
        for text in [
            "0h",
            "31d",
            "-1h",
            "1;echo x",
            "999999999999999999999d",
            "",
            "中文",
        ] {
            assert!(parse_window(text).is_err());
        }
    }
    #[test]
    fn failed_password_publickey_and_success() {
        let mut s = Summary::default();
        for message in [
            "Failed password for invalid user root from 192.0.2.1 port 43000 ssh2",
            "Failed publickey for root from 192.0.2.1 port 43000 ssh2",
            "Accepted publickey for root from 192.0.2.1 port 43000 ssh2",
            "Invalid user root from 192.0.2.1 port 43000",
            "pam_unix(sshd:auth): authentication failure; rhost=192.0.2.1",
        ] {
            s.consume(&record(message, true, 100), 0, 200);
        }
        let e = &s.entries[&"192.0.2.1".parse().unwrap()];
        assert_eq!(e.ssh_failures, 2);
        assert_eq!(e.ssh_successes, 1);
    }
    #[test]
    fn ipv6_kernel_and_untrusted_messages() {
        let mut s = Summary::default();
        s.consume(&record("portguard DROP IN=eth0 SRC=2001:db8::1 DST=2001:db8::2 PROTO=TCP SPT=1234 DPT=5202",false,150),0,200);
        s.consume(
            &record(
                "Failed password for root from 2001:db8::1 port 43000 ssh2",
                false,
                150,
            ),
            0,
            200,
        );
        s.consume(
            &record("portguard DROP SRC=192.0.2.1 DPT=5202", true, 150),
            0,
            200,
        );
        assert_eq!(s.entries.len(), 1);
        let e = &s.entries[&"2001:db8::1".parse().unwrap()];
        assert_eq!(e.denied_packets_logged, 1);
        assert!(e.destination_ports.contains(&5202));
        assert_eq!(e.ssh_failures, 0);
    }
    #[test]
    fn window_order_and_bad_logs() {
        let mut s = Summary::default();
        s.consume(
            &record(
                "Failed password for root from 192.0.2.1 port 1234 ssh2",
                true,
                50,
            ),
            100,
            200,
        );
        s.consume(
            &record(
                "Failed password for root from 192.0.2.1 port 1234 ssh2",
                true,
                250,
            ),
            100,
            200,
        );
        s.consume("not JSON", 100, 200);
        s.consume(
            &record(
                "Failed password for root from 192.0.2.1 port 1234 ssh2",
                true,
                180,
            ),
            100,
            200,
        );
        s.consume(
            &record(
                "Failed password for root from 192.0.2.1 port 1234 ssh2",
                true,
                110,
            ),
            100,
            200,
        );
        assert_eq!(s.entries.len(), 1);
        assert_eq!(s.malformed_records, 1);
        let e = &s.entries[&"192.0.2.1".parse().unwrap()];
        assert_eq!(e.first_seen_unix, 110);
        assert_eq!(e.last_seen_unix, 180);
    }
    #[test]
    fn username_does_not_inject_source_ip() {
        let message =
            "Failed password for invalid user bad from 1.1.1.1 from 192.0.2.1 port 1234 ssh2";
        assert_eq!(ssh_ip(message).unwrap().to_string(), "192.0.2.1");
    }
}
