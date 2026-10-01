use crate::config::{Config, Network, PortRange};
use anyhow::{Context, Result, bail};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub const TABLE: &str = "portguard";

pub fn render(c: &Config) -> Result<String> {
    c.validate()?;
    if !c.enabled {
        return Ok(String::new());
    }
    let mut sets = String::new();
    let mut rules = String::new();
    for (i, (_, rule)) in c.rules.iter().enumerate() {
        if !rule.enabled || rule.allow == ["*"] {
            continue;
        }
        let ports = rule
            .ports
            .iter()
            .map(|s| PortRange::parse(s).map(PortRange::nft))
            .collect::<Result<Vec<_>>>()?
            .join(", ");
        let port_match = format!("meta l4proto {{ tcp, udp }} th dport {{ {ports} }}");
        let networks = rule
            .allow
            .iter()
            .map(|a| Network::parse(a))
            .collect::<Result<Vec<_>>>()?;
        for version in [4, 6] {
            let elements: BTreeSet<_> = networks
                .iter()
                .filter(|n| n.ip.is_ipv4() == (version == 4))
                .map(|n| n.canonical())
                .collect();
            if elements.is_empty() {
                continue;
            }
            let name = format!("r{i}_v{version}");
            sets.push_str(&format!("    set {name} {{\n        type ipv{version}_addr\n        flags interval\n        auto-merge\n        elements = {{ {} }}\n    }}\n", elements.into_iter().collect::<Vec<_>>().join(", ")));
            rules.push_str(&format!(
                "        {port_match} {} saddr @{name} accept\n",
                if version == 4 { "ip" } else { "ip6" }
            ));
        }
        rules.push_str(&format!("        {port_match} drop\n"));
    }
    Ok(format!(
        "table inet {TABLE} {{\n{sets}    chain input {{\n        type filter hook input priority -10; policy accept;\n{rules}    }}\n}}\n"
    ))
}

fn run(args: &[&str], input: &str) -> Result<String> {
    // No shell: configuration strings are never executed as shell commands.
    let mut child = Command::new("nft")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("无法启动 nft：请安装 nftables")?;
    let mut stdin = child.stdin.take().unwrap();
    let bytes = input.as_bytes().to_vec();
    let writer = thread::spawn(move || stdin.write_all(&bytes));
    let mut stdout = child.stdout.take().unwrap();
    let output = thread::spawn(move || {
        let mut b = String::new();
        stdout.read_to_string(&mut b).map(|_| b)
    });
    let mut stderr = child.stderr.take().unwrap();
    let errors = thread::spawn(move || {
        let mut b = String::new();
        stderr.read_to_string(&mut b).map(|_| b)
    });
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break s;
        }
        if start.elapsed() >= Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("nft 操作超过 10 秒：中止；如为应用操作，下次写入命令将先恢复事务记录");
        }
        thread::sleep(Duration::from_millis(10));
    };
    let output = output
        .join()
        .map_err(|_| anyhow::anyhow!("nft 输出线程失败"))??;
    let error = errors
        .join()
        .map_err(|_| anyhow::anyhow!("nft 错误线程失败"))??;
    let written = writer
        .join()
        .map_err(|_| anyhow::anyhow!("nft 输入线程失败"))?;
    if !status.success() {
        bail!("nft 失败（检查 root/CAP_NET_ADMIN 权限）：{}", error.trim());
    }
    written?;
    Ok(output)
}

pub fn snapshot() -> Result<String> {
    let tables = run(&["list", "tables"], "")?;
    if tables
        .lines()
        .any(|l| l.trim() == format!("table inet {TABLE}"))
    {
        // Numeric output prevents reverse DNS/service-name lookup and yields restorable syntax.
        run(&["-nn", "list", "table", "inet", TABLE], "")
    } else {
        Ok(String::new())
    }
}

fn script(current: &str, body: &str) -> String {
    format!(
        "{}{body}",
        if current.is_empty() {
            String::new()
        } else {
            format!("delete table inet {TABLE}\n")
        }
    )
}

pub fn check(body: &str) -> Result<()> {
    let batch = script(&snapshot()?, body);
    if !batch.is_empty() {
        run(&["-c", "-f", "-"], &batch)?;
    }
    Ok(())
}

pub fn install(body: &str) -> Result<()> {
    let batch = script(&snapshot()?, body);
    if !batch.is_empty() {
        run(&["-c", "-f", "-"], &batch)?;
        // Delete old table and create new table in one kernel transaction, never flush ruleset.
        run(&["-f", "-"], &batch)?;
    }
    Ok(())
}

pub fn equivalent(a: &str, b: &str) -> bool {
    a.split_whitespace().eq(b.split_whitespace())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(allow: &str) -> Config {
        Config::parse(&format!(
            "protected_ports=[22]\n[rules.\"中文规则\"]\nports=['5200-5300','33890']\nallow={allow}"
        ))
        .unwrap()
    }
    #[test]
    fn dual_stack_and_both_protocols() {
        let r = render(&config("['192.0.2.1/24','192.0.2.99/24','2001:db8::/64']")).unwrap();
        assert!(r.contains("meta l4proto { tcp, udp } th dport { 5200-5300, 33890 }"));
        assert_eq!(r.matches("192.0.2.0/24").count(), 1);
        assert!(r.contains("ip6 saddr @r0_v6 accept"));
        assert!(r.contains(" drop"));
        assert!(!r.contains("中文规则"));
    }
    #[test]
    fn wildcard_and_empty_differ() {
        assert!(!render(&config("['*']")).unwrap().contains("th dport"));
        let r = render(&config("[]")).unwrap();
        assert!(r.contains(" drop"));
        assert!(!r.contains("saddr"));
    }
    #[test]
    fn atomic_table_only() {
        let s = script("old table", "new table");
        assert_eq!(s, "delete table inet portguard\nnew table");
        assert!(!s.contains("flush ruleset"));
    }
}
