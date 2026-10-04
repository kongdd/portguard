use crate::{
    config::{Config, Network, PortRange},
    process,
};
use anyhow::{Context, Result, bail};
use std::{collections::BTreeSet, path::Path, process::Command, time::Duration};

pub const TABLE: &str = "portguard";

pub fn render(c: &Config) -> Result<String> {
    c.validate()?;
    if !c.enabled {
        return Ok(String::new());
    }
    let mut sets = String::new();
    let mut rules = String::new();
    for (i, (_, rule)) in c.rules.iter().enumerate() {
        if !rule.enabled || rule.allows_any() {
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
            .map(|a| Network::parse(a.ip()))
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
        rules.push_str(&format!(
            "        {port_match} {}\n",
            if c.log_denied { "jump denied" } else { "drop" }
        ));
    }
    let logging = if c.log_denied {
        "    chain denied {\n        limit rate 5/second burst 10 packets log prefix \"portguard DROP \"\n        drop\n    }\n"
    } else {
        ""
    };
    Ok(format!(
        "table inet {TABLE} {{\n{sets}{logging}    chain input {{\n        type filter hook input priority -10; policy accept;\n{rules}    }}\n}}\n"
    ))
}

fn nft() -> Command {
    // Prefer PATH so tests can inject a fake nft. Root shells on Debian often omit /usr/sbin.
    if let Some(path) = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|dir| dir.join("nft"))
            .find(|candidate| candidate.is_file())
    }) {
        return Command::new(path);
    }
    Command::new(
        ["/usr/sbin/nft", "/sbin/nft"]
            .into_iter()
            .find(|path| Path::new(path).is_file())
            .unwrap_or("nft"),
    )
}
fn run(args: &[&str], input: &str) -> Result<String> {
    // No shell: configuration strings are never executed as shell commands.
    let (status, output, error) = process::run(
        nft().args(args),
        input,
        Duration::from_secs(10),
        process::read_text,
    )
    .context("无法完成 nft 操作：请检查 nftables 安装及权限")?;
    if !status.success() {
        bail!("nft 失败（检查 root/CAP_NET_ADMIN 权限）：{}", error.trim());
    }
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
