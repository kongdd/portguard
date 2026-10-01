use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "yes")]
    pub enabled: bool,
    // Required, deliberately no default: the operator must specify SSH ports.
    pub protected_ports: Vec<u16>,
    pub rules: BTreeMap<String, Rule>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default = "yes")]
    pub enabled: bool,
    pub ports: Vec<String>,
    pub allow: Vec<String>,
}

fn yes() -> bool {
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn parse(s: &str) -> Result<Self> {
        let (a, b) = s.split_once('-').unwrap_or((s, s));
        let start = a.parse::<u16>().with_context(|| format!("无效端口：{s}"))?;
        let end = b.parse::<u16>().with_context(|| format!("无效端口：{s}"))?;
        if start == 0 || start > end {
            bail!("无效端口范围：{s}（须为 1–65535，起点不大于终点）");
        }
        Ok(Self { start, end })
    }
    pub fn overlaps(self, other: Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }
    pub fn contains(self, port: u16) -> bool {
        self.start <= port && port <= self.end
    }
    pub fn nft(self) -> String {
        if self.start == self.end {
            self.start.to_string()
        } else {
            format!("{}-{}", self.start, self.end)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    pub ip: IpAddr,
    pub prefix: u8,
}

impl Network {
    pub fn parse(s: &str) -> Result<Self> {
        let (address, prefix) = s.split_once('/').map_or((s, None), |(a, p)| (a, Some(p)));
        let ip: IpAddr = address
            .parse()
            .with_context(|| format!("无效 IP/CIDR：{s}"))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        let prefix = prefix
            .map(str::parse::<u8>)
            .transpose()
            .with_context(|| format!("无效 CIDR：{s}"))?
            .unwrap_or(max);
        if prefix > max {
            bail!("CIDR 前缀超出范围：{s}");
        }
        Ok(Self { ip, prefix })
    }
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self.ip, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let mask = u32::MAX.checked_shl((32 - self.prefix) as u32).unwrap_or(0);
                u32::from(a) & mask == u32::from(b) & mask
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let mask = u128::MAX
                    .checked_shl((128 - self.prefix) as u32)
                    .unwrap_or(0);
                u128::from(a) & mask == u128::from(b) & mask
            }
            _ => false,
        }
    }
    pub fn canonical(self) -> String {
        match self.ip {
            IpAddr::V4(a) => {
                let mask = u32::MAX.checked_shl((32 - self.prefix) as u32).unwrap_or(0);
                format!(
                    "{}/{}",
                    std::net::Ipv4Addr::from(u32::from(a) & mask),
                    self.prefix
                )
            }
            IpAddr::V6(a) => {
                let mask = u128::MAX
                    .checked_shl((128 - self.prefix) as u32)
                    .unwrap_or(0);
                format!(
                    "{}/{}",
                    std::net::Ipv6Addr::from(u128::from(a) & mask),
                    self.prefix
                )
            }
        }
    }
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text).context("TOML 配置无效")?;
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<()> {
        if self.protected_ports.is_empty() || self.protected_ports.contains(&0) {
            bail!("protected_ports 必须填写 VPS 实际 SSH 端口，且不能含 0");
        }
        if self.rules.len() > 256 {
            bail!("规则数不能超过 256");
        }
        let mut seen: Vec<(&str, PortRange)> = Vec::new();
        for (name, rule) in &self.rules {
            if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
                bail!("规则名称不能为空、不能含控制字符，且须不超过 128 字节");
            }
            if rule.ports.is_empty() || rule.ports.len() > 256 {
                bail!("规则 {name}：ports 须含 1–256 个端口或范围");
            }
            if rule.allow.len() > 4096 {
                bail!("规则 {name}：allow 数量不能超过 4096");
            }
            if rule.allow.iter().any(|a| a == "*") {
                if rule.allow.len() != 1 {
                    bail!("规则 {name}：'*' 不能与其他 IP 混写");
                }
            } else {
                for a in &rule.allow {
                    Network::parse(a).with_context(|| format!("规则 {name}"))?;
                }
            }
            for text in &rule.ports {
                let port = PortRange::parse(text).with_context(|| format!("规则 {name}"))?;
                // Even disabled rules and '*' are checked: enabling them later must be safe.
                for &protected in &self.protected_ports {
                    if port.contains(protected) {
                        bail!("规则 {name} 的端口 {text} 包含受保护端口 {protected}，未应用");
                    }
                }
                for (old_name, old_port) in &seen {
                    if port.overlaps(*old_port) {
                        bail!(
                            "规则 {name} 的端口 {text} 与规则 {old_name} 的 {} 重叠",
                            old_port.nft()
                        );
                    }
                }
                seen.push((name, port));
            }
        }
        Ok(())
    }
    pub fn protect_ssh_session(&self, session: Option<&str>) -> Result<()> {
        // Fourth SSH_CONNECTION field is the SSH server port, not the source port.
        if let Some(session) = session {
            let fields: Vec<_> = session.split_whitespace().collect();
            if fields.len() == 4 {
                if let Ok(port) = fields[3].parse::<u16>() {
                    if !self.protected_ports.contains(&port) {
                        bail!("当前 SSH 会话的服务器端口 {port} 未列入 protected_ports，未应用");
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(tail: &str) -> Result<Config> {
        Config::parse(&format!("protected_ports=[22]\n{tail}"))
    }
    #[test]
    fn named_rules_and_defaults() {
        let c = parse(
            "[rules.\"办公室\"]\nports=['5200-5300']\nallow=['192.0.2.19/24','2001:db8::/64']",
        )
        .unwrap();
        assert!(c.enabled);
        assert!(c.rules["办公室"].enabled);
    }
    #[test]
    fn missing_and_unknown_fields_fail() {
        assert!(Config::parse("[rules]").is_err());
        assert!(parse("typo=true\n[rules]").is_err());
        assert!(parse("[rules.a]\nports=['5202']\nallow=['*']\nextra=true").is_err());
    }
    #[test]
    fn protection_applies_to_wildcard_and_disabled() {
        for allow in ["[]", "['*']", "['192.0.2.1']"] {
            assert!(
                parse(&format!(
                    "[rules.ssh]\nenabled=false\nports=['20-30']\nallow={allow}"
                ))
                .is_err()
            );
        }
        assert!(Config::parse("protected_ports=[]\n[rules]").is_err());
    }
    #[test]
    fn overlap() {
        assert!(
            parse("[rules.a]\nports=['5200-5300']\nallow=[]\n[rules.b]\nports=['5300']\nallow=[]")
                .is_err()
        );
        assert!(parse("[rules.a]\nports=['5200','5200']\nallow=[]").is_err());
        assert!(
            parse("[rules.a]\nports=['5200-5300']\nallow=[]\n[rules.b]\nports=['5301']\nallow=[]")
                .is_ok()
        );
    }
    #[test]
    fn invalid_input() {
        for p in ["0", "65536", "90-80", "1-2-3", "*"] {
            assert!(PortRange::parse(p).is_err());
        }
        for ip in [
            "bad",
            "1.2.3.4/33",
            "::/129",
            "1.2.3.4; drop",
            "1.2.3.4/8/8",
        ] {
            assert!(Network::parse(ip).is_err());
        }
        assert!(parse("[rules.a]\nports=['5200']\nallow=['*','192.0.2.1']").is_err());
    }
    #[test]
    fn networks() {
        let n = Network::parse("192.0.2.19/24").unwrap();
        assert_eq!(n.canonical(), "192.0.2.0/24");
        assert!(n.contains("192.0.2.8".parse().unwrap()));
        assert!(!n.contains("192.0.3.8".parse().unwrap()));
        assert!(!n.contains("::ffff:192.0.2.8".parse().unwrap()));
        assert!(
            Network::parse("0.0.0.0/0")
                .unwrap()
                .contains("255.255.255.255".parse().unwrap())
        );
        assert!(
            Network::parse("::/0")
                .unwrap()
                .contains("2001:db8::1".parse().unwrap())
        );
        assert_eq!(
            Network::parse("2001:db8::f/64").unwrap().canonical(),
            "2001:db8::/64"
        );
    }
    #[test]
    fn actual_ssh_port() {
        let c = parse("[rules]").unwrap();
        assert!(
            c.protect_ssh_session(Some("1.1.1.1 50000 2.2.2.2 22"))
                .is_ok()
        );
        assert!(
            c.protect_ssh_session(Some("1.1.1.1 50000 2.2.2.2 2222"))
                .is_err()
        );
    }
}
