//! Best-effort HTTPS IP attribution. Never infer geography from an address prefix.
use crate::{process, store};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const SUCCESS_TTL: u64 = 7 * 86400;
const FAILURE_TTL: u64 = 600;
const MAX_LOOKUPS: usize = 32;
const CACHE_FORMAT_VERSION: u8 = 1;

unsafe extern "C" {
    fn geteuid() -> u32;
}

pub fn default_cache_path() -> PathBuf {
    // Do not use a caller-controlled HOME/XDG_CACHE_HOME when running as root.
    if unsafe { geteuid() } == 0 {
        return PathBuf::from("/var/cache/portguard/geoip.json");
    }
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")));
    base.unwrap_or_else(std::env::temp_dir)
        .join("portguard/geoip.json")
}

fn local_address(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            if ip.is_loopback() {
                return Some("Loopback");
            }
            if ip.is_private() || ip.is_link_local() {
                return Some("Private");
            }
            if ip.is_documentation()
                || ip.is_multicast()
                || octets[0] == 0
                || octets[0] >= 240
                || (octets[0] == 100 && (64..128).contains(&octets[1]))
                || (octets[0] == 198 && (18..20).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
            {
                return Some("Reserved");
            }
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return local_address(v4.into());
            }
            if ip.is_loopback() {
                return Some("Loopback");
            }
            let octets = ip.octets();
            if octets[0] & 0xfe == 0xfc || (octets[0] == 0xfe && octets[1] & 0xc0 == 0x80) {
                return Some("Private");
            }
            if octets[0] & 0xe0 != 0x20 || ip.segments()[..2] == [0x2001, 0x0db8] {
                return Some("Reserved");
            }
        }
    }
    None
}

fn safe_label(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty()
        || text.chars().count() > 100
        || text.chars().any(|c| {
            c.is_control() || matches!(c, '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
    {
        return None;
    }
    // Preserve the table's column separators.
    Some(text.replace('|', "/"))
}

fn compact_address(address: &str) -> String {
    if let Some(suffix) = address.strip_prefix("新疆维吾尔自治区") {
        if suffix.is_empty() || suffix.starts_with(" / ") {
            return format!("新疆{suffix}");
        }
    }
    address.to_string()
}

fn address_from_response(response: &Value, ip: IpAddr) -> Option<String> {
    if response.get("success")?.as_bool()? != true
        || response.get("ip")?.as_str()?.parse::<IpAddr>().ok()? != ip
    {
        return None;
    }
    let country = safe_label(response.get("country")?.as_str()?)?;
    let region = response
        .get("region")
        .and_then(Value::as_str)
        .and_then(safe_label);
    let city = response
        .get("city")
        .and_then(Value::as_str)
        .and_then(safe_label);
    let domestic = response.get("country_code")?.as_str()? == "CN";
    let city = city.map(|city| {
        if domestic {
            city
        } else {
            city.chars().take(4).collect()
        }
    });
    let first = if domestic {
        region.unwrap_or(country)
    } else {
        country
    };
    let address = match city {
        Some(city) if city != first => format!("{first} / {city}"),
        _ => first,
    };
    Some(compact_address(&address))
}

fn lookup(ip: IpAddr) -> Option<String> {
    let url = format!("https://ipwho.is/{ip}?lang=zh-CN");
    let mut command = Command::new("curl");
    command.args([
        "-q",
        "--fail",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--connect-timeout",
        "1",
        "--max-time",
        "2",
        "--max-filesize",
        "65536",
        &url,
    ]);
    let (status, text, _) = process::run(&mut command, "", Duration::from_secs(3), |stdout| {
        let mut text = String::new();
        stdout.take(65537).read_to_string(&mut text)?;
        Ok(text)
    })
    .ok()?;
    if !status.success() || text.len() > 65536 {
        return None;
    }
    address_from_response(&serde_json::from_str::<Value>(&text).ok()?, ip)
}

#[derive(Serialize, Deserialize)]
struct Cached {
    address: Option<String>,
    fetched_at: u64,
    #[serde(default)]
    format_version: u8,
}

fn load_cache(path: &Path, timestamp: u64) -> BTreeMap<IpAddr, Cached> {
    let mut cache: BTreeMap<IpAddr, Cached> = fs::metadata(path)
        .ok()
        .filter(|metadata| metadata.len() <= 2 * 1024 * 1024)
        .and_then(|_| fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default();
    cache.retain(|_, entry| {
        let ttl = if entry.address.is_some() {
            SUCCESS_TTL
        } else {
            FAILURE_TTL
        };
        entry.format_version == CACHE_FORMAT_VERSION
            && entry.fetched_at <= timestamp
            && timestamp - entry.fetched_at < ttl
            && entry
                .address
                .as_deref()
                .is_none_or(|text| safe_label(text).as_deref() == Some(text))
    });
    for entry in cache.values_mut() {
        if let Some(address) = &mut entry.address {
            *address = compact_address(address);
        }
    }
    cache
}

pub fn addresses(ips: &[IpAddr], path: &Path, timestamp: u64) -> BTreeMap<IpAddr, String> {
    let mut cache = load_cache(path, timestamp);
    let mut result = BTreeMap::new();
    let mut jobs = Vec::new();
    for &ip in ips {
        let address = if let Some(label) = local_address(ip) {
            label.to_string()
        } else if let Some(cached) = cache.get(&ip) {
            cached.address.clone().unwrap_or_else(|| "Unknown".into())
        } else {
            if jobs.len() < MAX_LOOKUPS {
                jobs.push(ip);
            }
            "Unknown".into()
        };
        result.insert(ip, address);
    }
    if jobs.is_empty() {
        return result;
    }
    let next = AtomicUsize::new(0);
    let deadline = Instant::now() + Duration::from_secs(8);
    let (sender, receiver) = mpsc::channel();
    thread::scope(|scope| {
        for _ in 0..4 {
            let sender = sender.clone();
            let jobs = &jobs;
            let next = &next;
            scope.spawn(move || {
                while Instant::now() < deadline {
                    let Some(&ip) = jobs.get(next.fetch_add(1, Ordering::Relaxed)) else {
                        break;
                    };
                    let _ = sender.send((ip, lookup(ip)));
                }
            });
        }
    });
    drop(sender);
    for (ip, address) in receiver {
        result.insert(ip, address.clone().unwrap_or_else(|| "Unknown".into()));
        cache.insert(
            ip,
            Cached {
                address,
                fetched_at: timestamp,
                format_version: CACHE_FORMAT_VERSION,
            },
        );
    }
    // Cache errors must never prevent reporting authentication or firewall events.
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if fs::create_dir_all(parent).is_ok() {
        if let Ok(text) = serde_json::to_string(&cache) {
            let _ = store::atomic(path, &text);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_ips_never_need_an_external_lookup() {
        for (ip, expected) in [
            ("127.0.0.1", "Loopback"),
            ("::1", "Loopback"),
            ("10.0.0.1", "Private"),
            ("192.168.1.2", "Private"),
            ("fe80::1", "Private"),
            ("fd00::1", "Private"),
            ("192.0.2.254", "Reserved"),
            ("2001:db8::1", "Reserved"),
            ("100.64.0.1", "Reserved"),
            ("::ffff:192.168.1.1", "Private"),
        ] {
            assert_eq!(local_address(ip.parse().unwrap()), Some(expected));
        }
        assert_eq!(local_address("1.1.1.1".parse().unwrap()), None);
    }
    #[test]
    fn domestic_and_foreign_addresses_and_bad_responses() {
        let ip = "1.1.1.1".parse().unwrap();
        let mut response = serde_json::json!({"success":true,"ip":"1.1.1.1",
            "country_code":"CN","country":"中国","region":"广东省","city":"深圳市"});
        assert_eq!(
            address_from_response(&response, ip).as_deref(),
            Some("广东省 / 深圳市")
        );
        response["region"] = "新疆维吾尔自治区".into();
        response["city"] = "乌鲁木齐".into();
        assert_eq!(
            address_from_response(&response, ip).as_deref(),
            Some("新疆 / 乌鲁木齐")
        );
        assert_eq!(compact_address("新疆维吾尔自治区"), "新疆");
        response["country_code"] = "AU".into();
        response["country"] = "澳大利亚".into();
        response["city"] = "布里斯班".into();
        assert_eq!(
            address_from_response(&response, ip).as_deref(),
            Some("澳大利亚 / 布里斯班")
        );
        response["country_code"] = "US".into();
        response["country"] = "美国".into();
        response["city"] = "华盛顿哥伦比亚特区".into();
        assert_eq!(
            address_from_response(&response, ip).as_deref(),
            Some("美国 / 华盛顿哥")
        );
        response["city"] = "东京".into();
        assert_eq!(
            address_from_response(&response, ip).as_deref(),
            Some("美国 / 东京")
        );
        response["country_code"] = "CN".into();
        response["region"] = "内蒙古自治区".into();
        response["city"] = "呼和浩特市".into();
        assert_eq!(
            address_from_response(&response, ip).as_deref(),
            Some("内蒙古自治区 / 呼和浩特市")
        );
        response["success"] = false.into();
        assert!(address_from_response(&response, ip).is_none());
        assert!(safe_label("city\x1b[31m").is_none());
        assert!(safe_label("city\nnext line").is_none());
        assert!(safe_label("city\u{202e}").is_none());
    }
}
