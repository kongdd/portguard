mod audit;
mod config;
mod geoip;
mod nft;
mod process;
mod store;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config::Config;
use std::{
    io::{Write, stderr, stdout},
    net::IpAddr,
    path::PathBuf,
    thread,
    time::Duration,
};

#[derive(Parser)]
#[command(version, about = "端口/IP 白名单管理；只操作专用 nftables 表")]
struct Cli {
    #[arg(short = 'c', long, global = true, default_value = "firewall.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// 按 IP 查询 SSH 登录、异常连接和防火墙拦截日志
    Audit(audit::Options),
    /// 校验配置和 nftables 规则，不改变防火墙
    Check {
        /// 输出生成的 nftables 规则
        #[arg(long)]
        print: bool,
        /// 只校验 TOML（无需 nftables 或 root）
        #[arg(long)]
        config_only: bool,
    },
    /// 应用配置；无需重启 rathole。加 --watch 后持续热载文件变化。
    Apply {
        /// 应用当前文件后继续监视，内容稳定变化时再次应用
        #[arg(long)]
        watch: bool,
        /// 轮询间隔（毫秒）。两次读到相同新内容后才应用，避免写到一半。
        #[arg(long, default_value_t = 500)]
        interval_ms: u64,
    },
    /// 查看配置、实际规则和上一版状态
    Status {
        /// 判断给定 IP 在各规则下是否可访问
        #[arg(long)]
        ip: Option<IpAddr>,
    },
    /// 恢复上一版成功配置；保留新增加的保护端口
    Rollback,
    /// 取消全部限制并写入 enabled=false
    Disable,
}

fn status(store: &store::Store, ip: Option<IpAddr>) -> Result<()> {
    println!("配置: {}", store.path.display());
    if store.pending() {
        println!("状态: 存在未完成事务，下次 apply/rollback/disable 将先恢复");
    }
    let config = Config::parse(&store.text()?)?;
    let live = nft::snapshot()?;
    let state = store.state()?;
    println!(
        "实际防火墙: {}",
        if live.is_empty() {
            "未启用（专用表不存在）"
        } else {
            "已启用（专用表存在）"
        }
    );
    match &state {
        None => println!("记录: 尚无成功应用记录"),
        Some(state) => {
            let applied = Config::parse(&state.current.config_text)?;
            println!(
                "配置: {}",
                if applied == config {
                    "与上次成功配置一致"
                } else {
                    "已修改，尚未应用"
                }
            );
            println!(
                "实际规则: {}",
                if nft::equivalent(&live, &state.current.rules) {
                    "与上次成功状态一致"
                } else {
                    "已被外部修改或主机重启，请重新 apply"
                }
            );
            println!(
                "上一版: {}",
                if state.previous.is_some() {
                    "可回退"
                } else {
                    "无"
                }
            );
        }
    }
    println!(
        "保护端口: {}",
        config
            .protected_ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
    // Show the last successfully applied policy, not an unapplied draft as live policy.
    let display = state
        .as_ref()
        .map(|s| Config::parse(&s.current.config_text))
        .transpose()?
        .unwrap_or(config);
    println!("\n规则\t端口（TCP/UDP）\t白名单（上次成功配置；实际状态见上方）");
    for (name, rule) in &display.rules {
        let allow = if !display.enabled || !rule.enabled {
            "未限制".into()
        } else if rule.allows_any() {
            "*（全部来源）".into()
        } else if rule.allow.is_empty() {
            "拒绝全部".into()
        } else {
            rule.allow
                .iter()
                .map(|entry| {
                    if entry.note().is_empty() {
                        entry.ip().to_string()
                    } else {
                        format!("{}（{}）", entry.ip(), entry.note())
                    }
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        print!("{name}\t{}\t{allow}", rule.ports.join(", "));
        if let Some(ip) = ip {
            let matched = rule
                .allow
                .iter()
                .find(|s| config::Network::parse(s.ip()).is_ok_and(|n| n.contains(ip)));
            let result = if !display.enabled || !rule.enabled || rule.allows_any() {
                "不受限制".into()
            } else if let Some(matched) = matched {
                format!("允许，匹配 {}", matched.ip())
            } else {
                "拒绝".into()
            };
            print!("\t{ip}: {result}");
        }
        println!();
    }
    if state.is_none() {
        println!("\n以上为配置预览，尚未有本工具的应用记录。");
    }
    Ok(())
}

fn note(message: &str) {
    let _ = writeln!(stderr(), "{message}");
    let _ = stderr().flush();
}
fn report(message: &str) {
    let _ = writeln!(stdout(), "{message}");
    let _ = stdout().flush();
}
fn apply_once(store: &store::Store, session: Option<&str>) -> Result<()> {
    let _lock = store::lock()?;
    store.recover()?;
    if store.apply(store.text()?, session)? {
        report(&format!(
            "已应用：{}；rathole 无需重启",
            store.path.display()
        ));
    } else {
        report("配置与实际规则未变，无需重新应用");
    }
    Ok(())
}
fn watch(store: &store::Store, session: Option<&str>, interval_ms: u64) -> Result<()> {
    let interval = Duration::from_millis(interval_ms.clamp(100, 60_000));
    note(&format!(
        "监视 {}；新内容连续稳定 {} ms 后应用。无效配置不会改变现有规则。",
        store.path.display(),
        interval.as_millis()
    ));
    let mut seen = String::new();
    let mut reported = String::new();
    // Apply the file already on disk, then only react to a later stable change.
    match store.text() {
        Ok(text) => reconcile(store, session, text, &mut seen, &mut reported),
        Err(error) => remember(
            &mut reported,
            &format!("读取配置失败，保留现有规则：{error:#}"),
        ),
    }
    loop {
        thread::sleep(interval);
        let text = match store.text() {
            Ok(text) => text,
            Err(error) => {
                remember(
                    &mut reported,
                    &format!("读取配置失败，保留现有规则：{error:#}"),
                );
                continue;
            }
        };
        if text == seen {
            continue;
        }
        thread::sleep(interval);
        match store.text() {
            Ok(stable) if stable == text => {
                reconcile(store, session, stable, &mut seen, &mut reported)
            }
            Ok(_) => {}
            Err(error) => remember(
                &mut reported,
                &format!("读取配置失败，保留现有规则：{error:#}"),
            ),
        }
    }
}
// Called under the global lock, after recovery. Never substitute a newer,
// unconfirmed draft for the content that passed the stability check.
fn stable_text(store: &store::Store, expected: &str) -> Result<Option<String>> {
    let current = store.text()?;
    Ok((current == expected).then_some(current))
}
fn reconcile(
    store: &store::Store,
    session: Option<&str>,
    text: String,
    seen: &mut String,
    reported: &mut String,
) {
    if text == *seen {
        return;
    }
    let result = (|| {
        let _lock = store::lock()?;
        store.recover()?;
        match stable_text(store, &text)? {
            Some(stable) => store.apply(stable, session).map(Some),
            None => Ok(None),
        }
    })();
    match result {
        Ok(None) => {} // File changed: wait for another pair of stable reads.
        Ok(Some(changed)) => {
            *seen = text;
            reported.clear();
            if changed {
                report(&format!(
                    "已应用：{}；rathole 无需重启",
                    store.path.display()
                ));
            } else {
                report("配置与实际规则未变，无需重新应用");
            }
        }
        Err(error) => remember(reported, &format!("未应用，防火墙保持原样：{error:#}")),
    }
}
fn remember(reported: &mut String, message: &str) {
    if reported != message {
        note(message);
        *reported = message.to_string();
    }
}
fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Action::Audit(options) = &cli.command {
        return audit::run(options);
    }
    let path = cli
        .config
        .canonicalize()
        .with_context(|| format!("无法找到配置 {}", cli.config.display()))?;
    let store = store::Store { path };
    let session = std::env::var("SSH_CONNECTION").ok();
    match cli.command {
        Action::Audit(_) => unreachable!("audit handled before loading firewall config"),
        Action::Check { print, config_only } => {
            let config = Config::parse(&store.text()?)?;
            config.protect_ssh_session(session.as_deref())?;
            let rules = nft::render(&config)?;
            if print {
                if rules.is_empty() {
                    println!("# enabled=false：应用时只删除专用表");
                } else {
                    print!("{rules}");
                }
            }
            if !config_only {
                let _lock = store::lock()?;
                nft::check(&rules)?;
            }
            if store.pending() {
                eprintln!("注意：存在未完成事务，下次写入命令将先恢复");
            }
            println!(
                "检查通过{}",
                if config_only {
                    "（仅配置，未验证内核规则）"
                } else {
                    "（配置与 nftables）"
                }
            );
        }
        Action::Status { ip } => {
            let _lock = store::lock()?;
            status(&store, ip)?;
        }
        Action::Apply {
            watch: true,
            interval_ms,
        } => watch(&store, session.as_deref(), interval_ms)?,
        Action::Apply { watch: false, .. } => apply_once(&store, session.as_deref())?,
        Action::Rollback => {
            let _lock = store::lock()?;
            store.recover()?;
            store.rollback(session.as_deref())?;
            println!("已回退到上一版配置");
        }
        Action::Disable => {
            let _lock = store::lock()?;
            store.recover()?;
            store.disable()?;
            println!("已取消全部限制；配置已写入 enabled=false");
        }
    }
    Ok(())
}

#[cfg(test)]
mod watch_tests {
    use super::*;
    use std::{fs, time::SystemTime};

    #[test]
    fn newer_or_recovered_content_must_pass_stability_check_again() {
        let path = std::env::temp_dir().join(format!(
            "portguard-watch-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = store::Store { path: path.clone() };
        fs::write(&path, "confirmed draft").unwrap();
        assert_eq!(
            stable_text(&store, "confirmed draft").unwrap(),
            Some("confirmed draft".into())
        );
        // An editor's atomic replacement (or recovery) happens after the two reads.
        let replacement = path.with_extension("replacement");
        fs::write(&replacement, "new unconfirmed draft").unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert_eq!(stable_text(&store, "confirmed draft").unwrap(), None);
        assert_eq!(
            stable_text(&store, "new unconfirmed draft").unwrap(),
            Some("new unconfirmed draft".into())
        );
        fs::remove_file(&path).unwrap();
        assert!(stable_text(&store, "new unconfirmed draft").is_err());
    }
}
