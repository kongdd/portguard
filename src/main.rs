mod audit;
mod config;
mod geoip;
mod nft;
mod process;
mod store;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use config::Config;
use std::{net::IpAddr, path::PathBuf};

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
    /// 应用配置；无需重启 rathole
    Apply,
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
        } else if rule.allow == ["*"] {
            "*（全部来源）".into()
        } else if rule.allow.is_empty() {
            "拒绝全部".into()
        } else {
            rule.allow.join(", ")
        };
        print!("{name}\t{}\t{allow}", rule.ports.join(", "));
        if let Some(ip) = ip {
            let matched = rule
                .allow
                .iter()
                .find(|s| config::Network::parse(s).is_ok_and(|n| n.contains(ip)));
            let result = if !display.enabled || !rule.enabled || rule.allow == ["*"] {
                "不受限制".into()
            } else if let Some(matched) = matched {
                format!("允许，匹配 {matched}")
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
        Action::Apply => {
            let _lock = store::lock()?;
            store.recover()?;
            if store.apply(store.text()?, session.as_deref())? {
                println!("已应用：{}；rathole 无需重启", store.path.display());
            } else {
                println!("配置与实际规则未变，无需重新应用");
            }
        }
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
