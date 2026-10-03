use crate::{config::Config, nft};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

unsafe extern "C" {
    fn flock(fd: i32, operation: i32) -> i32;
    fn fchown(fd: i32, owner: u32, group: u32) -> i32;
}

// Global lock: multiple config files must not concurrently replace the same table.
pub fn lock() -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open("/run/lock/portguard.lock")
        .context("无法取得锁，请使用 sudo")?;
    if unsafe { flock(file.as_raw_fd(), 2 | 4) } != 0 {
        bail!("另一个 portguard 操作正在执行，请稍后重试");
    }
    Ok(file)
}

pub fn atomic(path: &Path, text: &str) -> Result<()> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => Some(metadata),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    // O_EXCL avoids following a pre-existing temporary symlink.
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".tmp.{}", std::process::id()));
    let temporary = PathBuf::from(name);
    let mut created = false;
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        created = true;
        file.write_all(text.as_bytes())?;
        if let Some(metadata) = &metadata {
            let temporary_metadata = file.metadata()?;
            if (temporary_metadata.uid(), temporary_metadata.gid())
                != (metadata.uid(), metadata.gid())
                && unsafe { fchown(file.as_raw_fd(), metadata.uid(), metadata.gid()) } != 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("无法保留原文件所有者，未替换文件");
            }
            // chown may clear permission bits, so restore permissions afterwards.
            file.set_permissions(fs::Permissions::from_mode(metadata.mode() & 0o7777))?;
        }
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_parent(path)?;
        Ok(())
    })();
    // Only remove our own newly-created file; never delete another file on open failure.
    if result.is_err() && created {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn sync_parent(path: &Path) -> Result<()> {
    File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
    Ok(())
}
fn remove(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => sync_parent(path),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Version {
    pub config_text: String,
    pub rules: String,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub current: Version,
    pub previous: Option<Version>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    old_disk: String,
    old_rules: String,
    old_state: Option<State>,
}

pub struct Store {
    pub path: PathBuf,
}
impl Store {
    pub fn side(&self, suffix: &str) -> PathBuf {
        let mut path = self.path.as_os_str().to_os_string();
        path.push(suffix);
        PathBuf::from(path)
    }
    pub fn text(&self) -> Result<String> {
        let size = fs::metadata(&self.path)?.len();
        if size > 2 * 1024 * 1024 {
            bail!("配置文件超过 2 MiB");
        }
        fs::read_to_string(&self.path).with_context(|| format!("无法读取 {}", self.path.display()))
    }
    pub fn state(&self) -> Result<Option<State>> {
        let path = self.side(".state.json");
        match fs::read_to_string(path) {
            Ok(t) => Ok(Some(
                serde_json::from_str(&t).context("状态文件损坏，未改变防火墙")?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
    pub fn pending(&self) -> bool {
        self.side(".pending.json").exists()
    }
    pub fn recover(&self) -> Result<()> {
        if !self.pending() {
            return Ok(());
        }
        let journal: Journal =
            serde_json::from_str(&fs::read_to_string(self.side(".pending.json"))?)
                .context("事务记录损坏，请人工检查；未改变防火墙")?;
        nft::install(&journal.old_rules).context("恢复旧规则失败；保留事务记录")?;
        atomic(&self.path, &journal.old_disk)?;
        match journal.old_state {
            Some(state) => atomic(
                &self.side(".state.json"),
                &serde_json::to_string_pretty(&state)?,
            )?,
            None => remove(&self.side(".state.json"))?,
        }
        remove(&self.side(".pending.json"))?;
        eprintln!("已恢复中断操作前的配置文件和规则");
        Ok(())
    }
    pub fn apply(&self, text: String, session: Option<&str>) -> Result<bool> {
        let config = Config::parse(&text)?;
        config.protect_ssh_session(session)?;
        let current_rules = nft::snapshot()?;
        let state = self.state()?;
        if state.is_none() && !current_rules.is_empty() {
            bail!(
                "专用表已存在，但此配置没有状态记录。请使用原配置文件管理；确认是残留后再手工删除专用表"
            );
        }
        if let Some(s) = &state {
            if Config::parse(&s.current.config_text)? == config
                && nft::equivalent(&s.current.rules, &current_rules)
            {
                return Ok(false);
            }
        }
        let previous_text = match &state {
            Some(s) => s.current.config_text.clone(),
            None => {
                let mut old = config.clone();
                old.enabled = false;
                toml::to_string_pretty(&old)?
            }
        };
        let previous = Version {
            config_text: previous_text,
            rules: current_rules,
        };
        self.commit(text, Some(previous))?;
        Ok(true)
    }
    fn commit(&self, text: String, previous: Option<Version>) -> Result<()> {
        let config = Config::parse(&text)?;
        let target_rules = nft::render(&config)?;
        // Syntax/kernel validation happens before writing a journal or changing any live state.
        nft::check(&target_rules)?;
        let journal = Journal {
            old_disk: self.text()?,
            old_rules: nft::snapshot()?,
            old_state: self.state()?,
        };
        atomic(
            &self.side(".pending.json"),
            &serde_json::to_string_pretty(&journal)?,
        )?;
        let result = (|| -> Result<()> {
            nft::install(&target_rules)?;
            let current = Version {
                config_text: text.clone(),
                rules: nft::snapshot()?,
            };
            // Applying an unchanged draft must not replace its inode or metadata.
            if text != journal.old_disk {
                atomic(&self.path, &text)?;
            }
            atomic(
                &self.side(".state.json"),
                &serde_json::to_string_pretty(&State { current, previous })?,
            )?;
            remove(&self.side(".pending.json"))?;
            Ok(())
        })();
        if let Err(error) = result {
            match self.recover() {
                Ok(()) => return Err(error.context("应用失败，已恢复原状态")),
                Err(recovery) => bail!(
                    "应用失败：{error:#}；自动恢复失败：{recovery:#}；保留事务记录，下次写入命令会重试恢复"
                ),
            }
        }
        Ok(())
    }
    pub fn rollback(&self, session: Option<&str>) -> Result<()> {
        let state = self.state()?.context("没有成功应用记录，无法回退")?;
        let previous = state.previous.context("没有上一版配置，无法回退")?;
        let current = Config::parse(&self.text()?)?;
        let mut target = Config::parse(&previous.config_text)?;
        // Never undo newly-added SSH protection while restoring old rules.
        for port in current.protected_ports {
            if !target.protected_ports.contains(&port) {
                target.protected_ports.push(port);
            }
        }
        target.validate()?;
        target.protect_ssh_session(session)?;
        let text = if target == Config::parse(&previous.config_text)? {
            previous.config_text
        } else {
            toml::to_string_pretty(&target)?
        };
        let previous = Version {
            config_text: state.current.config_text,
            rules: nft::snapshot()?,
        };
        // Render trusted, validated config rather than blindly replaying externally edited rules.
        self.commit(text, Some(previous))
    }
    pub fn disable(&self) -> Result<()> {
        // Escape hatch also works when the user has made their TOML invalid.
        let old_disk = self.text()?;
        let state = self.state()?;
        let mut config = match Config::parse(&old_disk) {
            Ok(c) => c,
            Err(_) => Config::parse(
                &state
                    .as_ref()
                    .context("配置无效且无成功状态，请使用紧急解除命令")?
                    .current
                    .config_text,
            )?,
        };
        if !config.enabled && nft::snapshot()?.is_empty() {
            return Ok(());
        }
        config.enabled = false;
        let previous = Version {
            config_text: state
                .as_ref()
                .map(|s| s.current.config_text.clone())
                .unwrap_or(old_disk),
            rules: nft::snapshot()?,
        };
        self.commit(toml::to_string_pretty(&config)?, Some(previous))
    }
}
