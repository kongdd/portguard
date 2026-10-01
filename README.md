# portguard

[![Test](https://github.com/kongdd/portguard/actions/workflows/test.yml/badge.svg)](https://github.com/kongdd/portguard/actions/workflows/test.yml)

一个 Rust CLI，用 TOML 管理端口范围的 IP 白名单。独立于 rathole，只维护专用的 nftables 表。修改后执行 `apply`，无需重启 rathole，无需常驻进程。

## 快速使用

运行环境：Linux、nftables；防火墙操作需要 root/CAP_NET_ADMIN。

```bash
# Ubuntu / Debian
sudo apt install nftables

# 解压二进制包后
sudo install -m 755 portguard /usr/local/bin/portguard
cp firewall.example.toml firewall.toml
nano firewall.toml

sudo portguard check
sudo portguard apply
sudo portguard status
```

请先填写 VPS 实际 SSH 端口，并将示例 IP 替换为自己的出口公网 IP。本文示例 IP 为文档保留地址。

## TOML 配置

```toml
# 放在所有 [表] 之前；填写 VPS 自身 SSH 端口，支持多个
protected_ports = [22]

[rules.nas]
ports = ["5200-5300"]
allow = ["203.0.113.25", "198.51.100.0/24", "2001:db8::/64"]

[rules.rdp]
ports = ["33890"]
allow = ["203.0.113.25"]

[rules.public]
ports = ["8080", "8443"]
allow = ["*"]

[rules.rathole]
ports = ["2333"]
allow = ["192.0.2.50"]
```

每条规则同时过滤 TCP/UDP 的入站访问，分别匹配 IPv4/IPv6。名称只用于标识规则，与 rathole 服务名无绑定。

| 配置 | 含义 |
|---|---|
| `ports = ["5202", "8000-8090"]` | 一个端口及一个闭区间 |
| `allow = ["203.0.113.25", "198.51.100.0/24"]` | 仅允许这些 IP/网段 |
| `allow = ["*"]` | 不限制来源；不能与其他 IP 混写 |
| `allow = []` | 拒绝全部来源 |
| 规则内 `enabled = false` | 关闭这条规则，保留配置 |
| 顶层 `enabled = false` | 关闭全部规则；默认 true |
| 删除整条规则后 `apply` | 取消相应端口限制 |

`allow` 必须填写。端口须为 1–65535。规则间或同一规则内的端口范围重叠均报错；关闭的规则仍参与配置校验。中文名称使用 `[rules."办公室"]`。

## 常用命令

```bash
sudo portguard check                # 配置 + nft -c 校验，不改变规则
sudo portguard apply                # 应用修改
sudo portguard status               # 配置与实际生效状态
sudo portguard rollback             # 回退上一版成功配置
sudo portguard disable              # 取消全部限制，并保存 enabled=false
sudo portguard audit                # 最近 24 小时的登录失败/拦截来源排行
```

默认读取当前目录的 `firewall.toml`，所有命令支持 `-c`：

```bash
sudo portguard -c /etc/portguard/firewall.toml apply
```

辅助选项：

```bash
portguard check --config-only       # 仅检查 TOML，无需 root 或 nft
portguard check --config-only --print  # 预览生成规则
sudo portguard status --ip 203.0.113.25  # 查看该 IP 匹配哪些条目
```

添加/删除 IP：直接编辑 `allow`，然后 `apply`。同一 IP 若仍被其他 CIDR 覆盖，删除单 IP 后仍然允许访问。

`status` 会提示配置尚未应用、专用表被外部修改、重启后丢失以及未完成事务。`--ip` 判断的是上次成功配置，不检测云安全组或其他防火墙。无成功记录时仅显示配置预览。

## 查询频繁登录和被拦截的 IP

```bash
sudo portguard audit                         # 最近 24 小时，前 20 个 IP
sudo portguard audit --since 1h --limit 30    # 最近一小时
sudo portguard audit --since 7d --min-events 10
sudo portguard audit --ip 203.0.113.25        # 单个 IP
sudo portguard audit --json                  # 结构化输出
```

按 SSH 失败次数优先排序，显示每个 IP 的登录失败/成功次数、拦截包日志数、被访问端口和最近出现时间。查询不需要 firewall.toml，不改变规则、不自动封禁；最长查询 30 天，最多分析最近 100000 条相关 journal 记录，达到上限会提示。

来源是 systemd journal：

- SSH 认证日志（sshd/sshd-session）：统计 `Failed ... from IP port ...` 与 `Accepted ...`；同一尝试伴随的 Invalid user、PAM 错误不重复计数。
- 内核防火墙日志：只统计本工具的 `portguard DROP` 记录，不把普通 rathole 连接错误算作攻击。

默认不开启拦截日志。如需查看被拦截的来源，在 TOML **顶层、所有表之前**增加：

```toml
protected_ports = [22]
log_denied = true

[rules.nas]
ports = ["5200-5300"]
allow = ["203.0.113.25"]
```

然后 `sudo portguard apply`。全部规则共用一个日志限速器：每秒最多 5 条、初始突发 10 条；日志超限仍然丢弃数据包，不会放行。journald/内核也可能再次限速，因此拦截数只代表实际记录的包数，不是连接数或完整攻击次数。没有历史记录时不能追溯过去流量。

查看原始记录：

```bash
sudo journalctl -u ssh -u sshd --since "1 hour ago"
sudo journalctl -k --since "1 hour ago" --grep 'portguard DROP'
sudo journalctl -u rathole --since "1 hour ago"  # 使用 systemd 服务时的运行日志
```

部分发行版还把 SSH 日志写入 `/var/log/auth.log` 或 `/var/log/secure`，本版 audit 只读取 journal。SSH 服务单元名称可能不同，audit 用 sshd 的日志标识检索，不依赖固定服务名。

rathole 的隧道连接、认证和转发错误不等于映射服务遭到攻击。经 rathole 转发到内网 SSH 的认证失败记录在**内网机器**；其连接来源通常是 rathole 客户端，不能直接当作公网攻击者。公网 VPS 的拦截日志仍可记录实际访问 VPS 的来源。

失败登录也可能来自正常用户；成功登录应结合账号核查。没有查询结果不代表没有攻击，日志可能未启用、已过期或当前用户无读取权限。`audit` 不检测所有端口、应用漏洞或已经入侵的程序。

## SSH 保护

任何规则覆盖 `protected_ports`，整次应用都会拒绝，旧规则不变。即使 `allow=["*"]` 或该规则已关闭，也不得覆盖保护端口。

VPS 自身 SSH 端口应保护；rathole 映射到内网 SSH 的端口（如 5202）可以限制。保护只是禁止本工具管理这些端口，不额外生成全部放行规则。

如果环境中保留了 `SSH_CONNECTION`，工具还会核对当前 SSH 服务端口是否列入保护列表。sudo/跳板机可能使该信息缺失，因此实际 SSH 端口始终需要手工填写；这不是完整的 SSH 服务自动发现。

回退时保留当前配置新增加的保护端口；旧规则若与它们冲突，回退也会拒绝。

## 回退与失败恢复

- `apply` 先校验，再用一次 nftables 事务替换专用表，不存在先清空再逐条写入的窗口。
- 新配置应用或保存失败会恢复原规则、配置文件和状态；原先未应用的编辑内容会保留。
- 中途进程退出会留下事务记录，下一次 `apply`、`rollback` 或 `disable` 先恢复再继续。没有后台自动恢复服务。
- `rollback` 恢复上一版成功配置，并重新生成规则；首次应用的上一版为关闭状态。
- 重复 `apply` 无变化时不覆盖历史。连续 `disable` 不丢失先前启用的配置。
- `disable` 可使用上次成功配置解除限制，即使当前 TOML 编辑坏了。

配置旁会自动生成 `firewall.toml.state.json` 和临时的 `firewall.toml.pending.json`。这些是内部状态，不要编辑。常规 `apply` 保留注释；`disable` 和合并保护端口的回退会重新格式化 TOML。

同一主机使用一份配置。全局文件锁防止并发写入；已有专用表但本配置没有状态记录时，`apply` 拒绝接管。请始终使用同一绝对配置路径管理，不要移动配置而丢弃其状态文件。

紧急解除（仅删除本工具的表，不修改 TOML；之后执行 `apply` 或重启恢复服务可能重新启用）：

```bash
sudo nft delete table inet portguard
```

## 边界

只操作 `table inet portguard` 的 INPUT 链，不清空整个 ruleset。`"*"`、关闭规则或删除表不会越过 UFW、其他 nftables 表或云安全组。

规则按协议与端口匹配；同端口的其他进程也会受影响。适用于宿主机/host 网络监听，Docker bridge 的端口发布不属于本版过滤范围。不按连接状态跳过 ACL，因此移除 IP 后会过滤该来源已有连接的后续入站数据包。

工具独立使用，不读取或修改 rathole 配置，不提供 TypeScript 网页端。本版先完成 CLI，后续页面可调用相同配置与操作。

## 开机恢复（可选）

重启后规则需重新加载。可以使用附带的 systemd oneshot 单元：

```bash
sudo mkdir -p /etc/portguard
# 将配置和首次 apply 生成的状态文件一起放在此目录，或在此目录首次 apply
sudo install -m 600 firewall.toml /etc/portguard/firewall.toml
sudo install -m 644 deploy/portguard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now portguard.service
```

已有应用记录时，需一并复制同名 `.state.json`，待处理事务应先完成再迁移。若 rathole 的 systemd 服务名称不同，修改单元中的 `Before=`。单元失败不会自动阻止另一个 rathole 服务启动；对启动顺序有硬要求时，需由该服务配置依赖。

## 编译与测试

```bash
cargo build --release --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
sudo python3 tests/cli_test.py
```

CLI 测试使用假的 nft 程序做失败注入，不改变系统规则。真实内核过滤测试严格要求独立网络命名空间：

```bash
sudo env PORTGUARD_BIN="$PWD/target/debug/portguard" \
  PORTGUARD_TEST_PARENT_NS="$(readlink /proc/self/ns/net)" \
  unshare --net python3 tests/kernel_test.py
```

该测试需要 nftables、iproute2、Python 3 和创建网络命名空间的权限。附带 GitHub Actions 配置，包含真实 IPv4/IPv6、TCP/UDP、回退和保护端口检查。

## 本次验证

Rust 单元测试 15 项、CLI 端到端测试 13 项通过；rustfmt 与 Clippy 检查通过。真实内核过滤由 GitHub Actions 在隔离网络命名空间验证，覆盖 IPv4/IPv6、TCP/UDP、SSH 保护、回退以及启用日志后的过滤行为。审计解析使用构造日志测试，不把它等同于真实攻击检测。

二进制包为 Linux x86_64 GNU 构建，要求 glibc ≥ 2.39（Ubuntu 24.04 及较新版本满足）；不是 Windows/macOS 或 NAS 通用安装包。其他 Linux 系统可从源码编译。
