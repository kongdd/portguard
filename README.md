# portguard

[![Test](https://github.com/kongdd/portguard/actions/workflows/test.yml/badge.svg)](https://github.com/kongdd/portguard/actions/workflows/test.yml)

一个 Rust CLI，用 TOML 管理端口范围的 IP 白名单。独立于 rathole，只维护专用的 nftables 表。修改后执行 `apply`，无需重启 rathole。`apply --watch` 会在应用后继续监视文件并热载。

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
allow = [
    { ip = "203.0.113.25", note = "家里" },
    { ip = "198.51.100.0/24", note = "办公室" },
    { ip = "2001:db8::/64", note = "办公室 IPv6" },
]

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

IP/CIDR 可以写成 `{ ip = "203.0.113.25", note = "家里" }`，备注紧挨地址；也支持原来的纯字符串格式，两种写法可混用。`note` 可省略或留空，最多 128 个字符，不能含控制字符。备注只用于识别，不改变白名单匹配；UI 可在每个地址旁直接编辑，CLI `status` 也会显示。删除地址时备注随该项一同删除。

### IP 与 CIDR 网段

`allow` 支持单个 IP 和 CIDR 网段。`/16`、`/24` 表示 IP 地址前多少位固定，末尾的 `0` 不是范围大小；**斜杠后的数字越大，网段范围越小**。

| 白名单项 | 包含的 IPv4 地址范围 | 地址数量 |
| --- | --- | ---: |
| `113.57.0.0/16` | `113.57.0.0` ～ `113.57.255.255` | 65,536 |
| `198.51.100.0/24` | `198.51.100.0` ～ `198.51.100.255` | 256 |
| `113.57.5.82/32` | 仅 `113.57.5.82` | 1 |

直接写 `113.57.5.82` 与写 `113.57.5.82/32` 一样，只允许这一个 IPv4 地址。IPv6 也支持 CIDR，单个地址对应 `/128`。

注意：`113.57.0.0/16` 会允许整个网段，不只是自己的 IP；它已经覆盖 `113.57.5.82`，因此即使删除单独的 `113.57.5.82`，该地址仍被允许。若只想放行自己的地址，应只填写单个 IP，不要额外放行大网段。以上数量是地址总数，不是传统子网的可用主机数。

## 常用命令

```bash
sudo portguard check                # 配置 + nft -c 校验，不改变规则
sudo portguard apply                # 应用一次
sudo portguard apply --watch        # 应用后持续热载配置变化
sudo portguard status               # 配置与实际生效状态
sudo portguard rollback             # 回退上一版成功配置
sudo portguard disable              # 取消全部限制，并保存 enabled=false
sudo portguard audit                # 最近 24 小时的登录失败/拦截来源排行
```

默认读取当前目录的 `firewall.toml`，所有命令支持 `-c`：

```bash
sudo portguard -c /etc/portguard/firewall.toml apply
sudo portguard -c /etc/portguard/firewall.toml apply --watch --interval-ms 500
```

`apply` 本身就是热载：用一次 nftables 事务替换专用表，rathole 不用重启。不加 `--watch` 时进程随即退出，适合手工执行或脚本调用。`--watch` 先应用当前文件，再按路径重新读取，编辑器原子替换也能发现；新内容必须连续两次相同才应用，避免写到一半。配置无效、校验失败或会锁死当前 SSH 端口时，只报错并保留正在生效的规则，进程继续等待下一次修改。它和单次 `apply` 使用同一把锁。`--interval-ms` 限制在 100–60000。可用 `deploy/portguard-watch.service` 开机运行；不需要持续热载时，仍用单次 `apply`。

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
sudo portguard audit --since 1y              # 最近一年（365 天），也可写 365d
sudo portguard audit --ip 203.0.113.25        # 单个 IP
sudo portguard audit --json                  # 结构化输出
sudo portguard audit --min-events 0          # 也显示仅有成功登录的 IP
sudo portguard audit --no-geo                # 不向第三方发送公网 IP、不联网查询属地
sudo portguard audit index --since 1y        # 预解析一年日志，建立/更新索引
sudo portguard audit index --since 1y --rebuild # 重建索引（只读取 journal）
sudo portguard audit --no-index              # 绕过索引，直接读取 journal 进行核对
```

按 `fail` 列倒序（可加 `--sort` 切换），显示每个 IP 的登录失败/成功次数、无效用户日志数、连接断开/重置日志数、拦截包日志数、被访问端口和最近出现时间。`--min-events` 的门槛包含失败、无效用户、断开、重置和拦截日志，默认 1；设置为 0 也显示仅成功登录的 IP。查询不需要 firewall.toml，不改变规则、不自动封禁；最长查询 1 年（365 天），默认使用持久化 SQLite 索引，首次查询流式解析指定时间范围内全部相关 journal 记录，不设置日志条数上限；后续自动增量更新并从索引按精确秒级时间范围统计。`--limit` 只限制展示的 IP 数，不限制统计日志量。每次 journal 解析最长运行 300 秒，超时或读取失败会回滚索引更新并报错，不返回截断的部分统计。可查询的历史取决于 journal 的实际保留时间，不保证保留一年日志。

普通终端输出只保留查询标题和表格，不重复显示统计口径、属地隐私或启用日志的说明；相关说明见本节。遇到格式无效的记录时，仅向 stderr 输出简短 `Warning`。`--json` 保持原结构，详细说明仍在 `notes` 中；兼容字段 `truncated` 现在固定为 `false`，表示不再按日志条数截断。

表头统一小写：`ip` / `address` / `fail` / `ok` / `invalid` / `closed` / `reset` / `last`。`last` 自动选择 `sec`、`min`、`hour`、`day`、`mon`，取整显示，数字右对齐、单位左对齐；`mon` 按 30 天计算。JSON 仍保留完整字段名和 Unix 秒时间戳。

默认按 `fail` 列倒序（与历史行为一致），可用 `--sort <column>` 切换为其他列的倒序，例如 `audit --sort invalid`、`audit --sort reset`、`audit --sort drop`（拦截日志最多优先）、`audit --sort last`（最新优先）。表格的 `drop` 列展示限速后实际记录的拦截包数，与 JSON 的 `denied_packets_logged` 一致。`--sort` 也接受小写表头名称，如 `ip`、`address`、`closed`。`--sort ip` 按 IP 地址数值倒序排列，而不是按字符串排序；混合地址族时 IPv6 排在 IPv4 前。`--sort address` 先为所有符合门槛的候选 IP 填充属地，再按属地字符串倒序排列并应用 `--limit`；属地相同时按 IP 字符串升序排列。属地查询预算仍然有效，未查询或查询失败的候选使用 `Unknown` 参与排序；`--no-geo` 时全部显示 `-`，按 IP 打破平局。

`Address` 默认通过 `curl` 向 `https://ipwho.is` 查询（需要安装 curl），使用中文结果：中国大陆 IP 显示“省份 / 城市”，其他 IP 显示“国家 / 城市”，国外城市名最多保留前 4 个字，国内城市名不受此限制（表格和 JSON 都适用）。内网、回环和保留地址分别标注 `Private`、`Loopback`、`Reserved`，不会发送给第三方；公网查询失败、超时或超过本次查询预算显示 `Unknown`。属地是服务商估算，不代表精确位置或攻击者国籍。`--no-geo` 禁用属地查询及缓存读取，地址显示 `-`。

属地成功缓存 7 天、失败缓存 10 分钟。root 默认缓存路径 `/var/cache/portguard/geoip.json`，普通用户使用 `$XDG_CACHE_HOME/portguard/geoip.json`（或 `~/.cache/portguard/geoip.json`）；可用 `--geo-cache PATH` 指定。每次最多查询 32 个未缓存公网 IP，4 路并发，总调度预算 8 秒，最后一批最多另需 3 秒；失败不会影响日志统计。表格属地最多占 24 个显示列，超长用省略号截断，JSON 的 `address` 不受表格的 24 列宽限制，国外城市仍最多保留 4 个字。在线查询会将公网 IP 发给第三方，仅用于展示，不改变防火墙。

### audit 索引

root 默认索引路径 `/var/cache/portguard/audit.sqlite3`，普通用户与属地缓存使用同一个缓存目录。可通过 `--index-path PATH` 指定其他数据库；索引文件以 `600` 权限新建，不保存原始日志正文，只保存 journal 游标、时间、解析出的 IP、事件类型和目标端口。按时间、IP 建数据库索引，复用与展示条数无关，`--ip` 不会导致其他 IP 被漏建索引。

- `audit index --since 1y` 预建索引，默认一年；普通 `audit` 首次只建立本次需要的范围。
- 覆盖范围扩大时只补读尚未解析的历史区间；平时只读取上次快照之后的新日志及边界秒，使用 `__CURSOR` 去重，避免增量重复计数。即使本次查询范围缩小，也会补齐索引快照之间的空档。
- SQLite 事务和写锁保证更新、覆盖范围标记一起提交，失败回滚；同一路径的并发更新会等待，不会重复累计。索引绑定机器和有效用户身份，不能静默复用其他机器或权限范围的数据。
- 索引保留已解析的最近 365 天记录，journal 轮转后仍能查询这些历史；从未解析、已经被 journal 删除的历史不能补回。导入旧 journal、改变日志读取权限或修改解析口径后应执行 `audit index --rebuild`，重新扫描当前可访问的日志。
- `--no-index` 完全绕过索引，直接解析当前 journal；源日志已轮转时，其结果可能少于保留历史的索引。损坏或不兼容的索引会明确报错，不会静默返回旧数据；版本不兼容可用 `--rebuild`，数据库物理损坏可指定新的 `--index-path` 重建。
- JSON 新增 `index` 信息（路径、索引覆盖起止时间、总记录数、本次新增解析记录数）；`--no-index` 时为 `null`。`audit index --json` 输出索引状态，不查询属地。

构建 release 后可运行 `python3 tests/index_bench.py`，用 50 万条合成日志核对索引与直接解析的统计一致性及查询速度；不会读取/修改真实 journal，不联网，也不改变防火墙。

### 日志来源与统计口径

来源是 systemd journal：

在 journal 保留数据不变且使用相同查询截止时间时，同一 IP 的 `100d` 统计应不小于 `30d`，但不同时间范围的前 20 名可能是不同 IP，比较时可用 `--ip` 指定同一来源。表格默认展示前 20 个符合门槛的 IP，不是所有 IP。`Fail` 只统计明确的 `Failed` 认证失败；禁用密码认证时，扫描可能仅留下 `Invalid`、`Closed` 或 `Reset`，不能把它们硬算成认证失败。仅成功登录的 IP 需要 `--min-events 0`，查看完整来源列表还应增大 `--limit`。

- SSH 日志（sshd/sshd-session）：分别统计 `Failed ... from IP port ...`、`Accepted ...`、`Invalid user ...`、`Connection closed by ... IP port ...` 和 `Connection reset by ... IP port ...`。无效用户、断开、重置不算作认证失败；同一连接可能产生多类日志，不能相加当作独立连接或攻击次数。正常客户端也可能断开或重置，需结合频率、账号和时间分析。无来源 IP 的 KEX/PAM 错误不归属到某个 IP，避免猜测或重复计数。
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

配置旁会自动生成 `firewall.toml.state.json` 和临时的 `firewall.toml.pending.json`。这些是内部状态，不要编辑。常规 `apply` 保留注释，内容不变时不重写配置文件；`disable` 和合并保护端口的回退会重新格式化 TOML。替换已有文件时保留原所有者、用户组和权限，避免 sudo 操作后配置变成 root 专属；新建内部状态文件使用 `0600`。

同一主机使用一份配置。全局文件锁防止并发写入；已有专用表但本配置没有状态记录时，`apply` 拒绝接管。请始终使用同一绝对配置路径管理，不要移动配置而丢弃其状态文件。

紧急解除（仅删除本工具的表，不修改 TOML；之后执行 `apply` 或重启恢复服务可能重新启用）：

```bash
sudo nft delete table inet portguard
```

## 边界

只操作 `table inet portguard` 的 INPUT 链，不清空整个 ruleset。`"*"`、关闭规则或删除表不会越过 UFW、其他 nftables 表或云安全组。

规则按协议与端口匹配；同端口的其他进程也会受影响。适用于宿主机/host 网络监听，Docker bridge 的端口发布不属于本版过滤范围。不按连接状态跳过 ACL，因此移除 IP 后会过滤该来源已有连接的后续入站数据包。

工具独立使用，不读取或修改 rathole 配置。可选的 [TypeScript 网页管理端](UI/README.md) 放在 `UI/`，提供规则编辑、配置校验和保存，并检测当前浏览器的出口 IPv4/IPv6。页面不调用应用、回退或关闭限制命令；保存后的配置由独立运行的 `apply --watch` 热载。管理服务默认监听 `0.0.0.0:7500`，使用明文 HTTP 和初始账号 `admin/123456`，请立即改密并限制访问来源；也可设 `PORTGUARD_UI_BIND=127.0.0.1` 配合 SSH 隧道。

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

Rust 单元测试 17 项、CLI 端到端测试 13 项通过；rustfmt 与 Clippy 检查通过。真实内核过滤由 GitHub Actions 在隔离网络命名空间验证，覆盖 IPv4/IPv6、TCP/UDP、SSH 保护、回退以及启用日志后的过滤行为。审计解析使用构造日志测试，不把它等同于真实攻击检测。

二进制包为 Linux x86_64 GNU 构建，要求 glibc ≥ 2.39（Ubuntu 24.04 及较新版本满足）；不是 Windows/macOS 或 NAS 通用安装包。其他 Linux 系统可从源码编译。
