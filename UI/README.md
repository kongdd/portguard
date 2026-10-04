# Portguard UI

TypeScript 网页 + 本机 HTTP API；调用现有 Rust CLI，不直接执行 nft，不改变 CLI 的事务/回退逻辑。

## 启动

需要 Linux、Node.js 22+、nftables 和已安装的 portguard。防火墙命令需要 root/CAP_NET_ADMIN。

```bash
cd UI
npm install
npm run build
# 先创建并填写真实 SSH 保护端口；不要覆盖已有配置
# cp ../firewall.example.toml ../firewall.toml
sudo env PORTGUARD_CONFIG="$(realpath ../firewall.toml)" \
  PORTGUARD_BIN=/usr/local/bin/portguard \
  SSH_CONNECTION="${SSH_CONNECTION:-}" \
  "$(command -v node)" dist-server/server.js
```

默认监听 `0.0.0.0:7500`，无需 Caddy。浏览器打开 `http://服务器IP:7500`。

默认账号 `admin`，密码 `123456`。首次启动会在配置旁创建 `firewall.toml.ui-auth.json`，只保存密码哈希。登录后可在页面修改密码；修改后旧会话失效，当前浏览器会保持登录。

这是明文 HTTP。公网或云安全组应只放行你的来源 IP 到 7500，不要对全网开放。可用 `PORTGUARD_UI_BIND=127.0.0.1` 改回仅本机，用 `PORTGUARD_UI_PORT` 改端口。

也可以使用 Bun：`bun install`、`bun run build`、`bun test`、`bun dist-server/server.js`。

## 功能与注意事项

- 添加/删除/启停规则，编辑端口范围、IP/CIDR 白名单、SSH 保护端口和拦截日志。
- 每个 IP/CIDR 旁可填写备注（如家里、办公室，最多 128 个字符）。保存为同一项内的 `{ ip = "203.0.113.25", note = "家里" }`，地址与备注相邻；兼容旧字符串格式。删除地址也会删除备注，备注不影响放行规则。
- 结构化编辑或原始 TOML；规则名可在 TOML 中重命名。
- 页面只读取和保存 TOML，不调用 `apply`、`rollback`、`disable` 或 nft。保存前用 `portguard check --config-only` 校验，因此网页进程不需要 root。
- 热载由单独的 `sudo portguard apply --watch` 完成。保存后的稳定文件会被它自动应用；配置无效时 watch 保留旧规则。
- 关闭或删除规则意味着取消该端口限制，不是拒绝全部。
- 结构化保存重排 TOML 并移除注释；保留注释请使用 TOML 编辑模式。
- 登录后自动向 ipify 查询**浏览器出口 IPv4/IPv6**，也可手动刷新并加入某条规则。查询失败不阻止编辑；支持手工填写。第三方会看到浏览器来源 IP。
- 浏览器出口 IP 不一定等于 SSH 来源，VPN/代理/NAT 会影响结果。
- 登录使用 HttpOnly、SameSite=Strict 会话 Cookie，12 小时过期。连续 8 次密码错误会锁定该来源 1 分钟。无 CORS，拒绝跨站 Origin。
- 服务内串行处理操作，保存/操作前检查配置摘要，检测已发生的外部编辑。**运行期间不要同时用 CLI 或其他编辑器写同一配置**：API 的草稿保存与 CLI 全局锁不共享，摘要检查不能消除跨进程的最后瞬间竞争。
- CLI 保留原有保护端口和事务恢复。UI 并非自动回退计时器；应用前确认 SSH 端口真实准确、保留应急 SSH 连接。
- 服务会继承 SSH_CONNECTION；使用 sudo 时按上面命令显式传入，仍必须手工填写真实 protected_ports。
- 运行目录、UI 源码/构建文件、CLI 和配置文件必须由可信管理员控制，避免普通用户替换后让 root 执行。
- `npm run dev` 仅用于页面开发，不是完整管理服务；生产使用构建后 API 服务。

## 测试

```bash
npm test
npm run build
```

测试覆盖配置默认值、中文规则、IPv6、IP 备注与旧格式混用、TOML 往返、名称转义、密码更新，以及非法 JSON、超限请求和异步异常后的服务可用性；不会操作真实防火墙。
