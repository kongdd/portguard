import * as TOML from 'smol-toml';
export type AllowEntry = string | { ip: string; note?: string };
export interface Rule { enabled: boolean; ports: string[]; allow: AllowEntry[] }
export const allowIp = (entry: AllowEntry): string => typeof entry === 'string' ? entry : entry.ip;
export const allowNote = (entry: AllowEntry): string => typeof entry === 'string' ? '' : entry.note ?? '';
export function setAllowNote(rule: Rule, index: number, note: string) {
  const ip = allowIp(rule.allow[index]);
  rule.allow[index] = note ? { ip, note } : ip;
}
export interface Config { enabled: boolean; log_denied: boolean; protected_ports: number[]; rules: Record<string, Rule> }
export function parseConfig(text: string): Config {
  const c = TOML.parse(text) as unknown as Config;
  if (!Array.isArray(c.protected_ports) || !c.rules || typeof c.rules !== 'object' || Array.isArray(c.rules)) throw new Error('请填写 protected_ports 和 rules');
  for (const rule of Object.values(c.rules)) {
    if (!rule || !Array.isArray(rule.ports) || !rule.ports.every(port => typeof port === 'string') || !Array.isArray(rule.allow)
      || !rule.allow.every(entry => typeof entry === 'string' || entry && typeof entry.ip === 'string' && (entry.note === undefined || typeof entry.note === 'string'))) {
      throw new Error('规则须填写 ports 和 allow，备注项须含 ip 和可选的 note');
    }
  }
  return { ...c, enabled: c.enabled ?? true, log_denied: c.log_denied ?? false,
    rules: Object.fromEntries(Object.entries(c.rules).map(([name, r]) => [name, {
      ...r, enabled: r.enabled ?? true,
      allow: r.allow.map(entry => typeof entry === 'string' ? entry : { ...entry }),
    }])) };
}
function inlineValue(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(inlineValue).join(', ')}]`;
  if (value && typeof value === 'object') {
    return `{ ${Object.entries(value).map(([key, item]) => `${/^[A-Za-z0-9_-]+$/.test(key) ? key : inlineValue(key)} = ${inlineValue(item)}`).join(', ')} }`;
  }
  if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean') throw new Error('无效白名单内容');
  // Let the TOML library escape strings, including quotes and control characters.
  return TOML.stringify({ value }).slice('value = '.length).trimEnd();
}
export function serializeConfig(config: Config): string {
  // CLI is the authoritative validator; preserve unknown fields for it to reject.
  const { rules, ...settings } = config;
  if (!Object.keys(rules).length) return TOML.stringify(config);
  const sections = Object.entries(rules).map(([name, rule]) => {
    const text = TOML.stringify({ rules: { [name]: { ...rule, allow: [] } } });
    // Keep each address and its note together on one line, even when all entries are tables.
    const allow = rule.allow.length ? `allow = [\n${rule.allow.map(entry => `  ${inlineValue(entry)},`).join('\n')}\n]` : 'allow = []';
    return text.replace(/^allow = \[\s*\]$/m, () => allow);
  });
  return [TOML.stringify(settings), ...sections].join('\n');
}
export function portError(value: string): string {
  if (!/^\d+(-\d+)?$/.test(value)) return '格式应为 8080 或 5200-5300';
  const [start, end = start] = value.split('-').map(Number);
  return start < 1 || end > 65535 || start > end ? '端口须为 1–65535，起点不能大于终点' : '';
}
export function portConflict(config: Config, value: string, extra: string[] = []): string {
  const error = portError(value);
  if (error) return error;
  const [start, end = start] = value.split('-').map(Number);
  if (config.protected_ports.some(p => start <= p && p <= end)) return '端口覆盖 SSH 保护端口';
  const groups: [string, string[]][] = Object.entries(config.rules).map(([name, rule]) => [name, rule.ports]);
  groups.push(['新规则', extra]);
  for (const [name, ports] of groups) for (const port of ports) {
    const [a, b = a] = port.split('-').map(Number);
    if (start <= b && a <= end) return `端口与规则“${name}”的 ${port} 重叠`;
  }
  return '';
}
export function addressError(value: string): string {
  if (value === '*') return '';
  const [ip, prefix, extra] = value.split('/');
  const v6 = ip.includes(':');
  let valid = false;
  if (v6) {
    try { valid = new URL(`http://[${ip}]/`).hostname.startsWith('['); } catch { /* Invalid IPv6. */ }
  } else {
    valid = /^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(ip) && ip.split('.').every(n => Number(n) <= 255);
  }
  if (!valid) return '请填写有效的 IPv4、IPv6、CIDR 或 *';
  if (extra !== undefined || prefix !== undefined && (!/^\d+$/.test(prefix) || Number(prefix) > (v6 ? 128 : 32))) return `CIDR 前缀须为 0–${v6 ? 128 : 32}`;
  return '';
}
function notedAddress(ip: string, note: string): AllowEntry {
  const error = addressError(ip);
  if (error || ip === '*') throw new Error(error || '添加 IP 不接受 *，请明确选择“全部允许”');
  if ([...note].length > 128 || /[\p{Cc}]/u.test(note)) throw new Error('备注最多 128 个字符，不能含控制字符');
  return note ? { ip, note } : ip;
}
export function createRule(config: Config, name: string, portsText: string, sources: string, access: string): { name: string; rule: Rule } {
  name = name.trim();
  if (!name || new TextEncoder().encode(name).length > 128 || /[\p{Cc}]/u.test(name)) throw new Error('规则名称不能为空、不能含控制字符，且不超过 128 字节');
  if (Object.hasOwn(config.rules, name)) throw new Error('规则名称已存在');
  if (Object.keys(config.rules).length >= 256) throw new Error('规则数不能超过 256');
  const ports = portsText.trim().split(/[\s,，]+/).filter(Boolean);
  if (!ports.length || ports.length > 256) throw new Error('请填写 1–256 个端口或范围');
  ports.forEach((port, index) => { const error = portConflict(config, port, ports.slice(0, index)); if (error) throw new Error(error); });
  let allow: AllowEntry[];
  if (access === 'public') allow = ['*'];
  else if (access === 'deny') allow = [];
  else if (access === 'restricted') {
    allow = sources.split(/\r?\n/).map(line => line.trim()).filter(Boolean).map(line => {
      const [ip, ...note] = line.split(/[ \t]+/);
      return notedAddress(ip, note.join(' '));
    });
    if (!allow.length) throw new Error('白名单模式至少填写一个 IP/CIDR；拒绝全部请显式选择');
    if (allow.length > 4096) throw new Error('IP 数量不能超过 4096');
    if (new Set(allow.map(allowIp)).size !== allow.length) throw new Error('白名单含重复 IP');
  } else throw new Error('请选择有效的访问策略');
  return { name, rule: { enabled: true, ports, allow } };
}
export function appendIp(rule: Rule, ip: string, note: string): Rule {
  ip = ip.trim(); note = note.trim();
  const entry = notedAddress(ip, note);
  if (rule.allow.some(item => allowIp(item) === ip)) throw new Error('该 IP 已存在，请在规则中直接编辑备注');
  const allow = rule.allow.filter(item => allowIp(item) !== '*');
  if (allow.length >= 4096) throw new Error('IP 数量不能超过 4096');
  return { ...rule, allow: [...allow, entry] };
}
export function matchesRule(name: string, rule: Rule, query: string): boolean {
  const fields = [name, ...rule.ports, ...rule.allow.flatMap(entry => [allowIp(entry), allowNote(entry)])];
  return fields.some(field => field.toLowerCase().includes(query.trim().toLowerCase()));
}
export function normalizeIp(ip: string): string {
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}
