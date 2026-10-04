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
export function normalizeIp(ip: string): string {
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}
