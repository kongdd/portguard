import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { readFile, writeFile, rename, unlink, realpath, stat } from 'node:fs/promises';
import { resolve, dirname, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { parseConfig, serializeConfig, normalizeIp, type Config } from './policy.js';
import { readJson as body, withRequestErrors } from './http.js';
import { readWatchStatus } from './watch.js';
import { authenticate, hashPassword, loadAuth, saveAuth, validUsername, type AuthFile, type User } from './auth.js';

const exec = promisify(execFile);
const configPath = await realpath(process.env.PORTGUARD_CONFIG ?? '../firewall.toml');
const authPath = process.env.PORTGUARD_AUTH_FILE ?? configPath + '.ui-auth.json';
const binary = process.env.PORTGUARD_BIN ?? '/usr/local/bin/portguard';
const port = Number(process.env.PORTGUARD_UI_PORT ?? 7500);
const bind = process.env.PORTGUARD_UI_BIND ?? '0.0.0.0';
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('无效服务端口');
const root = resolve(dirname(fileURLToPath(import.meta.url)), '../dist');
const revision = (text: string) => createHash('sha256').update(text).digest('hex');
let auth = await loadAuth(authPath);
let busy = false;
const sessions = new Map<string, { username: string; expires: number }>();
const failures = new Map<string, { count: number; until: number }>();

async function cli(command: string, path = configPath, extra: string[] = []) {
  const { stdout, stderr } = await exec(binary, ['-c', path, command, ...extra], {
    timeout: 30_000, maxBuffer: 2 * 1024 * 1024,
  });
  return stdout + stderr;
}
function reply(res: ServerResponse, code: number, data: unknown, extra: Record<string, string> = {}) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', ...extra });
  res.end(JSON.stringify(data));
}
function sessionToken(req: IncomingMessage): string {
  const item = (req.headers.cookie ?? '').split(';').map(s => s.trim()).find(s => s.startsWith('portguard_session='));
  return item?.slice('portguard_session='.length) ?? '';
}
function currentUser(req: IncomingMessage): string | undefined {
  const token = sessionToken(req);
  const session = sessions.get(token);
  if (!session || session.expires < Date.now()) { sessions.delete(token); return; }
  return session.username;
}
function setSession(res: ServerResponse, username: string) {
  const token = randomBytes(32).toString('base64url');
  sessions.set(token, { username, expires: Date.now() + 12 * 60 * 60 * 1000 });
  return 'portguard_session=' + token + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200';
}
function sameOrigin(req: IncomingMessage): boolean {
  const host = req.headers.host;
  if (!host || host.length > 255 || /[\s/]/.test(host)) return false;
  if (!req.headers.origin) return true;
  try { return new URL(req.headers.origin).host === host; } catch { return false; }
}
function limited(ip: string): boolean {
  const item = failures.get(ip);
  return !!item && item.until > Date.now();
}
function noteFailure(ip: string) {
  const item = failures.get(ip) ?? { count: 0, until: 0 };
  item.count += 1;
  if (item.count >= 8) { item.until = Date.now() + 60_000; item.count = 0; }
  failures.set(ip, item);
}
createServer(withRequestErrors(async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'; connect-src 'self' https://api.ipify.org https://api6.ipify.org; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  if (!sameOrigin(req)) { reply(res, 403, { error: '禁止跨站请求' }); return; }
  const url = new URL(req.url ?? '/', 'http://localhost');
  if (!url.pathname.startsWith('/api/')) {
    if (req.method !== 'GET') { reply(res, 405, { error: 'Method not allowed' }); return; }
    const path = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    if (!/^(index\.html|assets\/[a-zA-Z0-9_.-]+)$/.test(path)) { reply(res, 404, {}); return; }
    try {
      const mime: Record<string, string> = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' };
      res.setHeader('Content-Type', mime[extname(path)] ?? 'application/octet-stream');
      res.end(await readFile(resolve(root, path)));
    } catch { reply(res, 404, { error: '请先构建 UI' }); }
    return;
  }
  const ip = normalizeIp(req.socket.remoteAddress ?? '');
  if (req.method === 'POST' && url.pathname === '/api/login') {
    if (limited(ip)) { reply(res, 429, { error: '登录失败过多，请一分钟后再试' }); return; }
    const data = await body(req);
    const username = String(data.username ?? '');
    const password = String(data.password ?? '');
    const user = password.length <= 128 && validUsername(username) ? authenticate(auth, username, password) : undefined;
    if (!user) { noteFailure(ip); reply(res, 401, { error: '用户名或密码错误' }); return; }
    failures.delete(ip);
    reply(res, 200, { username: user.username, mustChangePassword: !user.changed }, { 'Set-Cookie': setSession(res, user.username) });
    return;
  }
  if (req.method === 'POST' && url.pathname === '/api/logout') {
    sessions.delete(sessionToken(req));
    reply(res, 200, { ok: true }, { 'Set-Cookie': 'portguard_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
    return;
  }
  const username = currentUser(req);
  if (!username) { reply(res, 401, { error: '请先登录' }); return; }
  const user = auth.users.find(u => u.username === username);
  if (!user) { reply(res, 401, { error: '账号已失效，请重新登录' }); return; }
  if (req.method === 'GET' && url.pathname === '/api/session') {
    reply(res, 200, { username, mustChangePassword: !user.changed }); return;
  }
  if (req.method === 'GET' && url.pathname === '/api/ip') {
    reply(res, 200, { ip }); return;
  }
  if (req.method === 'GET' && url.pathname === '/api/watch') {
    reply(res, 200, await readWatchStatus(configPath)); return;
  }
  if (req.method === 'POST' && url.pathname === '/api/password') {
    const data = await body(req);
    const next = String(data.password ?? '');
    if (!authenticate(auth, username, String(data.current ?? '')) || next.length < 6 || next.length > 128) {
      reply(res, 400, { error: '当前密码错误，或新密码长度不在 6–128 之间' }); return;
    }
    const updated: User = { ...user, ...hashPassword(next), changed: true };
    const nextAuth: AuthFile = { users: auth.users.map(u => u.username === username ? updated : u) };
    await saveAuth(authPath, nextAuth);
    auth = nextAuth;
    for (const [token, session] of sessions) if (session.username === username) sessions.delete(token);
    reply(res, 200, { ok: true }, { 'Set-Cookie': setSession(res, username) });
    return;
  }
  if (busy) { reply(res, 409, { error: '操作进行中，请稍后重试' }); return; }
  busy = true;
  try {
    if (req.method === 'GET' && url.pathname === '/api/config') {
      const text = await readFile(configPath, 'utf8');
      let config: Config | null = null;
      try { config = parseConfig(text); } catch {}
      reply(res, 200, { text, config, revision: revision(text), path: configPath, peerIp: ip });
    } else if (req.method === 'GET' && url.pathname === '/api/status') {
      reply(res, 200, { output: await cli('status') });
    } else if (req.method === 'POST' && ['/api/check', '/api/save'].includes(url.pathname)) {
      const data = await body(req);
      const original = await readFile(configPath, 'utf8');
      if (data.revision !== revision(original)) { reply(res, 409, { error: '配置已被修改，请重新加载后编辑' }); return; }
      const text = typeof data.text === 'string' ? data.text : serializeConfig(data.config as Config);
      const temp = configPath + '.tmp.ui-' + randomBytes(8).toString('hex');
      try {
        await writeFile(temp, text, { mode: 0o600, flag: 'wx' });
        const output = await cli('check', temp, ['--config-only']);
        if (url.pathname === '/api/save') {
          if (revision(await readFile(configPath, 'utf8')) !== data.revision) throw new Error('配置已被外部修改，请重新加载');
          const info = await stat(configPath);
          const { chmod, chown } = await import('node:fs/promises');
          await chown(temp, info.uid, info.gid);
          await chmod(temp, info.mode & 0o777);
          await rename(temp, configPath);
        }
        reply(res, 200, { output, revision: revision(url.pathname === '/api/save' ? text : original) });
      } finally { await unlink(temp).catch(() => {}); }
    } else reply(res, 404, { error: '未知接口' });
  } finally { busy = false; }
})).listen(port, bind, () => {
  console.log('Portguard UI: http://' + bind + ':' + port);
  if (auth.users.some(u => !u.changed)) console.warn('仍在使用初始密码 admin / 123456，登录后请立即修改');
});
