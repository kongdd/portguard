import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { readJson, withRequestErrors } from './http.js';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseConfig, serializeConfig, normalizeIp, allowIp, allowNote, setAllowNote } from './policy.js';
import { authenticate, defaultAuth, hashPassword, loadAuth, saveAuth, verifyPassword, DEFAULT_PASSWORD, DEFAULT_USER } from './auth.js';
test('配置默认值及中文、IPv6、空白名单往返', () => {
  const c = parseConfig('protected_ports=[22]\n[rules."办公室"]\nports=["5200-5300"]\nallow=["2001:db8::/64"]\n[rules.deny]\nports=["8080"]\nallow=[]');
  assert.equal(c.enabled, true);
  assert.equal(c.rules['办公室'].enabled, true);
  assert.deepEqual(parseConfig(serializeConfig(c)), c);
});
test('恶意名称被作为 TOML 字符串而不是表注入', () => {
  const c = parseConfig('protected_ports=[22]\n[rules]');
  const name = 'x"]\nprotected_ports=[]';
  c.rules[name] = { enabled: true, ports: ['8080'], allow: ['*'] };
  assert.deepEqual(parseConfig(serializeConfig(c)), c);
});
test('IP 备注和地址相邻，混合旧字符串格式可往返', () => {
  const c = parseConfig(`protected_ports=[22]\n[rules.home]\nports=["8080"]\nallow=[{ ip="192.0.2.1", note="家里" }, "198.51.100.10", { ip="2001:db8::/64", note="办公室 IPv6" }]`);
  const rule = c.rules.home;
  assert.equal(allowIp(rule.allow[0]), '192.0.2.1');
  assert.equal(allowNote(rule.allow[0]), '家里');
  assert.equal(allowNote(rule.allow[1]), '');
  assert.match(serializeConfig(c), /\{ ip = "192\.0\.2\.1", note = "家里" \}/);
  assert.deepEqual(parseConfig(serializeConfig(c)), c);
  setAllowNote(rule, 1, '<script>仅是备注</script>');
  assert.deepEqual(rule.allow[1], { ip: '198.51.100.10', note: '<script>仅是备注</script>' });
  assert.equal(serializeConfig(c).includes('[[rules.home.allow]]'), false);
  assert.deepEqual(parseConfig(serializeConfig(c)), c);
  setAllowNote(rule, 0, '');
  assert.equal(rule.allow[0], '192.0.2.1');
  rule.allow.splice(1, 1);
  assert.equal(allowNote(rule.allow[1]), '办公室 IPv6');
});

test('备注引号和 TOML 表内容不会注入配置，未知字段保留给 CLI 拒绝', () => {
  const c = parseConfig('protected_ports=[22]\n[rules.a]\nports=["8080"]\nallow=["192.0.2.1"]');
  setAllowNote(c.rules.a, 0, '家里 "主线" \\ [rules.evil]');
  assert.deepEqual(parseConfig(serializeConfig(c)), c);
  Object.assign(c.rules.a.allow[0], { typo: true });
  assert.deepEqual(parseConfig(serializeConfig(c)), c);
});

test('只规范 IPv4 mapped 地址', () => {
  assert.equal(normalizeIp('::ffff:203.0.113.1'), '203.0.113.1');
  assert.equal(normalizeIp('2001:db8::1'), '2001:db8::1');
});
test('默认账号可登录，修改密码后旧密码失效', async () => {
  const auth = defaultAuth();
  assert.equal(authenticate(auth, DEFAULT_USER, DEFAULT_PASSWORD)?.changed, false);
  assert.equal(authenticate(auth, 'admin', 'wrong'), undefined);
  auth.users[0] = { ...auth.users[0], ...hashPassword('new-secret'), changed: true };
  const dir = await mkdtemp(join(tmpdir(), 'portguard-ui-'));
  const path = join(dir, 'ui-auth.json');
  await saveAuth(path, auth);
  const loaded = await loadAuth(path);
  assert.equal(verifyPassword('new-secret', loaded.users[0]), true);
  assert.equal(authenticate(loaded, DEFAULT_USER, DEFAULT_PASSWORD), undefined);
  assert.equal((await readFile(path, 'utf8')).includes(DEFAULT_PASSWORD), false);
});

test('请求解析和异步异常被捕获，后续请求仍可处理', async () => {
  const server = createServer(withRequestErrors(async (req, res) => {
    if (req.url === '/api/password') throw new Error('账号文件写入失败');
    const data = await readJson(req);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(data));
  }));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  // Use the HTTP client directly so local tests do not inherit proxy settings.
  const post = (path: string, body: string) => new Promise<{ status: number | undefined; data: Record<string, unknown> }>((resolve, reject) => {
    const req = request(url + path, { method: 'POST' }, res => {
      const chunks: Buffer[] = [];
      res.on('data', chunk => chunks.push(chunk));
      res.on('error', reject);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(Buffer.concat(chunks).toString()) }); }
        catch (error) { reject(error); }
      });
    });
    req.on('error', reject);
    req.end(body);
  });
  try {
    for (const text of ['{', 'null', '[]', '"string"']) {
      const res = await post('/api/login', text);
      assert.equal(res.status, 400);
      assert.equal(typeof res.data.error, 'string');
    }
    const oversized = await post('/api/login', 'x'.repeat(1024 * 1024 + 1));
    assert.equal(oversized.status, 413);
    const failed = await post('/api/password', '{}');
    assert.equal(failed.status, 400);
    assert.equal(failed.data.error, '账号文件写入失败');
    const ok = await post('/api/login', '{"username":"admin"}');
    assert.equal(ok.status, 200);
    assert.deepEqual(ok.data, { username: 'admin' });
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
      server.closeAllConnections();
    });
  }
});
