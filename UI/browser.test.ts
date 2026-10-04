import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildSync } from 'esbuild';
import { Window, type HTMLElement, type HTMLInputElement, type HTMLButtonElement, type HTMLTextAreaElement } from 'happy-dom';
import { parseConfig } from './policy.js';

const script = buildSync({ entryPoints: ['src/main.ts'], bundle: true, write: false, format: 'iife', loader: { '.css': 'empty' } }).outputFiles[0].text;
const initial = 'protected_ports=[22]\n[rules.home]\nports=["8080"]\nallow=[{ip="192.0.2.1",note="家里"}]\n[rules.office]\nports=["9000"]\nallow=["198.51.100.10"]';
async function waitFor(check: () => boolean) {
  for (let i = 0; i < 200; i++) { if (check()) return; await new Promise(resolve => setTimeout(resolve, 5)); }
  assert.ok(check(), 'UI did not reach the expected state');
}
async function page(cached: string | null = null, text = initial) {
  const window = new Window({ url: 'http://localhost:7500' });
  window.document.body.innerHTML = '<div id="app"></div>';
  if (cached) window.sessionStorage.setItem('portguard-draft', cached);
  const state = { text, revision: text === initial ? 'initial' : 'external', expired: false, saved: 0, beforeSave: async () => {} };
  window.fetch = async (input, init) => {
    const endpoint = String(input);
    const data = init?.body ? JSON.parse(String(init.body)) : {};
    let result: unknown = {}, status = 200;
    if (endpoint === '/api/login') { state.expired = false; result = { username: 'admin', mustChangePassword: false }; }
    else if (state.expired && endpoint.startsWith('/api/')) status = 401;
    else if (endpoint === '/api/session') result = { username: 'admin', mustChangePassword: false };
    else if (endpoint === '/api/config') result = { text: state.text, config: parseConfig(state.text), revision: state.revision, path: '/etc/test-firewall.toml' };
    else if (endpoint === '/api/save') {
      await state.beforeSave();
      if (data.revision !== state.revision) { status = 409; result = { error: '配置已被修改' }; }
      else { state.text = data.text; state.revision += '-saved'; state.saved++; result = { revision: state.revision }; }
    } else if (endpoint === '/api/watch') result = { state: 'waiting', message: '等待 watch 热载', appliedAt: null };
    else if (endpoint === '/api/ip') result = { ip: '203.0.113.25' };
    else if (endpoint.startsWith('https://')) result = { ip: '2001:db8::1' };
    return new window.Response(JSON.stringify(result), { status, headers: { 'Content-Type': 'application/json' } });
  };
  const get = (id: string) => window.document.getElementById(id)! as HTMLElement;
  const input = (id: string, value: string) => { const node = get(id) as unknown as HTMLInputElement; node.value = value; node.dispatchEvent(new window.Event('input', { bubbles: true })); };
  const click = (id: string) => (get(id) as unknown as HTMLButtonElement).click();
  window.eval(script);
  await waitFor(() => !!get('path').textContent && !(get('console') as unknown as HTMLElement).inert);
  return { window, state, get, input, click, close: async () => { await window.happyDOM.abort(); window.close(); } };
}

test('刷新恢复会话，按备注/IP 搜索，检测完成后可加入当前 IP', async t => {
  const p = await page(); t.after(p.close);
  assert.equal(p.get('login-screen').hidden, true);
  assert.doesNotMatch(p.get('login-screen').textContent!, /123456/);
  assert.equal((p.get('pass') as unknown as HTMLInputElement).type, 'password');
  assert.equal((p.get('save') as unknown as HTMLButtonElement).disabled, true);
  p.input('filter', '家里'); assert.equal(p.window.document.querySelectorAll('.rule-item').length, 1);
  p.input('filter', '198.51.100'); assert.equal(p.window.document.querySelector('.rule-item strong')?.textContent, 'office');
  p.input('filter', '');
  await waitFor(() => !(p.get('add-v4') as unknown as HTMLButtonElement).disabled);
  p.click('add-v4'); await waitFor(() => p.window.document.querySelectorAll('[data-address]').length === 2);
  assert.equal((p.get('address-1') as unknown as HTMLInputElement).value, '203.0.113.25');
});

test('模式切换保留未保存备注，重命名预填名称', async t => {
  const p = await page(); t.after(p.close);
  const note = p.window.document.querySelector<HTMLInputElement>('[aria-label="来源备注"]')!;
  note.value = '家里备用线路'; note.dispatchEvent(new p.window.Event('input'));
  p.click('mode'); await waitFor(() => !!p.get('raw'));
  assert.match((p.get('raw') as unknown as HTMLTextAreaElement).value, /家里备用线路/);
  p.click('mode'); await waitFor(() => !!p.get('address-0'));
  assert.equal(p.window.document.querySelector<HTMLInputElement>('[aria-label="来源备注"]')!.value, '家里备用线路');
  await waitFor(() => !(p.get('console') as unknown as HTMLElement).inert);
  p.click('mode'); await waitFor(() => !!p.get('raw'));
  p.input('raw', '# 保留草稿注释\n' + (p.get('raw') as unknown as HTMLTextAreaElement).value);
  p.click('mode'); await waitFor(() => !!p.get('address-0') && !(p.get('console') as unknown as HTMLElement).inert);
  p.click('mode'); await waitFor(() => !!p.get('raw') && !(p.get('console') as unknown as HTMLElement).inert);
  assert.match((p.get('raw') as unknown as HTMLTextAreaElement).value, /保留草稿注释/);
  p.click('mode'); await waitFor(() => !!p.get('address-0') && !(p.get('console') as unknown as HTMLElement).inert);
  p.click('rename'); await waitFor(() => p.get('modal').hasAttribute('open'));
  assert.equal((p.get('modal-input') as unknown as HTMLInputElement).value, 'home');
  p.click('modal-cancel');
});

test('保存自动添加输入框内容，请求期间禁用编辑，只报告保存而非已生效', async t => {
  const p = await page(); t.after(p.close);
  let release!: () => void;
  p.state.beforeSave = () => new Promise<void>(resolve => { release = resolve; });
  p.input('allow-input', '203.0.113.8'); p.click('save');
  await waitFor(() => !!release);
  assert.equal((p.get('console') as unknown as HTMLElement).inert, true);
  assert.equal((p.get('save') as unknown as HTMLButtonElement).disabled, true);
  release(); await waitFor(() => p.state.saved === 1 && !(p.get('console') as unknown as HTMLElement).inert);
  assert.match(p.state.text, /203\.0\.113\.8/);
  assert.equal((p.get('save') as unknown as HTMLButtonElement).disabled, true);
  assert.match(p.get('watch-status').textContent!, /等待/);
  // Subsequent edits must still use the live config, not stale DOM closures.
  p.state.beforeSave = async () => {};
  p.input('address-0', '192.0.2.77'); p.click('save');
  await waitFor(() => p.state.saved === 2);
  assert.match(p.state.text, /192\.0\.2\.77/);
});

test('非法 IP/端口不保存，地址修改保留备注', async t => {
  const p = await page(); t.after(p.close);
  p.input('address-0', '999.1.2.3'); p.click('save');
  await waitFor(() => !(p.get('console') as unknown as HTMLElement).inert);
  assert.equal(p.state.saved, 0); assert.equal(p.get('address-0').getAttribute('aria-invalid'), 'true');
  p.input('address-0', '192.0.2.8');
  p.input('port-input', '65536'); p.click('save');
  await waitFor(() => !(p.get('console') as unknown as HTMLElement).inert);
  assert.equal(p.state.saved, 0);
  p.input('port-input', ''); p.click('save');
  await waitFor(() => p.state.saved === 1);
  assert.match(p.state.text, /ip = "192\.0\.2\.8", note = "家里"/);
});

test('危险来源替换需确认，可以撤销并恢复 IP 备注', async t => {
  const p = await page(); t.after(p.close);
  p.click('allow-any'); await waitFor(() => p.get('modal').hasAttribute('open'));
  p.click('modal-cancel'); await waitFor(() => !(p.get('console') as unknown as HTMLElement).inert);
  assert.equal((p.get('address-0') as unknown as HTMLInputElement).value, '192.0.2.1');
  p.click('allow-any'); await waitFor(() => p.get('modal').hasAttribute('open'));
  p.window.document.getElementById('modal-form')!.dispatchEvent(new p.window.Event('submit', { cancelable: true }));
  await waitFor(() => (p.get('address-0') as unknown as HTMLInputElement).value === '*' && !(p.get('console') as unknown as HTMLElement).inert);
  p.click('undo'); await waitFor(() => (p.get('address-0') as unknown as HTMLInputElement).value === '192.0.2.1');
  assert.equal(p.window.document.querySelector<HTMLInputElement>('[aria-label="来源备注"]')!.value, '家里');
});

test('刷新恢复待输入草稿，磁盘冲突时不覆盖，离开页面有提醒', async t => {
  const p = await page(); t.after(p.close);
  p.input('allow-input', '203.0.113.66');
  const leave = new p.window.Event('beforeunload', { cancelable: true });
  p.window.dispatchEvent(leave); assert.equal(leave.defaultPrevented, true);
  const cached = p.window.sessionStorage.getItem('portguard-draft');
  const restored = await page(cached); t.after(restored.close);
  assert.equal((restored.get('allow-input') as unknown as HTMLInputElement).value, '203.0.113.66');
  const conflict = await page(cached, initial.replace('8080', '8081')); t.after(conflict.close);
  assert.match(conflict.get('draft-hint').textContent!, /磁盘配置已变化/);
  conflict.click('save'); await waitFor(() => !(conflict.get('console') as unknown as HTMLElement).inert);
  assert.equal(conflict.state.saved, 0); assert.match(conflict.state.text, /8081/);
});

test('菜单分别添加完整规则或 IP；新规则一次填写并保存', async t => {
  const p = await page(); t.after(p.close);
  p.window.document.querySelector<HTMLButtonElement>('[data-view="add-rule"]')!.click();
  await waitFor(() => !p.get('view-add-rule').hidden && !(p.get('console') as unknown as HTMLElement).inert);
  p.input('create-name', 'NAS'); p.input('create-ports', '5200-5300, 33890');
  p.input('create-sources', '203.0.113.25 家里\n2001:db8::/64 办公室');
  p.click('create-rule-save'); await waitFor(() => p.state.saved === 1);
  const c = parseConfig(p.state.text);
  assert.deepEqual(c.rules.NAS.ports, ['5200-5300', '33890']);
  assert.deepEqual(c.rules.NAS.allow[0], { ip: '203.0.113.25', note: '家里' });
  assert.deepEqual(c.rules.home, parseConfig(initial).rules.home);
});

test('添加规则阻止冲突端口，不会创建空白名单或半成品规则', async t => {
  const p = await page(); t.after(p.close);
  p.window.document.querySelector<HTMLButtonElement>('[data-view="add-rule"]')!.click();
  await waitFor(() => !(p.get('console') as unknown as HTMLElement).inert);
  p.input('create-name', 'NAS'); p.input('create-ports', '22'); p.input('create-sources', '192.0.2.8');
  p.click('create-rule-save'); await waitFor(() => !!p.get('create-rule-error').textContent);
  assert.match(p.get('create-rule-error').textContent!, /SSH/);
  assert.equal(p.state.saved, 0); assert.equal(p.window.document.querySelectorAll('.rule-item').length, 2);
  p.input('create-ports', '5200'); p.input('create-sources', ''); p.click('create-rule-save');
  await waitFor(() => !(p.get('console') as unknown as HTMLElement).inert);
  assert.equal(p.state.saved, 0); assert.equal(p.window.document.querySelectorAll('.rule-item').length, 2);
});

test('添加 IP 选择已有规则，保留端口和关闭状态，备注一起保存', async t => {
  const p = await page(null, initial.replace('[rules.office]', '[rules.office]\nenabled=false')); t.after(p.close);
  p.window.document.querySelector<HTMLButtonElement>('[data-view="add-ip"]')!.click();
  await waitFor(() => !p.get('view-add-ip').hidden && !(p.get('console') as unknown as HTMLElement).inert);
  p.input('create-target', 'office'); p.input('create-ip', '203.0.113.88'); p.input('create-note', '办公室备用');
  assert.match(p.get('create-target-hint').textContent!, /已关闭/);
  p.click('create-ip-save'); await waitFor(() => p.state.saved === 1);
  const c = parseConfig(p.state.text);
  assert.equal(c.rules.office.enabled, false); assert.deepEqual(c.rules.office.ports, ['9000']);
  assert.deepEqual(c.rules.office.allow[1], { ip: '203.0.113.88', note: '办公室备用' });
  assert.equal(c.rules.home.allow.length, 1);
});

test('添加规则表单刷新后保留，空配置添加 IP 引导先建规则', async t => {
  const p = await page(); t.after(p.close);
  p.window.document.querySelector<HTMLButtonElement>('[data-view="add-rule"]')!.click();
  await waitFor(() => !p.get('view-add-rule').hidden && !(p.get('console') as unknown as HTMLElement).inert);
  p.input('create-name', '待完成'); p.input('create-ports', '5200'); p.input('create-sources', '192.0.2.8 家里');
  const restored = await page(p.window.sessionStorage.getItem('portguard-draft')); t.after(restored.close);
  assert.equal(restored.get('view-add-rule').hidden, false);
  assert.equal((restored.get('create-name') as unknown as HTMLInputElement).value, '待完成');
  restored.click('create-rule-save'); await waitFor(() => restored.state.saved === 1);
  const empty = await page(null, 'protected_ports=[22]\n[rules]'); t.after(empty.close);
  empty.window.document.querySelector<HTMLButtonElement>('[data-view="add-ip"]')!.click();
  await waitFor(() => !empty.get('view-add-rule').hidden);
  assert.match(empty.get('toasts').textContent!, /先添加/);
});

test('菜单可自由切换并保留表单，保存 IP 不隐式创建另一条未完成规则', async t => {
  const p = await page(); t.after(p.close);
  p.window.document.querySelector<HTMLButtonElement>('[data-view="add-rule"]')!.click();
  await waitFor(() => !p.get('view-add-rule').hidden && !(p.get('console') as unknown as HTMLElement).inert);
  p.input('create-name', 'NAS'); p.input('create-ports', '5200');
  p.window.document.querySelector<HTMLButtonElement>('[data-view="add-ip"]')!.click();
  await waitFor(() => !p.get('view-add-ip').hidden && !(p.get('console') as unknown as HTMLElement).inert);
  p.input('create-target', 'office'); p.input('create-ip', '192.0.2.8'); p.input('create-note', '备用');
  p.click('create-ip-save'); await waitFor(() => p.state.saved === 1 && !(p.get('console') as unknown as HTMLElement).inert);
  assert.equal(Object.hasOwn(parseConfig(p.state.text).rules, 'NAS'), false);
  assert.equal((p.get('create-name') as unknown as HTMLInputElement).value, 'NAS');
  assert.match(p.window.sessionStorage.getItem('portguard-draft')!, /NAS/);
  p.window.document.querySelector<HTMLButtonElement>('[data-view="add-rule"]')!.click();
  await waitFor(() => !p.get('view-add-rule').hidden && !(p.get('console') as unknown as HTMLElement).inert);
  p.input('create-sources', '203.0.113.25 家里'); p.click('create-rule-save');
  await waitFor(() => p.state.saved === 2);
  assert.deepEqual(parseConfig(p.state.text).rules.NAS.ports, ['5200']);
});

test('给全部允许的规则添加 IP，必须确认改为白名单，取消不动配置', async t => {
  const p = await page(null, initial.replace('[{ip="192.0.2.1",note="家里"}]', '["*"]')); t.after(p.close);
  p.window.document.querySelector<HTMLButtonElement>('[data-view="add-ip"]')!.click();
  await waitFor(() => !p.get('view-add-ip').hidden && !(p.get('console') as unknown as HTMLElement).inert);
  p.input('create-ip', '192.0.2.8'); p.input('create-note', '家里'); p.click('create-ip-save');
  await waitFor(() => p.get('modal').hasAttribute('open'));
  p.click('modal-cancel'); await waitFor(() => !(p.get('console') as unknown as HTMLElement).inert);
  assert.equal(p.state.saved, 0);
  assert.deepEqual(parseConfig(p.state.text).rules.home.allow, ['*']);
  assert.equal((p.get('create-ip') as unknown as HTMLInputElement).value, '192.0.2.8');
});

test('会话过期不刷新或丢稿，重新登录恢复草稿', async t => {
  const p = await page(); t.after(p.close);
  p.input('allow-input', '203.0.113.9'); p.state.expired = true; p.click('save');
  await waitFor(() => !p.get('login-screen').hidden && !(p.get('login-screen') as unknown as HTMLElement).inert);
  assert.match(p.window.sessionStorage.getItem('portguard-draft')!, /203\.0\.113\.9/);
  p.input('pass', 'secret'); p.get('login-form').dispatchEvent(new p.window.Event('submit', { cancelable: true }));
  await waitFor(() => !p.get('console').hidden && !!p.get('address-1') && !(p.get('console') as unknown as HTMLElement).inert);
  assert.equal((p.get('address-1') as unknown as HTMLInputElement).value, '203.0.113.9');
  assert.equal((p.get('save') as unknown as HTMLButtonElement).disabled, false);
});
