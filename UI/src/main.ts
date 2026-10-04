import './style.css';
import { allowIp, allowNote, setAllowNote, parseConfig, serializeConfig, portError, addressError, matchesRule, type Config, type Rule } from '../policy';
import type { WatchStatus } from '../watch';

type View = 'rules' | 'account';
interface Draft { username: string; path: string; revision: string; loadedText: string; savedSnap: string; rawSnap: string; config: Config | null; raw: string; rawMode: boolean; selected: string; inputs: Record<string, string> }
const el = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;
const escape = (s: string) => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
let revision = '', loadedText = '', savedSnap = '', rawSnap = '', path = '', raw = '', rawMode = false;
let config: Config | null = null, selected = '', filter = '', view: View = 'rules';
let busy = false, loggedIn = false, username = '', publicIp = '', publicV6 = '';
let undo: (() => void) | null = null;
const draftKey = 'portguard-draft';
const app = document.querySelector<HTMLDivElement>('#app')!;
app.innerHTML = `
<div class="progress"></div>
<section class="login-screen" id="login-screen">
  <div class="login-copy"><div class="mark" aria-hidden="true"><i></i><i></i><i></i></div><h1>端口只对你打开。</h1><p>这里只修改 firewall.toml。规则由 portguard apply --watch 读取文件后热载。</p></div>
  <form class="login-card" id="login-form">
    <h2>登录控制台</h2><p class="sub">防火墙规则</p>
    <label>用户名<input id="user" required autocomplete="username" value="admin"></label>
    <label>密码<input id="pass" type="password" required autocomplete="current-password"></label>
    <button>进入</button><p class="note">初始账号 admin / 123456。这是明文 HTTP，登录后请马上改密码。</p>
  </form>
</section>
<div class="console" id="console" hidden>
  <aside class="side"><div class="lockup"><div class="mark" aria-hidden="true"><i></i><i></i><i></i></div><div><strong>PORTGUARD</strong><span id="who"></span></div></div>
    <nav class="nav"><button type="button" data-view="rules">规则</button><button type="button" data-view="account">账号</button></nav>
  </aside>
  <div class="workspace">
    <header class="top"><div class="top-title"><h2 id="title">规则</h2><span class="dirty" id="dirty" hidden>未保存</span></div><div class="top-meta"><span class="path" id="path"></span></div>
      <div class="actions"><button class="ghost" id="undo" type="button" disabled>撤销</button><button class="ghost" id="reload" type="button">重新加载</button><button class="ghost" id="mode" type="button">TOML</button><button class="primary" id="save" type="button" disabled>保存配置</button></div>
    </header>
    <div class="banner" id="banner" hidden><span>仍在使用初始密码。</span><button class="ghost" id="goto-password" type="button">去修改</button></div>
    <p class="draft-hint" id="draft-hint" hidden></p>
    <div class="watch-status" id="watch-status" role="status">正在读取热载状态…</div>
    <div class="ipbar"><div><span>当前 IPv4 · 连接地址或出口查询</span><strong id="ip4">检测中</strong></div><div><span>当前 IPv6 · 连接地址或出口查询</span><strong id="ip6">检测中</strong></div><button class="ghost" id="detect" type="button">重新检测</button></div>
    <section class="view" id="view-rules"></section>
    <section class="view" id="view-account" hidden><form class="account" id="pw-form"><h3>修改密码</h3><p class="muted">至少 6 位。修改后其他会话失效，当前浏览器保持登录。</p>
      <label>当前密码<input id="cur" type="password" required autocomplete="current-password"></label><label>新密码<input id="next" type="password" required minlength="6" maxlength="128" autocomplete="new-password"></label>
      <div class="form-actions"><button class="primary" type="submit">更新密码</button><button class="ghost" id="logout" type="button">退出登录</button></div>
    </form></section>
  </div>
</div>
<dialog class="modal" id="modal" aria-labelledby="modal-title"><form id="modal-form"><h2 id="modal-title"></h2><p id="modal-body"></p><label id="modal-field" hidden>名称<input id="modal-input" autocomplete="off"></label><div class="actions"><button class="ghost" id="modal-cancel" type="button">取消</button><button id="modal-ok" type="submit">确认</button></div></form></dialog>
<div class="toasts" id="toasts" aria-live="polite"></div>`;

function toast(message: string, bad = false) {
  const node = document.createElement('div');
  node.className = 'toast' + (bad ? ' bad' : ''); node.textContent = message;
  el('toasts').append(node); setTimeout(() => node.remove(), bad ? 8000 : 3600);
}
function ask(title: string, body: string, ok = '确认', danger = false, field = false, initial = '') {
  const dialog = el<HTMLDialogElement>('modal');
  el('modal-title').textContent = title; el('modal-body').textContent = body;
  el('modal-field').hidden = !field; el<HTMLInputElement>('modal-input').value = initial;
  el('modal-ok').textContent = ok; el('modal-ok').className = danger ? 'danger' : 'primary';
  dialog.showModal();
  (field ? el('modal-input') : el('modal-cancel')).focus();
  return new Promise<string | null>(resolve => {
    const finish = (value: string | null) => { dialog.close(); cleanup(); resolve(value); };
    const submit = (event: Event) => { event.preventDefault(); finish(field ? el<HTMLInputElement>('modal-input').value.trim() : 'ok'); };
    const cancel = (event: Event) => { event.preventDefault(); finish(null); };
    el('modal-form').addEventListener('submit', submit);
    el('modal-cancel').addEventListener('click', cancel); dialog.addEventListener('cancel', cancel);
    function cleanup() {
      el('modal-form').removeEventListener('submit', submit);
      el('modal-cancel').removeEventListener('click', cancel); dialog.removeEventListener('cancel', cancel);
    }
  });
}
class LoginRequired extends Error {}
function showLogin() {
  const expired = loggedIn;
  loggedIn = false; el('login-screen').hidden = false; el('console').hidden = true;
  if (expired) toast('登录已过期，草稿已保留，请重新登录', true);
}
async function api(endpoint: string, data?: unknown) {
  const res = await fetch('/api/' + endpoint, { method: data === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: data === undefined ? undefined : JSON.stringify(data), signal: AbortSignal.timeout(45_000) });
  if (res.status === 401 && endpoint !== 'login') { showLogin(); throw new LoginRequired(); }
  const json = await res.json();
  if (!res.ok) throw new Error(json.error ?? '请求失败');
  return json;
}
async function task(fn: () => Promise<void>) {
  if (busy) return;
  busy = true; el('console').inert = true; el('login-screen').inert = true; document.body.classList.add('busy'); update();
  try { await fn(); } catch (e) { if (!(e instanceof LoginRequired)) toast((e as Error).message, true); }
  finally { busy = false; el('console').inert = false; el('login-screen').inert = false; document.body.classList.remove('busy'); update(); }
}
function pendingInputs(): Record<string, string> {
  const pending: Record<string, string> = {};
  if (rawMode) return pending;
  for (const id of ['protected-input', 'port-input', 'allow-input']) {
    const value = el<HTMLInputElement>(id)?.value.trim();
    if (value) pending[id] = value;
  }
  document.querySelectorAll<HTMLInputElement>('[data-address]').forEach(input => {
    if (config && input.value !== allowIp(config.rules[selected].allow[Number(input.dataset.address)])) pending[input.id] = input.value;
  });
  return pending;
}
function dirty() {
  if (!path) return false;
  const snapshot = JSON.stringify(config);
  return (rawMode ? raw !== loadedText : snapshot !== savedSnap || snapshot === rawSnap && raw !== loadedText) || Object.keys(pendingInputs()).length > 0;
}
function update() {
  const modified = dirty();
  el('dirty').hidden = !modified;
  el<HTMLButtonElement>('save').disabled = busy || !modified;
  el('save').textContent = busy ? '处理中…' : '保存配置';
  el('reload').textContent = modified ? '放弃修改' : '重新加载';
  el<HTMLButtonElement>('undo').disabled = busy || !undo;
  for (const [id, ip] of [['add-v4', publicIp], ['add-v6', publicV6]]) if (el(id)) el<HTMLButtonElement>(id).disabled = !ip;
  try {
    if (modified && path && username) sessionStorage.setItem(draftKey, JSON.stringify({ username, path, revision, loadedText, savedSnap, rawSnap, config, raw, rawMode, selected, inputs: pendingInputs() }));
    else if (loggedIn && path) sessionStorage.removeItem(draftKey);
  } catch { /* In-memory drafts and leave confirmation still work if browser storage is unavailable. */ }
}
function changed(keepUndo = false) {
  if (!keepUndo) { undo = null; el('undo').textContent = '撤销'; }
  if (!rawMode && el('rule-items')) {
    paintList();
    const rule = config?.rules[selected], pill = el('detail')?.querySelector('.pill');
    if (rule && pill) { const [label, kind] = policy(rule); pill.textContent = label; pill.className = 'pill ' + kind; }
  }
  update();
}
function offerUndo(label: string, action: () => void, focus = selected) {
  undo = () => { action(); if (config && Object.hasOwn(config.rules, focus)) selected = focus; };
  el('undo').textContent = '撤销' + label; changed(true);
}
function valid(input: HTMLInputElement, message: string, report = false) {
  input.setCustomValidity(message); input.setAttribute('aria-invalid', String(!!message)); input.title = message;
  if (message && report) input.reportValidity();
  return !message;
}
function nameValid(name: string) {
  if (!name || new TextEncoder().encode(name).length > 128 || /[\p{Cc}]/u.test(name)) { toast('名称不能为空、不能含控制字符，且不超过 128 字节', true); return false; }
  return true;
}
function policy(rule: Rule) {
  if (!config?.enabled || !rule.enabled) return ['未限制', 'muted'];
  if (!rule.allow.length) return ['拒绝全部', 'bad'];
  if (rule.allow.length === 1 && allowIp(rule.allow[0]) === '*') return ['全部来源', 'warn'];
  return [`${rule.allow.length} 个来源`, 'ok'];
}
function show(next: View) {
  view = next;
  for (const name of ['rules', 'account'] as View[]) el('view-' + name).hidden = name !== next;
  document.querySelectorAll<HTMLButtonElement>('.nav button').forEach(button => button.setAttribute('aria-current', button.dataset.view === next ? 'page' : 'false'));
  el('title').textContent = next === 'rules' ? '规则' : '账号'; update();
}
function chips(host: HTMLElement, items: string[], empty: string, remove: (index: number) => void) {
  host.replaceChildren();
  if (!items.length) { const span = document.createElement('span'); span.className = 'empty-chip'; span.textContent = empty; host.append(span); }
  items.forEach((item, index) => {
    const button = document.createElement('button'); button.type = 'button'; button.className = 'chip'; button.title = '移除 ' + item;
    button.innerHTML = `<span>${escape(item)}</span><span aria-hidden="true">×</span>`; button.onclick = () => remove(index); host.append(button);
  });
}
function portConflict(value: string): string {
  const error = portError(value);
  if (error || !config) return error;
  const [start, end = start] = value.split('-').map(Number);
  if (config.protected_ports.some(p => start <= p && p <= end)) return '端口覆盖 SSH 保护端口，不能添加';
  for (const [name, rule] of Object.entries(config.rules)) for (const port of rule.ports) {
    const [a, b = a] = port.split('-').map(Number);
    if (start <= b && a <= end) return `端口与规则“${name}”的 ${port} 重叠`;
  }
  return '';
}
function addProtected() {
  const input = el<HTMLInputElement>('protected-input'), value = input.value.trim();
  if (!valid(input, /^\d+$/.test(value) && Number(value) >= 1 && Number(value) <= 65535 ? '' : '保护端口须为 1–65535', true)) return false;
  if (!config!.protected_ports.includes(Number(value))) config!.protected_ports.push(Number(value));
  input.value = ''; paintProtected(); changed(); return true;
}
function addPort() {
  const input = el<HTMLInputElement>('port-input'), value = input.value.trim();
  if (!valid(input, portConflict(value), true)) return false;
  config!.rules[selected].ports.push(value); input.value = ''; paintPorts(); changed(); return true;
}
async function replaceAllow(next: string[], label: string) {
  const rule = config!.rules[selected];
  if (JSON.stringify(rule.allow) === JSON.stringify(next)) return true;
  if (rule.allow.length && !await ask(label, `${label === '全部来源' ? '任何来源都可访问。' : '所有来源都会被拒绝。'}现有 IP 和备注会被替换，保存后才生效。`, '替换', true)) return false;
  const previous = rule.allow;
  rule.allow = next; paintAllow(); paintList();
  offerUndo('来源切换', () => { rule.allow = previous; }); return true;
}
async function addAllow() {
  const input = el<HTMLInputElement>('allow-input'), value = input.value.trim();
  if (!valid(input, addressError(value), true)) return false;
  const rule = config!.rules[selected];
  if (value === '*') { if (!await replaceAllow(['*'], '全部来源')) return false; }
  else {
    if (rule.allow.some(entry => allowIp(entry) === value)) { valid(input, '该地址已存在', true); return false; }
    if (rule.allow.some(entry => allowIp(entry) === '*')) rule.allow = [];
    rule.allow.push(value); paintAllow(); paintList(); changed();
  }
  input.value = ''; update(); return true;
}
async function commitPending() {
  if (rawMode) return true;
  for (const input of Array.from(document.querySelectorAll<HTMLInputElement>('#view-rules input'))) if (!input.reportValidity()) return false;
  document.querySelectorAll<HTMLInputElement>('[data-address]').forEach(input => { input.value = input.value.trim(); });
  if (el<HTMLInputElement>('protected-input')?.value.trim() && !addProtected()) return false;
  if (el<HTMLInputElement>('port-input')?.value.trim() && !addPort()) return false;
  if (el<HTMLInputElement>('allow-input')?.value.trim() && !await addAllow()) return false;
  return true;
}
function readyToRedraw() {
  for (const input of Array.from(document.querySelectorAll<HTMLInputElement>('#view-rules input'))) if (!input.reportValidity()) return false;
  if (Object.keys(pendingInputs()).length) { toast('请先添加待输入内容，或清空后再删除', true); return false; }
  return true;
}
function paintProtected() {
  chips(el('protected-chips'), config!.protected_ports.map(String), '未设置', index => void task(async () => {
    if (!readyToRedraw()) return;
    if (!await ask('删除 SSH 保护端口', '移除保护不会自动关闭 SSH，但后续规则可能限制此端口。请确认实际 SSH 端口仍受保护。', '删除', true)) return;
    const [port] = config!.protected_ports.splice(index, 1); paintProtected();
    offerUndo('保护端口删除', () => { config!.protected_ports.splice(index, 0, port); });
  }));
}
function paintPorts() {
  const rule = config!.rules[selected];
  chips(el('port-chips'), rule.ports, '尚未添加端口', index => {
    if (!readyToRedraw()) return;
    const [port] = rule.ports.splice(index, 1); paintPorts(); paintList();
    offerUndo('端口删除', () => { rule.ports.splice(index, 0, port); });
  });
}
function paintAllow() {
  const rule = config!.rules[selected], list = el('allow-chips'); list.replaceChildren();
  if (!rule.allow.length) { const empty = document.createElement('span'); empty.className = 'empty-chip'; empty.textContent = rule.enabled ? '拒绝全部来源' : '规则关闭，不限制'; list.append(empty); }
  rule.allow.forEach((entry, index) => {
    const row = document.createElement('div'); row.className = 'allow-entry';
    const address = document.createElement('input'); address.id = 'address-' + index; address.dataset.address = String(index); address.className = 'allow-address'; address.value = allowIp(entry); address.setAttribute('aria-label', '来源 IP/CIDR');
    address.oninput = () => {
      const value = address.value.trim();
      const error = addressError(value) || (rule.allow.some((other, i) => i !== index && allowIp(other) === value) ? '该地址已存在' : '')
        || (value === '*' && allowIp(rule.allow[index]) !== '*' ? '请使用“全部来源”按钮，并确认放开限制' : '');
      if (valid(address, error)) rule.allow[index] = typeof rule.allow[index] === 'string' ? value : { ...rule.allow[index] as object, ip: value };
      changed();
    };
    address.onchange = () => { if (address.checkValidity()) address.value = address.value.trim(); update(); };
    valid(address, addressError(address.value));
    const note = document.createElement('input'); note.type = 'text'; note.placeholder = '备注，如家里 / 办公室'; note.maxLength = 128; note.value = allowNote(entry); note.setAttribute('aria-label', '来源备注');
    note.oninput = () => { valid(note, /[\p{Cc}]/u.test(note.value) ? '备注不能含控制字符' : ''); setAllowNote(rule, index, note.value); changed(); };
    const remove = document.createElement('button'); remove.type = 'button'; remove.className = 'ghost'; remove.textContent = '×'; remove.setAttribute('aria-label', '移除 ' + allowIp(entry));
    remove.onclick = () => { if (!readyToRedraw()) return; const [removed] = rule.allow.splice(index, 1); paintAllow(); paintList(); offerUndo('来源删除', () => { rule.allow.splice(index, 0, removed); }); };
    row.append(address, note, remove); list.append(row);
  });
}
function renderRules() {
  const root = el('view-rules');
  if (rawMode) {
    root.innerHTML = '<label>原始 TOML<textarea id="raw" spellcheck="false"></textarea></label><p class="muted">切换模式保留当前草稿；结构化保存会重排 TOML 并移除注释。</p>';
    el<HTMLTextAreaElement>('raw').value = raw; el('raw').oninput = () => { raw = el<HTMLTextAreaElement>('raw').value; changed(); }; return;
  }
  root.replaceChildren(); if (!config) return;
  root.innerHTML = `<div class="settings"><label class="switch"><input id="enabled" type="checkbox" ${config.enabled ? 'checked' : ''}>启用防火墙</label><label class="switch"><input id="log" type="checkbox" ${config.log_denied ? 'checked' : ''}>记录拦截日志</label><div class="protect"><span>SSH 保护端口</span><div class="chips" id="protected-chips"></div><input id="protected-input" inputmode="numeric" aria-label="新增 SSH 保护端口" placeholder="22"><button class="ghost" id="protected-add" type="button">添加</button></div></div><div class="split"><div class="rule-list"><div class="list-head"><input id="filter" aria-label="搜索规则、端口、IP 或备注" placeholder="规则 / 端口 / IP / 备注"><button class="ghost" id="add" type="button">新建</button></div><div id="rule-items"></div></div><div class="detail" id="detail"></div></div>`;
  el<HTMLInputElement>('enabled').onchange = () => void task(async () => {
    const next = el<HTMLInputElement>('enabled').checked;
    if (!next && !await ask('关闭全部限制', '保存后所有规则端口将不再限制来源。', '关闭限制', true)) { el<HTMLInputElement>('enabled').checked = config!.enabled; return; }
    config!.enabled = next; changed();
  });
  el<HTMLInputElement>('log').onchange = () => { config!.log_denied = el<HTMLInputElement>('log').checked; changed(); };
  paintProtected(); el('protected-add').onclick = () => addProtected();
  el('protected-input').oninput = () => { el<HTMLInputElement>('protected-input').setCustomValidity(''); changed(); };
  el<HTMLInputElement>('protected-input').onkeydown = event => { if (event.key === 'Enter') { event.preventDefault(); addProtected(); } };
  el<HTMLInputElement>('filter').value = filter;
  el('filter').oninput = () => { filter = el<HTMLInputElement>('filter').value; paintList(); };
  el('add').onclick = () => void task(async () => {
    if (!await commitPending()) return;
    const name = await ask('新建规则', '名称只用于识别，不绑定 rathole 服务名。', '创建', false, true);
    if (!name || !nameValid(name)) return;
    if (Object.hasOwn(config!.rules, name)) { toast('规则名称已存在', true); return; }
    Object.defineProperty(config!.rules, name, { value: { enabled: true, ports: [], allow: [] }, enumerable: true, writable: true, configurable: true });
    selected = name; renderRules(); changed(); el('port-input').focus();
  });
  paintList(); paintDetail(); update();
}
function paintList() {
  if (!config) return;
  const host = el('rule-items'); host.replaceChildren();
  const names = Object.keys(config.rules).filter(name => matchesRule(name, config!.rules[name], filter));
  if (!names.length) { host.innerHTML = '<div class="empty">没有匹配的规则。</div>'; return; }
  for (const name of names) {
    const rule = config.rules[name], [label, kind] = policy(rule);
    const button = document.createElement('button'); button.type = 'button'; button.className = 'rule-item' + (name === selected ? ' active' : '') + (rule.enabled ? '' : ' off');
    button.innerHTML = `<strong>${escape(name)}</strong><small>${escape(rule.ports.join(', ') || '未填端口')}</small><span class="pill ${kind}">${label}</span>`;
    button.onclick = () => void task(async () => { if (!await commitPending()) return; selected = name; paintList(); paintDetail(); update(); }); host.append(button);
  }
}
function paintDetail() {
  const host = el('detail'), rule = config?.rules[selected];
  if (!config || !rule) { host.innerHTML = '<div class="empty">选择一条规则，或新建。空白名单表示拒绝全部；* 表示不限制来源。关闭规则会取消限制，不是拒绝。</div>'; return; }
  const [label, kind] = policy(rule);
  host.innerHTML = `<div class="detail-head"><h3>${escape(selected)}</h3><div class="pills"><span class="pill ${kind}">${label}</span></div></div><div class="detail-body"><label class="switch"><input id="rule-on" type="checkbox" ${rule.enabled ? 'checked' : ''}>限制这些端口（关闭后不限制来源）</label><div class="grid-2"><section class="field"><header>TCP / UDP 端口</header><div class="chips" id="port-chips"></div><div class="add-row"><input id="port-input" aria-label="新增端口或范围" placeholder="5200-5300"><button class="ghost" id="port-add" type="button">添加</button></div></section><section class="field allow-field"><header>允许来源 · IP 与备注可直接编辑</header><div class="chips allow-list" id="allow-chips"></div><div class="add-row"><input id="allow-input" aria-label="新增 IP/CIDR" placeholder="203.0.113.25 或 2001:db8::/64"><button class="ghost" id="allow-add" type="button">添加</button></div><div class="quick"><button class="ghost" id="add-v4" type="button">加入 IPv4</button><button class="ghost" id="add-v6" type="button">加入 IPv6</button><button class="ghost" id="allow-any" type="button">全部来源</button><button class="ghost" id="allow-none" type="button">拒绝全部</button></div></section></div></div><div class="detail-actions"><button class="ghost" id="rename" type="button">重命名</button><button class="danger" id="delete" type="button">删除规则</button></div>`;
  el<HTMLInputElement>('rule-on').onchange = () => void task(async () => {
    const next = el<HTMLInputElement>('rule-on').checked;
    if (!next && !await ask('关闭此规则限制', '保存后这些端口可被任何来源访问。', '关闭限制', true)) { el<HTMLInputElement>('rule-on').checked = rule.enabled; return; }
    rule.enabled = next; paintList(); changed();
  });
  paintPorts(); paintAllow();
  for (const [id, validate] of [['port-input', portConflict], ['allow-input', addressError]] as const) {
    el<HTMLInputElement>(id).oninput = () => { const input = el<HTMLInputElement>(id); valid(input, input.value.trim() ? validate(input.value.trim()) : ''); changed(); };
    el<HTMLInputElement>(id).onkeydown = event => { if (event.key === 'Enter') { event.preventDefault(); el(id === 'port-input' ? 'port-add' : 'allow-add').click(); } };
  }
  el('port-add').onclick = () => addPort(); el('allow-add').onclick = () => void task(async () => { await addAllow(); });
  for (const id of ['add-v4', 'add-v6']) el(id).onclick = () => void task(async () => {
    const ip = id === 'add-v4' ? publicIp : publicV6;
    if (!ip) return;
    if (!await commitPending()) return;
    el<HTMLInputElement>('allow-input').value = ip; await addAllow();
  });
  el('allow-any').onclick = () => void task(async () => { if (await commitPending()) await replaceAllow(['*'], '全部来源'); });
  el('allow-none').onclick = () => void task(async () => { if (await commitPending()) await replaceAllow([], '拒绝全部'); });
  el('rename').onclick = () => void task(async () => {
    if (!await commitPending()) return;
    const name = await ask('重命名', '只改名称，保留端口、IP 和备注。', '重命名', false, true, selected);
    if (!name || name === selected || !nameValid(name)) return;
    if (Object.hasOwn(config!.rules, name)) { toast('规则名称已存在', true); return; }
    config!.rules = Object.fromEntries(Object.entries(config!.rules).map(([key, value]) => [key === selected ? name : key, value])); selected = name; renderRules(); changed();
  });
  el('delete').onclick = () => void task(async () => {
    if (!await commitPending() || !await ask('删除 ' + selected, '保存后会取消这些端口的限制，不是拒绝全部来源。', '删除', true)) return;
    const name = selected; delete config!.rules[name]; selected = Object.keys(config!.rules)[0] ?? ''; renderRules();
    offerUndo('规则删除', () => { config!.rules = { ...config!.rules, [name]: rule }; }, name);
  });
  update();
}
async function load(restore = false) {
  // Capture storage before rendering, because rendering updates button/draft state.
  let draft: Draft | null = null;
  if (restore) try { draft = JSON.parse(sessionStorage.getItem(draftKey) ?? 'null'); } catch { /* Invalid cached draft. */ }
  const data = await api('config');
  config = data.config; raw = loadedText = data.text; revision = data.revision; path = data.path;
  savedSnap = rawSnap = JSON.stringify(config); rawMode = !config; undo = null; el('undo').textContent = '撤销';
  if (draft?.username === username && draft?.path === path) {
    config = draft.config; raw = draft.raw; rawMode = draft.rawMode; savedSnap = draft.savedSnap; rawSnap = draft.rawSnap ?? JSON.stringify(config);
    loadedText = draft.loadedText; revision = draft.revision; selected = draft.selected;
    el('draft-hint').hidden = false;
    el('draft-hint').textContent = revision === data.revision ? '已恢复本标签页的未保存草稿。' : '已恢复草稿，但磁盘配置已变化；保存不会覆盖新文件，请先备份草稿或放弃修改并重新加载。';
  } else { el('draft-hint').hidden = true; }
  if (config && !Object.hasOwn(config.rules, selected)) selected = Object.keys(config.rules)[0] ?? '';
  el('path').textContent = path; renderRules();
  if (draft?.username === username && draft?.path === path) for (const [id, value] of Object.entries(draft.inputs ?? {})) {
    const input = el<HTMLInputElement>(id); if (input) { input.value = String(value); input.dispatchEvent(new Event('input')); }
  }
  el('mode').textContent = rawMode ? '结构化' : 'TOML'; update();
}
async function enter(session: { username: string; mustChangePassword: boolean }) {
  username = session.username; loggedIn = true; el('login-screen').hidden = true; el('console').hidden = false;
  el('who').textContent = username; el('banner').hidden = !session.mustChangePassword; el<HTMLInputElement>('pass').value = '';
  await load(true); show(view); void detect(); void refreshStatus();
}
let checking = false;
async function refreshStatus() {
  if (!loggedIn || checking) return;
  checking = true;
  try {
    const status: WatchStatus = await api('watch');
    el('watch-status').dataset.state = status.state;
    el('watch-status').textContent = `${status.message}${status.appliedAt ? ' · 上次成功：' + new Date(status.appliedAt).toLocaleString() : ''}（磁盘文件状态；不会检测外部 nft 修改）`;
  } catch (e) {
    if (!(e instanceof LoginRequired)) { el('watch-status').dataset.state = 'unknown'; el('watch-status').textContent = '热载状态暂不可用，保存文件不代表已经生效。'; }
  } finally { checking = false; }
}
function assignIp(ip: string) {
  if (addressError(ip) || ip === '*' || ip.includes('/') || ip === '127.0.0.1' || ip === '::1') return;
  if (ip.includes(':')) publicV6 = ip; else publicIp = ip;
}
async function detect() {
  const button = el<HTMLButtonElement>('detect'); if (button.disabled) return;
  button.disabled = true; publicIp = ''; publicV6 = ''; el('ip4').textContent = el('ip6').textContent = '检测中'; update();
  try {
    try { assignIp(String((await api('ip')).ip ?? '')); } catch { /* Try browser egress lookup next. */ }
    await Promise.allSettled([['https://api.ipify.org?format=json', false], ['https://api6.ipify.org?format=json', true]].map(async ([url, v6]) => {
      if (v6 ? publicV6 : publicIp) return;
      const res = await fetch(url as string, { signal: AbortSignal.timeout(3000), cache: 'no-store', credentials: 'omit' });
      if (res.ok) assignIp(String((await res.json()).ip ?? ''));
    }));
  } finally {
    button.disabled = false; el('ip4').textContent = publicIp || '未检测到'; el('ip6').textContent = publicV6 || '未检测到'; update();
  }
}
async function saveDraft() {
  if (!await commitPending()) return;
  const text = rawMode ? raw : serializeConfig(config!);
  const result = await api('save', { revision, text });
  // Inputs are inert throughout the request. Use the acknowledged text directly,
  // avoiding a second read that could replace it with someone else's edits.
  if (rawMode) config = parseConfig(text);
  loadedText = raw = text; revision = result.revision; savedSnap = rawSnap = JSON.stringify(config);
  undo = null; el('undo').textContent = '撤销'; el('draft-hint').hidden = true; update();
  toast('配置已保存；是否热载成功请看上方状态。'); await refreshStatus();
}
document.querySelectorAll<HTMLButtonElement>('.nav button').forEach(button => button.onclick = () => { if (!busy) show(button.dataset.view as View); });
el('goto-password').onclick = () => show('account');
el('login-form').onsubmit = event => { event.preventDefault(); void task(async () => { await enter(await api('login', { username: el<HTMLInputElement>('user').value, password: el<HTMLInputElement>('pass').value })); }); };
el('pw-form').onsubmit = event => { event.preventDefault(); void task(async () => {
  await api('password', { current: el<HTMLInputElement>('cur').value, password: el<HTMLInputElement>('next').value });
  el<HTMLInputElement>('cur').value = el<HTMLInputElement>('next').value = ''; el('banner').hidden = true; toast('密码已更新');
}); };
el('logout').onclick = () => void task(async () => {
  if (dirty() && !await ask('退出登录', '未保存修改和本标签页的草稿将被丢弃。', '丢弃并退出', true)) return;
  await api('logout', {}); sessionStorage.removeItem(draftKey);
  config = null; savedSnap = 'null'; raw = loadedText = ''; rawMode = true; undo = null; loggedIn = false; showLogin();
});
el('reload').onclick = () => void task(async () => { if (!dirty() || await ask('放弃修改', '重新加载磁盘上的配置，未保存内容和本地草稿会丢失。', '放弃', true)) await load(); });
el('mode').onclick = () => void task(async () => {
  if (rawMode) { const parsed = parseConfig(raw); config = parsed; rawSnap = JSON.stringify(config); rawMode = false; }
  else { if (!await commitPending()) return; const snapshot = JSON.stringify(config); if (snapshot !== rawSnap) raw = serializeConfig(config!); rawSnap = snapshot; rawMode = true; }
  undo = null; el('undo').textContent = '撤销'; el('mode').textContent = rawMode ? '结构化' : 'TOML'; renderRules(); update();
});
el('undo').onclick = () => void task(async () => { if (!readyToRedraw() || !undo) return; const action = undo; undo = null; action(); renderRules(); changed(); });
el('save').onclick = () => void task(saveDraft);
el('detect').onclick = () => void detect();
window.addEventListener('beforeunload', event => { if (dirty()) { update(); event.preventDefault(); event.returnValue = ''; } });
window.addEventListener('keydown', event => { if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') { event.preventDefault(); if (loggedIn && !busy && dirty()) void task(saveDraft); } });
setInterval(() => { if (!busy) void refreshStatus(); }, 5000);
void task(async () => { await enter(await api('session')); });
