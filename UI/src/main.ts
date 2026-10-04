import './style.css';
import { allowIp, allowNote, setAllowNote, type Config, type Rule } from '../policy';

type View = 'rules' | 'account';
const app = document.querySelector<HTMLDivElement>('#app')!;
let revision = '', loadedText = '', config: Config | null = null, raw = '', rawMode = false, busy = false;
let publicIp = '', publicV6 = '', username = '', mustChange = false, selected = '', view: View = 'rules';
const escape = (s: string) => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
const tokens = (s: string) => s.split(/[\s,，]+/).filter(Boolean);
const el = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

app.innerHTML = `
<div class="progress"></div>
<section class="login-screen" id="login-screen">
  <div class="login-copy"><div class="mark" aria-hidden="true"><i></i><i></i><i></i></div><h1>端口只对你打开。</h1><p>这里只修改 firewall.toml。规则由 portguard apply --watch 读取文件后热载。</p></div>
  <form class="login-card" id="login-form">
    <h2>登录控制台</h2><p class="sub">防火墙规则 · 端口 7500</p>
    <label>用户名<input id="user" required autocomplete="username" value="admin"></label>
    <label>密码<input id="pass" type="password" required autocomplete="current-password"></label>
    <button>进入</button>
    <p class="note">初始账号 admin / 123456。这是明文 HTTP，登录后请马上改密码。</p>
  </form>
</section>
<div class="console" id="console" hidden>
  <aside class="side">
    <div class="lockup"><div class="mark" aria-hidden="true"><i></i><i></i><i></i></div><div><strong>PORTGUARD</strong><span id="who">未登录</span></div></div>
    <nav class="nav">
      <button type="button" data-view="rules">规则</button>
      <button type="button" data-view="account">账号</button>
    </nav>
  </aside>
  <div class="workspace">
    <header class="top">
      <div class="top-title"><h2 id="title">规则</h2><span class="dirty" id="dirty" hidden>未保存</span></div>
      <div class="top-meta"><span class="path" id="path"></span></div>
      <div class="actions">
        <button class="ghost" id="reload" type="button">放弃修改</button>
        <button class="ghost" id="mode" type="button">TOML</button>
        <button class="primary" id="save" type="button">保存配置</button>
      </div>
    </header>
    <div class="banner" id="banner" hidden><span>仍在使用初始密码。</span><button class="ghost" id="goto-password" type="button">去修改</button></div>
    <div class="ipbar"><div><span>当前 IPv4 · 本次连接</span><strong id="ip4">检测中</strong></div><div><span>当前 IPv6 · 本次连接</span><strong id="ip6">未连接</strong></div><button class="ghost" id="detect" type="button">重新检测</button></div>
    <section class="view" id="view-rules"></section>
    <section class="view" id="view-account" hidden>
      <form class="account" id="pw-form">
        <h3>修改密码</h3>
        <p class="muted">至少 6 位。修改后其他会话失效，当前浏览器保持登录。</p>
        <label>当前密码<input id="cur" type="password" required autocomplete="current-password"></label>
        <label>新密码<input id="next" type="password" required minlength="6" maxlength="128" autocomplete="new-password"></label>
        <div class="form-actions"><button class="primary" type="submit">更新密码</button><button class="ghost" id="logout" type="button">退出登录</button></div>
      </form>
    </section>
  </div>
</div>
<div class="modal" id="modal" hidden><form id="modal-form"><h2 id="modal-title"></h2><p id="modal-body"></p><label id="modal-field" hidden>名称<input id="modal-input" autocomplete="off"></label><div class="actions"><button class="ghost" id="modal-cancel" type="button">取消</button><button id="modal-ok" type="submit">确认</button></div></form></div>
<div class="toasts" id="toasts"></div>`;

function toast(message: string, bad = false) {
  const node = document.createElement('div');
  node.className = 'toast' + (bad ? ' bad' : '');
  node.textContent = message;
  el('toasts').append(node);
  setTimeout(() => node.remove(), bad ? 8000 : 3600);
}
function ask(title: string, body: string, ok = '确认', danger = false, field = false) {
  el('modal-title').textContent = title;
  el('modal-body').textContent = body;
  el('modal-field').hidden = !field;
  if (field) el<HTMLInputElement>('modal-input').value = '';
  const button = el<HTMLButtonElement>('modal-ok');
  button.textContent = ok;
  button.className = danger ? 'danger' : 'primary';
  el('modal').hidden = false;
  if (field) el('modal-input').focus();
  return new Promise<string | null>(resolve => {
    const finish = (value: string | null) => { el('modal').hidden = true; cleanup(); resolve(value); };
    const onSubmit = (event: Event) => { event.preventDefault(); finish(field ? el<HTMLInputElement>('modal-input').value.trim() : 'ok'); };
    const onCancel = () => finish(null);
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') finish(null); };
    el('modal-form').addEventListener('submit', onSubmit);
    el('modal-cancel').addEventListener('click', onCancel);
    document.addEventListener('keydown', onKey);
    function cleanup() {
      el('modal-form').removeEventListener('submit', onSubmit);
      el('modal-cancel').removeEventListener('click', onCancel);
      document.removeEventListener('keydown', onKey);
    }
  });
}
function validName(name: string) {
  if (!name || new TextEncoder().encode(name).length > 128 || [...name].some(ch => ch.charCodeAt(0) < 32)) { toast('名称不能为空、不能含控制字符，且不超过 128 字节', true); return false; }
  return true;
}
async function api(path: string, data?: unknown) {
  const res = await fetch('/api/' + path, { method: data === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: data === undefined ? undefined : JSON.stringify(data) });
  const json = await res.json();
  if (res.status === 401 && path !== 'login') location.reload();
  if (!res.ok) throw new Error(json.error ?? '请求失败');
  return json;
}
async function task(fn: () => Promise<void>) {
  if (busy) return;
  busy = true; document.body.classList.add('busy');
  try { await fn(); } catch (e) { toast((e as Error).message, true); }
  finally { busy = false; document.body.classList.remove('busy'); }
}
function snapshot() { return JSON.stringify(config); }
let savedSnap = '';
function dirty() { return rawMode ? raw !== loadedText : snapshot() !== savedSnap; }
function policy(rule: Rule) {
  if (!rule.enabled) return ['未限制', 'muted'];
  if (!rule.allow.length) return ['拒绝全部', 'bad'];
  if (rule.allow.length === 1 && allowIp(rule.allow[0]) === '*') return ['全部来源', 'warn'];
  return [`${rule.allow.length} 个来源`, 'ok'];
}
function show(next: View) {
  view = next;
  for (const name of ['rules', 'account'] as View[]) el('view-' + name).hidden = name !== next;
  document.querySelectorAll<HTMLButtonElement>('.nav button').forEach(button => button.setAttribute('aria-current', button.dataset.view === next ? 'page' : 'false'));
  el('title').textContent = next === 'rules' ? '规则' : '账号';
  el('dirty').hidden = !dirty();
}
function chips(host: HTMLElement, items: string[], empty: string, remove: (index: number) => void) {
  host.replaceChildren();
  if (!items.length) { const span = document.createElement('span'); span.className = 'empty-chip'; span.textContent = empty; host.append(span); return; }
  items.forEach((item, index) => {
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'chip'; button.title = '移除 ' + item;
    button.innerHTML = `<span>${escape(item)}</span><span aria-hidden="true">×</span>`;
    button.onclick = () => remove(index);
    host.append(button);
  });
}
function renderRules() {
  const root = el('view-rules');
  if (rawMode) {
    root.innerHTML = '<label>原始 TOML<textarea id="raw" spellcheck="false"></textarea></label><p class="muted">保留注释。切回结构化编辑会重新加载并丢弃未保存文本。</p>';
    el<HTMLTextAreaElement>('raw').value = raw;
    el('raw').oninput = () => { raw = el<HTMLTextAreaElement>('raw').value; el('dirty').hidden = !dirty(); };
    return;
  }
  root.replaceChildren();
  if (!config) return;
  const c = config;
  root.innerHTML = `<div class="settings"><label class="switch"><input id="enabled" type="checkbox" ${c.enabled ? 'checked' : ''}>启用防火墙</label><label class="switch"><input id="log" type="checkbox" ${c.log_denied ? 'checked' : ''}>记录拦截日志</label><div class="protect"><span>SSH 保护端口</span><div class="chips" id="protected-chips"></div><input id="protected-input" inputmode="numeric" placeholder="22"><button class="ghost" id="protected-add" type="button">添加</button></div></div><div class="split"><div class="rule-list"><div class="list-head"><input id="filter" placeholder="筛选规则"><button class="ghost" id="add" type="button">新建</button></div><div id="rule-items"></div></div><div class="detail" id="detail"></div></div>`;
  el<HTMLInputElement>('enabled').onchange = () => { c.enabled = el<HTMLInputElement>('enabled').checked; el('dirty').hidden = !dirty(); };
  el<HTMLInputElement>('log').onchange = () => { c.log_denied = el<HTMLInputElement>('log').checked; el('dirty').hidden = !dirty(); };
  const paintProtected = () => chips(el('protected-chips'), c.protected_ports.map(String), '未设置', index => { c.protected_ports.splice(index, 1); paintProtected(); el('dirty').hidden = !dirty(); });
  paintProtected();
  el('protected-add').onclick = () => {
    const value = Number(el<HTMLInputElement>('protected-input').value);
    if (!Number.isInteger(value) || value < 1 || value > 65535) { toast('保护端口须为 1–65535', true); return; }
    if (!c.protected_ports.includes(value)) c.protected_ports.push(value);
    el<HTMLInputElement>('protected-input').value = ''; paintProtected(); el('dirty').hidden = !dirty();
  };
  el<HTMLInputElement>('filter').oninput = paintList;
  el('add').onclick = async () => {
    const name = await ask('新建规则', '名称只用于识别，不绑定 rathole 服务名。', '创建', false, true);
    if (!name || !validName(name)) return;
    if (Object.hasOwn(c.rules, name)) { toast('规则名称已存在', true); return; }
    c.rules[name] = { enabled: true, ports: [], allow: [] };
    selected = name; renderRules();
  };
  paintList();
  paintDetail();
}
function paintList() {
  if (!config) return;
  const query = (el<HTMLInputElement>('filter')?.value ?? '').toLowerCase();
  const host = el('rule-items');
  host.replaceChildren();
  const names = Object.keys(config.rules).filter(name => !query || name.toLowerCase().includes(query) || config!.rules[name].ports.some(port => port.includes(query)));
  if (!names.length) { host.innerHTML = '<div class="empty">没有匹配的规则。</div>'; return; }
  for (const name of names) {
    const rule = config.rules[name];
    const [label, kind] = policy(rule);
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'rule-item' + (name === selected ? ' active' : '') + (rule.enabled ? '' : ' off');
    button.innerHTML = `<strong>${escape(name)}</strong><small>${escape(rule.ports.join(', ') || '未填端口')}</small><span class="pill ${kind}">${label}</span>`;
    button.onclick = () => { selected = name; paintList(); paintDetail(); };
    host.append(button);
  }
}
function paintDetail() {
  const host = el('detail');
  const rule = config?.rules[selected];
  if (!config || !rule) { host.innerHTML = '<div class="empty">选择一条规则，或新建。空白名单表示拒绝全部；* 表示不限制来源。关闭规则会取消该端口限制，不是拒绝。</div>'; return; }
  const [label, kind] = policy(rule);
  host.innerHTML = `<div class="detail-head"><h3>${escape(selected)}</h3><div class="pills"><span class="pill ${kind}">${label}</span>${config.enabled ? '' : '<span class="pill warn">防火墙已关闭</span>'}</div></div><div class="detail-body"><label class="switch"><input id="rule-on" type="checkbox" ${rule.enabled ? 'checked' : ''}>限制这些端口</label><div class="grid-2"><section class="field"><header>TCP / UDP 端口</header><div class="chips" id="port-chips"></div><div class="add-row"><input id="port-input" placeholder="5200-5300"><button class="ghost" id="port-add" type="button">添加</button></div></section><section class="field allow-field"><header>允许来源</header><div class="chips" id="allow-chips"></div><div class="add-row"><input id="allow-input" placeholder="203.0.113.25 或 2001:db8::/64"><button class="ghost" id="allow-add" type="button">添加</button></div><div class="quick"><button class="ghost" id="add-v4" type="button">加入 IPv4</button><button class="ghost" id="add-v6" type="button">加入 IPv6</button><button class="ghost" id="allow-any" type="button">全部来源</button><button class="ghost" id="allow-none" type="button">拒绝全部</button></div></section></div></div><div class="detail-actions"><button class="ghost" id="rename" type="button">重命名</button><button class="danger" id="delete" type="button">删除规则</button></div>`;
  const touch = () => { el('dirty').hidden = !dirty(); paintList(); const [next, tone] = policy(rule); const pill = host.querySelector('.pill'); if (pill) { pill.className = 'pill ' + tone; pill.textContent = next; } };
  el<HTMLInputElement>('rule-on').onchange = () => { rule.enabled = el<HTMLInputElement>('rule-on').checked; touch(); };
  const paintPorts = () => chips(el('port-chips'), rule.ports, '尚未添加端口', index => { rule.ports.splice(index, 1); paintPorts(); touch(); });
  const paintAllow = () => {
    const list = el('allow-chips');
    list.classList.add('allow-list');
    list.replaceChildren();
    if (!rule.allow.length) {
      const empty = document.createElement('span');
      empty.className = 'empty-chip';
      empty.textContent = rule.enabled ? '拒绝全部来源' : '规则关闭，不限制';
      list.append(empty);
    }
    rule.allow.forEach((entry, index) => {
      const ip = allowIp(entry);
      const row = document.createElement('div');
      row.className = 'allow-entry';
      const address = document.createElement('span');
      address.className = 'allow-address';
      address.textContent = ip;
      const note = document.createElement('input');
      note.type = 'text'; note.placeholder = '备注，如家里 / 办公室'; note.maxLength = 128;
      note.value = allowNote(entry);
      note.setAttribute('aria-label', ip + ' 的备注');
      note.oninput = () => { setAllowNote(rule, index, note.value); touch(); };
      const remove = document.createElement('button');
      remove.type = 'button'; remove.className = 'ghost'; remove.textContent = '×';
      remove.setAttribute('aria-label', '移除 ' + ip);
      remove.onclick = () => { rule.allow.splice(index, 1); paintAllow(); touch(); };
      row.append(address, note, remove);
      list.append(row);
    });
  };
  paintPorts(); paintAllow();
  const addPort = () => {
    const value = el<HTMLInputElement>('port-input').value.trim();
    if (!/^[1-9]\d{0,4}(-[1-9]\d{0,4})?$/.test(value)) { toast('端口格式应为 8080 或 5200-5300', true); return; }
    rule.ports.push(value); el<HTMLInputElement>('port-input').value = ''; paintPorts(); touch();
  };
  const addAllow = (value: string) => {
    if (value !== '*' && !/^([0-9.]+|[0-9a-fA-F:]+)(\/\d{1,3})?$/.test(value)) { toast('来源须是 IP、CIDR 或 *', true); return; }
    if (value === '*' || rule.allow.some(entry => allowIp(entry) === '*')) rule.allow = [value];
    else if (!rule.allow.some(entry => allowIp(entry) === value)) rule.allow.push(value);
    paintAllow(); touch();
  };
  el('port-add').onclick = addPort;
  el<HTMLInputElement>('port-input').onkeydown = event => { if (event.key === 'Enter') { event.preventDefault(); addPort(); } };
  el('allow-add').onclick = () => { addAllow(el<HTMLInputElement>('allow-input').value.trim()); el<HTMLInputElement>('allow-input').value = ''; };
  el<HTMLInputElement>('allow-input').onkeydown = event => { if (event.key === 'Enter') { event.preventDefault(); el('allow-add').click(); } };
  el('add-v4').onclick = () => publicIp ? addAllow(publicIp) : toast('还没有检测到 IPv4', true);
  el('add-v6').onclick = () => publicV6 ? addAllow(publicV6) : toast('还没有检测到 IPv6', true);
  el('allow-any').onclick = () => addAllow('*');
  el('allow-none').onclick = () => { rule.allow = []; paintAllow(); touch(); };
  el('rename').onclick = async () => {
    const name = await ask('重命名', '保存配置后，由 watch 热载。', '重命名', false, true);
    if (!name || name === selected || !config || !validName(name)) return;
    if (Object.hasOwn(config.rules, name)) { toast('规则名称已存在', true); return; }
    config.rules = Object.fromEntries(Object.entries(config.rules).map(([key, value]) => [key === selected ? name : key, value]));
    selected = name; renderRules();
  };
  el('delete').onclick = async () => {
    if (!config || !await ask('删除 ' + selected, '先从草稿删除。保存后，watch 会取消这些端口的限制。', '删除', true)) return;
    delete config.rules[selected]; selected = Object.keys(config.rules)[0] ?? ''; renderRules();
  };
}
async function load() {
  const data = await api('config');
  config = data.config; raw = loadedText = data.text; revision = data.revision; rawMode = !config;
  savedSnap = snapshot();
  if (config && !config.rules[selected]) selected = Object.keys(config.rules)[0] ?? '';
  el('path').textContent = data.path;
  el('mode').textContent = rawMode ? '结构化' : 'TOML';
  renderRules(); el('dirty').hidden = true;
}
function assignIp(ip: string) {
  if (!/^[0-9a-fA-F:.]+$/.test(ip) || ip === '127.0.0.1' || ip === '::1') return;
  if (ip.includes(':')) publicV6 = ip; else publicIp = ip;
}
function paintIp() {
  el('ip4').textContent = publicIp || '未检测到';
  el('ip6').textContent = publicV6 || '未连接';
}
async function detect() {
  el('ip4').textContent = '检测中';
  publicIp = ''; publicV6 = '';
  try { assignIp(String((await api('ip')).ip ?? '')); } catch { /* 连接地址读取失败时再试外部查询 */ }
  paintIp();
  if (publicIp && publicV6) return;
  await Promise.allSettled([['https://api.ipify.org?format=json', false], ['https://api6.ipify.org?format=json', true]].map(async ([url, v6]) => {
    if (v6 ? publicV6 : publicIp) return;
    try {
      const res = await fetch(url as string, { signal: AbortSignal.timeout(3000), cache: 'no-store', credentials: 'omit' });
      if (!res.ok) return;
      const data = await res.json();
      if (typeof data.ip === 'string') assignIp(data.ip);
    } catch { /* 第三方查询失败不影响已看到的连接地址 */ }
  }));
  paintIp();
}
function payload() { return rawMode ? { revision, text: raw } : { revision, config }; }
async function saveDraft() {
  await api('save', payload());
  toast('配置已保存，watch 会自动热载');
  await load();
}
document.querySelectorAll<HTMLButtonElement>('.nav button').forEach(button => button.onclick = () => show(button.dataset.view as View));
el('goto-password').onclick = () => show('account');
el('login-form').onsubmit = event => { event.preventDefault(); void task(async () => {
  const session = await api('login', { username: el<HTMLInputElement>('user').value, password: el<HTMLInputElement>('pass').value });
  username = session.username; mustChange = session.mustChangePassword;
  el('login-screen').hidden = true; el('console').hidden = false; el('who').textContent = username; el('banner').hidden = !mustChange;
  await load(); show('rules'); void detect();
}); };
el('pw-form').onsubmit = event => { event.preventDefault(); void task(async () => {
  await api('password', { current: el<HTMLInputElement>('cur').value, password: el<HTMLInputElement>('next').value });
  el<HTMLInputElement>('cur').value = ''; el<HTMLInputElement>('next').value = ''; mustChange = false; el('banner').hidden = true;
  toast('密码已更新');
}); };
el('logout').onclick = () => { void api('logout').finally(() => location.reload()); };
el('reload').onclick = () => void task(async () => { if (!dirty() || await ask('放弃修改', '重新加载磁盘上的配置，当前未保存内容会丢失。', '放弃', true)) await load(); });
el('mode').onclick = () => void task(async () => {
  if (!rawMode) { if (dirty() && !await ask('切换到 TOML', '未保存的结构化修改会丢失。', '切换', true)) return; rawMode = true; renderRules(); }
  else { if (raw !== loadedText && !await ask('返回结构化编辑', '将重新加载，未保存的 TOML 会丢失。', '重新加载', true)) return; await load(); }
  el('mode').textContent = rawMode ? '结构化' : 'TOML';
});
el('save').onclick = () => void task(saveDraft);
el('detect').onclick = () => void detect();
