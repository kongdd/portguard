#!/usr/bin/env python3
"""Full CLI subprocess tests with a fake nft for deterministic fault injection."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import time
import unittest

BINARY = Path(os.environ.get('PORTGUARD_BIN', 'target/debug/portguard')).resolve()
FAKE = Path(__file__).with_name('fake_nft.py')

class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        bindir = self.root / 'bin'
        bindir.mkdir()
        shutil.copy(FAKE, bindir / 'nft')
        (bindir / 'nft').chmod(0o755)
        self.env = os.environ.copy()
        self.env.pop('SSH_CONNECTION', None)
        self.env.update(PATH=str(bindir) + ':' + self.env['PATH'], FAKE_NFT_DIR=str(self.root))
        self.config = self.root / 'firewall.toml'
        self.write(['192.0.2.1'])
        # Geolocation is deterministic and never contacts an external service in tests.
        curl = bindir / 'curl'
        curl.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
root=Path(os.environ["FAKE_NFT_DIR"])
ip=sys.argv[-1].split("/")[-1].split("?")[0]
with (root/"geo_calls").open("a") as calls: calls.write(ip+"\\n")
if (root/"geo_fail").exists(): sys.exit(7)
if (root/"geo_bad_json").exists(): print("not JSON"); sys.exit(0)
foreign=ip=="1.1.1.1"
print(json.dumps({"success":True,"ip":ip,"country_code":"AU" if foreign else "CN",
    "country":"澳大利亚" if foreign else "中国","region":"广东省",
    "city":"布里斯班很长的城市名称" if foreign else "深圳市"}))
''')
        curl.chmod(0o755)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, allow, protected='[22]', port='5200-5300'):
        self.config.write_text(f'# Keep this comment\nprotected_ports={protected}\n[rules.nas]\nports=["{port}"]\nallow={json.dumps(allow)}\n')

    def run_cli(self, *args, ok=True, env=None):
        if args and args[0] == 'audit':
            indexed = 'index' in args or '--index-path' in args
            if not indexed and '--no-index' not in args:
                args = (*args, '--no-index')
            if '--index-path' not in args:
                args = (*args, '--index-path', str(self.root / 'audit.sqlite3'))
            args = (*args, '--geo-cache', str(self.root / 'geo.json'))
        result = subprocess.run([str(BINARY), '-c', str(self.config), *args], env=env or self.env, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode == 0, ok, result.stdout + result.stderr)
        return result.stdout + result.stderr

    def kernel(self):
        return json.loads((self.root / 'kernel.json').read_text())

    def test_apply_status_rollback_disable(self):
        self.run_cli('check', '--print')
        self.run_cli('apply')
        self.assertIn('192.0.2.1/32', self.kernel()['acl'])
        self.assertIn('# Keep this comment', self.config.read_text())
        self.assertIn('允许，匹配', self.run_cli('status', '--ip', '192.0.2.1'))
        self.write(['198.51.100.1'])
        self.assertIn('尚未应用', self.run_cli('status'))
        self.run_cli('apply')
        self.assertIn('198.51.100.1/32', self.kernel()['acl'])
        self.run_cli('rollback')
        self.assertIn('192.0.2.1/32', self.kernel()['acl'])
        self.assertIn('192.0.2.1', self.config.read_text())
        self.run_cli('disable')
        self.assertEqual(self.kernel()['acl'], '')
        self.assertIn('enabled = false', self.config.read_text())
        self.run_cli('disable')  # idempotent; previous remains the enabled version
        self.run_cli('rollback')
        self.assertIn('192.0.2.1/32', self.kernel()['acl'])
        self.assertEqual(self.kernel()['system'], 'unchanged')

    def test_protection_and_overlap_leave_kernel_untouched(self):
        self.run_cli('apply')
        old = self.kernel()
        self.write(['*'], port='20-30')
        self.assertIn('受保护端口', self.run_cli('apply', ok=False))
        self.assertEqual(self.kernel(), old)
        self.write(['192.0.2.1'])
        with self.config.open('a') as f:
            f.write('[rules.rdp]\nports=["5300"]\nallow=[]\n')
        self.assertIn('重叠', self.run_cli('apply', ok=False))
        self.assertEqual(self.kernel(), old)

    def test_wildcard_empty_and_disabled(self):
        self.write(['*'])
        self.run_cli('apply')
        self.assertNotIn('th dport', self.kernel()['acl'])
        self.write([])
        self.run_cli('apply')
        self.assertIn(' drop', self.kernel()['acl'])
        self.assertNotIn('saddr', self.kernel()['acl'])
        with self.config.open('a') as f:
            f.write('enabled=false\n')
        self.run_cli('apply')
        self.assertNotIn('th dport', self.kernel()['acl'])

    def test_nft_validation_failure_preserves_draft_and_history(self):
        self.run_cli('apply')
        old = self.kernel()
        state = Path(str(self.config) + '.state.json').read_text()
        self.write(['198.51.100.1'])
        draft = self.config.read_text()
        (self.root / 'fail_check_once').touch()
        self.run_cli('apply', ok=False)
        self.assertEqual(self.kernel(), old)
        self.assertEqual(self.config.read_text(), draft)
        self.assertEqual(Path(str(self.config) + '.state.json').read_text(), state)
        self.assertFalse(Path(str(self.config) + '.pending.json').exists())

    def test_nft_apply_and_postapply_failures_recover(self):
        for marker in ['fail_apply_once', 'snapshot_after_apply']:
            self.run_cli('apply')
            old = self.kernel()
            state = Path(str(self.config) + '.state.json').read_text()
            self.write(['198.51.100.1'])
            draft = self.config.read_text()
            (self.root / marker).touch()
            self.run_cli('apply', ok=False)
            self.assertEqual(self.kernel(), old)
            self.assertEqual(self.config.read_text(), draft)
            self.assertEqual(Path(str(self.config) + '.state.json').read_text(), state)
            self.assertFalse(Path(str(self.config) + '.pending.json').exists())
            self.write(['192.0.2.1'])

    def test_crash_is_recoverable(self):
        self.run_cli('apply')
        self.write(['198.51.100.1'])
        (self.root / 'crash_after_apply').touch()
        process = subprocess.Popen([str(BINARY), '-c', str(self.config), 'apply'], env=self.env, start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 10
            while not (self.root / 'applied.marker').exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue((self.root / 'applied.marker').exists())
            import signal
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
            self.assertTrue(Path(str(self.config) + '.pending.json').exists())
            self.assertIn('未完成事务', self.run_cli('status'))
            self.assertIn('已恢复中断', self.run_cli('disable'))
            self.assertEqual(self.kernel()['acl'], '')
            self.assertFalse(Path(str(self.config) + '.pending.json').exists())
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()

    def test_external_changes_and_noop(self):
        self.run_cli('apply')
        count = (self.root / 'batches.log').read_text().count('\n')
        self.assertIn('无需重新应用', self.run_cli('apply'))
        self.assertEqual((self.root / 'batches.log').read_text().count('\n'), count)
        kernel = self.kernel()
        kernel['acl'] = ''
        (self.root / 'kernel.json').write_text(json.dumps(kernel))
        self.assertIn('外部修改', self.run_cli('status'))
        self.run_cli('apply')
        self.assertIn('192.0.2.1/32', self.kernel()['acl'])

    def test_ssh_connection_and_rollback_protection(self):
        env = self.env.copy()
        env['SSH_CONNECTION'] = '192.0.2.1 50000 198.51.100.1 2222'
        self.assertIn('2222', self.run_cli('apply', ok=False, env=env))
        self.write(['192.0.2.1'], protected='[22,2222]')
        self.run_cli('apply', env=env)
        self.write(['198.51.100.1'], protected='[22,2222,5202]', port='5301')
        self.run_cli('apply')
        self.assertIn('受保护端口', self.run_cli('rollback', ok=False))
        self.assertIn('5301', self.kernel()['acl'])

    def test_disable_can_rescue_invalid_draft(self):
        self.run_cli('apply')
        self.config.write_text('broken {')
        self.run_cli('disable')
        self.assertEqual(self.kernel()['acl'], '')
        self.assertIn('enabled = false', self.config.read_text())

    def test_logging_is_opt_in_and_rollback_restores_it(self):
        self.run_cli('apply')
        self.assertNotIn('log prefix', self.kernel()['acl'])
        text = self.config.read_text()
        self.config.write_text('log_denied=true\n' + text)
        self.run_cli('apply')
        rules = self.kernel()['acl']
        self.assertEqual(rules.count('limit rate 5/second burst 10 packets'), 1)
        self.assertIn('jump denied', rules)
        self.assertIn('log prefix "portguard DROP "', rules)
        self.run_cli('rollback')
        self.assertNotIn('log prefix', self.kernel()['acl'])

    def test_audit_without_firewall_config_and_query_filters(self):
        import time
        fixture = self.root / 'journal.jsonl'
        now = int(time.time())
        rows = []
        def row(message, ssh=True, ago=10):
            rows.append({'MESSAGE': message, 'SYSLOG_IDENTIFIER': 'sshd' if ssh else 'kernel',
                         '_TRANSPORT': 'syslog' if ssh else 'kernel',
                         '__REALTIME_TIMESTAMP': str((now - ago) * 1000000)})
        for _ in range(3):
            row('Failed password for invalid user root from 192.0.2.1 port 1234 ssh2')
        row('Invalid user root from 192.0.2.1 port 1234')
        row('Accepted publickey for root from 192.0.2.1 port 1234 ssh2')
        row('Failed password for root from 198.51.100.1 port 1234 ssh2', ago=90000)
        row('Accepted password for root from 192.0.2.2 port 1234 ssh2')
        row('Connection reset by 81.70.146.20 port 55624 [preauth]')
        row('Connection closed by authenticating user root 81.70.146.20 port 44438 [preauth]')
        row('Invalid user ubuntu from 159.75.186.122 port 48844')
        row('error: kex_exchange_identification: read: Connection reset by peer')
        fixture.write_text(''.join(json.dumps(r) + '\n' for r in rows))
        journal = self.root / 'bin' / 'journalctl'
        journal.write_text('#!/usr/bin/env python3\nfrom pathlib import Path\nimport os,sys\nroot=Path(os.environ["FAKE_NFT_DIR"])\n(root/"journal_args").write_text(" ".join(sys.argv[1:]))\nprint((root/"journal.jsonl").read_text(),end="")\n')
        journal.chmod(0o755)
        self.config.unlink()  # audit must not need firewall.toml or nft.
        result = json.loads(self.run_cli('audit', '--json'))
        self.assertEqual(len(result['entries']), 3)
        first = result['entries'][0]
        self.assertEqual(first['ip'], '192.0.2.1')
        self.assertEqual(first['ssh_failures'], 3)
        self.assertEqual(first['ssh_successes'], 1)
        self.assertEqual(first['ssh_invalid_users'], 1)
        by_ip = {entry['ip']: entry for entry in result['entries']}
        # The drop/ports columns are no longer displayed, but counts for SSH events remain.
        self.assertNotIn('2001:db8::1', by_ip)
        self.assertEqual(by_ip['81.70.146.20']['ssh_connection_closed'], 1)
        self.assertEqual(by_ip['81.70.146.20']['ssh_connection_reset'], 1)
        self.assertEqual(by_ip['81.70.146.20']['ssh_failures'], 0)
        self.assertEqual(by_ip['159.75.186.122']['ssh_invalid_users'], 1)
        self.assertNotIn('198.51.100.2', by_ip)
        successes = json.loads(self.run_cli('audit', '--min-events', '0', '--json'))
        self.assertEqual(len(successes['entries']), 4)
        table = self.run_cli('audit')
        self.assertIn('closed', table)
        self.assertIn('last', table)
        self.assertIn('address', table)
        for label in ('Address','Fail','OK','Invalid','Closed','Reset','Last'):
            self.assertNotIn(label, table)
        # Title still mentions IP literally; do not assert it is absent.
        self.assertIn('按 fail 列倒序', table)
        self.assertRegex(table, r'\d+ sec')
        self.assertNotIn('秒前', table)
        self.assertIn(' | ', table)
        self.assertIn('-+-', table)
        self.assertNotIn('\t', table)
        self.assertNotIn('登录失败不等于', table)
        self.assertNotIn('同一连接可能', table)
        self.assertNotIn('仅查询现有 journal', table)
        self.assertNotIn('Address 来自', table)
        self.assertNotIn('记录拦截来源', table)
        self.assertEqual(len(table.splitlines()), 6)  # Title, header, separator, three IPs.
        self.assertTrue(result['notes'])  # JSON remains backward compatible.
        filtered = json.loads(self.run_cli('audit', '--ip', '192.0.2.2', '--min-events', '0', '--json'))
        self.assertEqual(len(filtered['entries']), 1)
        self.assertEqual(filtered['entries'][0]['ssh_successes'], 1)
        connections = json.loads(self.run_cli('audit', '--ip', '81.70.146.20', '--min-events', '2', '--json'))
        self.assertEqual(len(connections['entries']), 1)
        minimum = json.loads(self.run_cli('audit', '--min-events', '3', '--limit', '1', '--json'))
        self.assertEqual(len(minimum['entries']), 1)
        journal_args = (self.root/'journal_args').read_text()
        self.assertIn('SYSLOG_IDENTIFIER=sshd + _TRANSPORT=kernel',
                      journal_args.replace(' SYSLOG_IDENTIFIER=sshd-session', ''))
        self.assertIn('--reverse', journal_args)
        self.assertIn('--no-tail', journal_args)
        self.assertNotIn('--lines', journal_args)
        self.assertIn('--since @', journal_args)
        self.assertIn('--until @', journal_args)
        yearly = json.loads(self.run_cli('audit', '--since', '1y', '--json'))
        self.assertEqual(yearly['until_unix'] - yearly['since_unix'], 365 * 86400)
        self.assertEqual(len(yearly['entries']), 4)
        self.assertNotIn('192.0.2.2', {entry['ip'] for entry in yearly['entries']})
        yearly_all = json.loads(self.run_cli('audit', '--since', '1y', '--min-events', '0', '--json'))
        self.assertEqual(len(yearly_all['entries']), 5)
        success_only = next(entry for entry in yearly_all['entries'] if entry['ip'] == '192.0.2.2')
        self.assertEqual(success_only['ssh_successes'], 1)
        self.assertEqual(success_only['ssh_failures'], 0)
        old = next(entry for entry in yearly['entries'] if entry['ip'] == '198.51.100.1')
        self.assertEqual(old['ssh_failures'], 1)
        yearly_days = json.loads(self.run_cli('audit', '--since', '365d', '--json'))
        self.assertEqual(yearly_days['entries'], yearly['entries'])
        self.run_cli('audit', '--since', '366d', ok=False)
        self.run_cli('audit', '--since', '2y', ok=False)
        self.run_cli('audit', '--since', '中文', ok=False)
        self.run_cli('audit', '--limit', '0', ok=False)
        self.run_cli('audit', '--sort', 'FAIL', ok=False)
        self.run_cli('audit', '--sort', 'drop', ok=False)
        self.run_cli('audit', '--sort', 'ports', ok=False)
        self.run_cli('audit', '--sort', 'ip', ok=True)
        self.assertEqual(json.loads(self.run_cli('audit', '--sort', 'invalid', '--json'))['sort'], 'invalid')

    def test_audit_geolocation_cache_opt_out_and_failures(self):
        now = int(time.time())
        ips = ['1.1.1.1', '81.70.146.20', '192.168.1.1', '192.0.2.254', '::1']
        rows = [{'MESSAGE': f'Failed password for root from {ip} port 1234 ssh2',
                 'SYSLOG_IDENTIFIER': 'sshd', '__REALTIME_TIMESTAMP': str((now - 10) * 1000000)}
                for ip in ips]
        (self.root / 'journal.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in rows))
        journal = self.root / 'bin' / 'journalctl'
        journal.write_text('#!/bin/sh\n/bin/cat "$FAKE_NFT_DIR/journal.jsonl"\n')
        journal.chmod(0o755)
        def addresses(*options):
            result = json.loads(self.run_cli('audit', '--json', *options))
            return {entry['ip']: entry['address'] for entry in result['entries']}
        first = addresses()
        self.assertEqual(first['1.1.1.1'], '澳大利亚 / 布里斯班')
        self.assertEqual(first['81.70.146.20'], '广东省 / 深圳市')
        self.assertEqual(first['192.168.1.1'], 'Private')
        self.assertEqual(first['192.0.2.254'], 'Reserved')
        self.assertEqual(first['::1'], 'Loopback')
        calls = (self.root / 'geo_calls').read_text().splitlines()
        self.assertEqual(sorted(calls), ['1.1.1.1', '81.70.146.20'])
        self.assertEqual(addresses(), first)
        cache_path = self.root / 'geo.json'
        cache = json.loads(cache_path.read_text())
        cache['81.70.146.20']['address'] = '新疆维吾尔自治区 / 乌鲁木齐'
        cache_path.write_text(json.dumps(cache))
        self.assertEqual(addresses()['81.70.146.20'], '新疆 / 乌鲁木齐')
        self.assertEqual((self.root / 'geo_calls').read_text().splitlines(), calls)
        self.assertTrue(all(value == '-' for value in addresses('--no-geo').values()))
        self.assertEqual((self.root / 'geo_calls').read_text().splitlines(), calls)
        # Old formatting must not keep long foreign city names alive in the cache.
        cache_path = self.root / 'geo.json'
        cache = json.loads(cache_path.read_text())
        for entry in cache.values(): entry.pop('format_version', None)
        cache_path.write_text(json.dumps(cache))
        self.assertEqual(addresses(), first)
        self.assertEqual(len((self.root / 'geo_calls').read_text().splitlines()), 4)
        # Expired entries must be queried again.
        cache_path = self.root / 'geo.json'
        cache = json.loads(cache_path.read_text())
        for entry in cache.values(): entry['fetched_at'] = now - 8 * 86400
        cache_path.write_text(json.dumps(cache))
        (self.root / 'geo_fail').touch()
        self.assertEqual(addresses()['1.1.1.1'], 'Unknown')
        failed_calls = (self.root / 'geo_calls').read_text()
        self.assertEqual(addresses()['1.1.1.1'], 'Unknown')
        self.assertEqual((self.root / 'geo_calls').read_text(), failed_calls)
        cache_path.unlink()
        (self.root / 'geo_fail').unlink()
        (self.root / 'geo_bad_json').touch()
        self.assertEqual(addresses()['1.1.1.1'], 'Unknown')

    def test_audit_drop_only_sources_count_toward_min_events(self):
        now = int(time.time())
        self.write_index_journal([
            self.index_row(f'drop-{i}',
                           'portguard DROP SRC=192.0.2.9 DST=192.0.2.10 PROTO=TCP DPT=5202',
                           now - 10, kernel=True)
            for i in range(2)
        ])
        for mode in [('--no-index',), ('--index-path', str(self.root / 'audit.sqlite3'))]:
            with self.subTest(mode=mode):
                args = ('audit', *mode, '--no-geo')
                report = json.loads(self.run_cli(*args, '--json'))
                self.assertEqual(len(report['entries']), 1)
                entry = report['entries'][0]
                self.assertEqual(entry['ip'], '192.0.2.9')
                self.assertEqual(entry['denied_packets_logged'], 2)
                self.assertEqual(entry['destination_ports'], [5202])
                self.assertIn('192.0.2.9', self.run_cli(*args))
                self.assertEqual(len(json.loads(self.run_cli(*args, '--min-events', '2', '--json'))['entries']), 1)
                self.assertEqual(json.loads(self.run_cli(*args, '--min-events', '3', '--json'))['entries'], [])

    def test_audit_ip_sort_is_numeric_descending(self):
        now = int(time.time())
        ips = ['192.0.2.2', '192.0.2.10', '2001:db8::2', '2001:db8::10']
        self.write_index_journal([
            self.index_row(f'ip-sort-{i}', f'Failed password for root from {ip} port 1234 ssh2', now - 10)
            for i, ip in enumerate(ips)
        ])
        expected = ['2001:db8::10', '2001:db8::2', '192.0.2.10', '192.0.2.2']
        for mode in [('--no-index',), ('--index-path', str(self.root / 'audit.sqlite3'))]:
            with self.subTest(mode=mode):
                args = ('audit', *mode, '--sort', 'ip', '--no-geo', '--json')
                entries = json.loads(self.run_cli(*args))['entries']
                self.assertEqual([entry['ip'] for entry in entries], expected)
                limited = json.loads(self.run_cli(*args, '--limit', '2'))['entries']
                self.assertEqual([entry['ip'] for entry in limited], expected[:2])

    def test_audit_address_sort_applies_limit_after_geolocation(self):
        now = int(time.time())
        self.write_index_journal([
            self.index_row(f'address-{i}', f'Failed password for root from {ip} port 1234 ssh2', now - 10)
            for i, ip in enumerate(['192.0.2.1', '81.70.146.20', '81.70.146.21'])
        ])
        for mode in [('--no-index',), ('--index-path', str(self.root / 'audit.sqlite3'))]:
            with self.subTest(mode=mode):
                args = ('audit', *mode, '--sort', 'address', '--json')
                entries = json.loads(self.run_cli(*args))['entries']
                self.assertEqual([entry['ip'] for entry in entries],
                                 ['81.70.146.20', '81.70.146.21', '192.0.2.1'])
                limited = json.loads(self.run_cli(*args, '--limit', '1'))['entries']
                self.assertEqual(limited, entries[:1])
                # Without geolocation all labels tie, so IP is the deterministic tie-breaker.
                disabled = json.loads(self.run_cli(*args, '--no-geo', '--limit', '1'))['entries']
                self.assertEqual(disabled[0]['ip'], '192.0.2.1')

    def test_audit_large_queries_do_not_drop_records(self):
        journal = self.root / 'bin' / 'journalctl'
        journal.write_text('''#!/usr/bin/env python3
import json,sys,time
now=int(time.time())
def row(message,ago):
    return json.dumps({"MESSAGE":message,"SYSLOG_IDENTIFIER":"sshd",
        "__REALTIME_TIMESTAMP":str((now-ago)*1000000)})+"\\n"
old=row("Connection closed by 192.0.2.2 port 1234 [preauth]",2*86400)
recent=[row("Accepted publickey for root from 192.0.2.1 port 1234 ssh2",10),
        row("Failed password for root from 192.0.2.1 port 1234 ssh2",20)]
# More than the old 100000-row cap: complete output requires --no-tail.
if "--no-tail" in sys.argv and not any(a.startswith("--lines") for a in sys.argv):
    sys.stdout.write("".join(recent)+old*100000)
else: sys.stdout.write(old*100000)
''')
        journal.chmod(0o755)
        report = json.loads(self.run_cli('audit', '--since', '30d', '--json', '--no-geo'))
        self.assertFalse(report['truncated'])
        self.assertEqual(report['scanned_records'], 100002)
        first = report['entries'][0]
        self.assertEqual(first['ip'], '192.0.2.1')
        self.assertEqual(first['ssh_failures'], 1)
        self.assertEqual(first['ssh_successes'], 1)
        self.assertEqual(report['entries'][1]['ssh_connection_closed'], 100000)
        self.assertLess(first['first_seen_unix'], first['last_seen_unix'])

    def test_audit_longer_window_keeps_all_shorter_window_counts(self):
        journal = self.root / 'bin' / 'journalctl'
        journal.write_text('''#!/usr/bin/env python3
import json,sys,time
now=int(time.time())
cutoff=int(sys.argv[sys.argv.index("--since")+1].lstrip("@"))
rows=[]
for ago,count in [(20*86400,293),(60*86400,70)]:
    for _ in range(count):
        rows.append({"MESSAGE":"Invalid user root from 192.0.2.1 port 1234",
            "SYSLOG_IDENTIFIER":"sshd","__REALTIME_TIMESTAMP":str((now-ago)*1000000)})
for ago in [10,50*86400]:
    for kind in ["Failed password", "Accepted publickey"]:
        rows.append({"MESSAGE":kind+" for root from 192.0.2.1 port 1234 ssh2",
            "SYSLOG_IDENTIFIER":"sshd","__REALTIME_TIMESTAMP":str((now-ago)*1000000)})
for row in reversed(rows):
    if int(row["__REALTIME_TIMESTAMP"])//1000000>=cutoff:
        print(json.dumps(row))
''')
        journal.chmod(0o755)
        reports = [json.loads(self.run_cli('audit', '--since', window, '--json', '--no-geo'))
                   for window in ['30d', '100d']]
        short, long = [report['entries'][0] for report in reports]
        self.assertEqual(short['ssh_invalid_users'], 293)
        self.assertEqual(long['ssh_invalid_users'], 363)
        self.assertEqual(short['ssh_failures'], 1)
        self.assertEqual(long['ssh_failures'], 2)
        self.assertEqual(short['ssh_successes'], 1)
        self.assertEqual(long['ssh_successes'], 2)
        self.assertTrue(all(not report['truncated'] for report in reports))
        for field in ['ssh_failures', 'ssh_successes', 'ssh_invalid_users',
                      'ssh_connection_closed', 'ssh_connection_reset', 'denied_packets_logged']:
            self.assertGreaterEqual(long[field], short[field])

    def write_index_journal(self, rows):
        fixture = self.root / 'index_journal.jsonl'
        fixture.write_text(''.join(json.dumps(row) + '\n' for row in rows))
        journal = self.root / 'bin' / 'journalctl'
        journal.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
root=Path(os.environ["FAKE_NFT_DIR"])
with (root/"index_calls").open("a") as calls: calls.write(json.dumps(sys.argv[1:])+"\\n")
start=int(sys.argv[sys.argv.index("--since")+1].lstrip("@"))
end=int(sys.argv[sys.argv.index("--until")+1].lstrip("@"))
rows=[json.loads(line) for line in (root/"index_journal.jsonl").read_text().splitlines()]
for row in sorted(rows,key=lambda r:int(r["__REALTIME_TIMESTAMP"]),reverse=True):
    if start*1000000<=int(row["__REALTIME_TIMESTAMP"])<end*1000000:
        print(json.dumps(row))
if (root/"index_fail").exists():
    print("injected journal failure",file=sys.stderr)
    sys.exit(1)
''')
        journal.chmod(0o755)

    def index_row(self, cursor, message, timestamp, kernel=False):
        return {'__CURSOR': cursor, '__REALTIME_TIMESTAMP': str(timestamp * 1000000),
                'MESSAGE': message, 'SYSLOG_IDENTIFIER': 'kernel' if kernel else 'sshd',
                '_TRANSPORT': 'kernel' if kernel else 'syslog'}

    def test_audit_index_reuse_incremental_backfill_and_rebuild(self):
        now = int(time.time())
        recent = self.index_row('recent', 'Invalid user root from 192.0.2.1 port 1234', now - 20 * 86400)
        older = self.index_row('older', 'Invalid user root from 192.0.2.1 port 1234', now - 60 * 86400)
        rows = [recent, older]
        self.write_index_journal(rows)
        db = self.root / 'audit.sqlite3'
        def query(window='30d'):
            return json.loads(self.run_cli('audit', '--since', window, '--index-path', str(db), '--no-geo', '--json'))
        short = query()
        self.assertEqual(short['entries'][0]['ssh_invalid_users'], 1)
        self.assertEqual(short['index']['imported_records'], 1)
        self.assertEqual(query()['index']['imported_records'], 0)
        long = query('100d')
        self.assertEqual(long['entries'][0]['ssh_invalid_users'], 2)
        self.assertEqual(long['index']['imported_records'], 1)
        self.assertEqual(query('100d')['index']['imported_records'], 0)
        new = self.index_row('new', 'Accepted publickey for root from 192.0.2.1 port 1234 ssh2', int(time.time()))
        rows.append(new)
        self.write_index_journal(rows)
        updated = query('100d')
        self.assertEqual(updated['entries'][0]['ssh_successes'], 1)
        self.assertEqual(updated['index']['imported_records'], 1)
        self.assertEqual(query('100d')['entries'], updated['entries'])
        direct = json.loads(self.run_cli('audit', '--since', '100d', '--no-index', '--no-geo', '--json'))
        self.assertEqual(direct['entries'], updated['entries'])
        self.assertEqual(direct['scanned_records'], updated['scanned_records'])
        self.assertIsNone(direct['index'])
        # The source can replay the boundary record; cursor identity must deduplicate it.
        self.write_index_journal(rows + [new])
        self.assertEqual(query('100d')['entries'], updated['entries'])
        calls = [json.loads(line) for line in (self.root / 'index_calls').read_text().splitlines()]
        initial_start = int(calls[0][calls[0].index('--since') + 1].lstrip('@'))
        last_start = int(calls[-1][calls[-1].index('--since') + 1].lstrip('@'))
        self.assertGreater(last_start - initial_start, 29 * 86400)
        # Cached history survives source rotation; an explicit rebuild replaces it.
        self.write_index_journal([new])
        self.assertEqual(query('100d')['entries'][0]['ssh_invalid_users'], 2)
        status = json.loads(self.run_cli('audit', 'index', '--since', '100d', '--rebuild', '--index-path', str(db), '--json'))
        self.assertEqual(status['total_records'], 1)
        self.assertEqual(status['imported_records'], 1)
        rebuilt = query('100d')
        self.assertEqual(rebuilt['entries'], [])  # Only success remains below the default threshold.
        success = json.loads(self.run_cli('audit', '--index-path', str(db), '--no-geo', '--min-events', '0', '--json'))
        self.assertEqual(success['entries'][0]['ssh_successes'], 1)

    def test_audit_index_fills_gap_even_for_a_narrower_request(self):
        now = int(time.time())
        original = self.index_row('original', 'Invalid user root from 192.0.2.1 port 1234', now - 90 * 86400)
        self.write_index_journal([original])
        db = self.root / 'audit.sqlite3'
        self.run_cli('audit', 'index', '--since', '100d', '--index-path', str(db))
        with sqlite3.connect(db) as conn:
            conn.execute('UPDATE audit_coverage SET until=?', (now - 20 * 86400,))
        gap = self.index_row('gap', 'Invalid user root from 192.0.2.1 port 1234', now - 10 * 86400)
        self.write_index_journal([original, gap])
        narrow = json.loads(self.run_cli('audit', '--since', '1h', '--index-path', str(db), '--no-geo', '--json'))
        self.assertEqual(narrow['entries'], [])
        self.assertEqual(narrow['index']['imported_records'], 1)
        broad = json.loads(self.run_cli('audit', '--since', '30d', '--index-path', str(db), '--no-geo', '--json'))
        self.assertEqual(broad['entries'][0]['ssh_invalid_users'], 1)
        self.assertEqual(broad['index']['imported_records'], 0)

    def test_audit_index_concurrent_updates_do_not_double_count(self):
        now = int(time.time())
        self.write_index_journal([
            self.index_row('failed', 'Failed password for root from 192.0.2.1 port 1234 ssh2', now - 10),
            self.index_row('ok', 'Accepted publickey for root from 192.0.2.1 port 1234 ssh2', now),
        ])
        db = self.root / 'audit.sqlite3'
        command = [str(BINARY), 'audit', '--index-path', str(db), '--no-geo', '--json']
        workers = [subprocess.Popen(command, env=self.env, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE) for _ in range(2)]
        reports = []
        for worker in workers:
            stdout, stderr = worker.communicate(timeout=20)
            self.assertEqual(worker.returncode, 0, stdout + stderr)
            reports.append(json.loads(stdout))
        for report in reports:
            self.assertEqual(report['entries'][0]['ssh_failures'], 1)
            self.assertEqual(report['entries'][0]['ssh_successes'], 1)
            self.assertEqual(report['scanned_records'], 2)
        self.assertEqual(sum(report['index']['imported_records'] for report in reports), 2)

    def test_audit_index_failure_does_not_commit_rows_or_coverage(self):
        now = int(time.time())
        original = self.index_row('original', 'Failed password for root from 192.0.2.1 port 1234 ssh2', now - 10)
        self.write_index_journal([original])
        db = self.root / 'audit.sqlite3'
        args = ['audit', '--index-path', str(db), '--no-geo', '--json']
        self.run_cli(*args)
        with sqlite3.connect(db) as conn:
            original_coverage = conn.execute('SELECT * FROM audit_coverage').fetchall()
        new = self.index_row('new', 'Accepted publickey for root from 192.0.2.1 port 1234 ssh2', int(time.time()))
        self.write_index_journal([original, new])
        (self.root / 'index_fail').touch()
        self.assertIn('injected journal failure', self.run_cli(*args, ok=False))
        with sqlite3.connect(db) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM audit_records').fetchone()[0], 1)
            self.assertEqual(conn.execute('SELECT * FROM audit_coverage').fetchall(), original_coverage)
        (self.root / 'index_fail').unlink()
        missing_cursor = dict(new)
        missing_cursor.pop('__CURSOR')
        self.write_index_journal([original, new, missing_cursor])
        self.assertIn('__CURSOR', self.run_cli(*args, ok=False))
        with sqlite3.connect(db) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM audit_records').fetchone()[0], 1)
        self.write_index_journal([original, new])
        recovered = json.loads(self.run_cli(*args))
        self.assertEqual(recovered['entries'][0]['ssh_successes'], 1)
        self.assertEqual(recovered['index']['imported_records'], 1)
        # The parser/schema version cannot be silently reused after an upgrade.
        with sqlite3.connect(db) as conn:
            conn.execute('PRAGMA user_version=99')
        self.assertIn('索引版本不兼容', self.run_cli(*args, ok=False))
        self.run_cli('audit', 'index', '--index-path', str(db), '--since', '24h', '--rebuild')
        self.assertEqual(json.loads(self.run_cli(*args))['entries'][0]['ssh_successes'], 1)

    def test_audit_bad_records_have_only_a_short_warning(self):
        journal = self.root / 'bin' / 'journalctl'
        journal.write_text('#!/bin/sh\nprintf "not-json\\n"\n')
        journal.chmod(0o755)
        text = self.run_cli('audit', '--no-geo')
        self.assertIn('Warning: skipped 1 malformed journal records.', text)
        self.assertNotIn('登录失败不等于', text)
        self.assertNotIn('记录拦截来源', text)
        report = json.loads(self.run_cli('audit', '--json', '--no-geo'))
        self.assertEqual(report['malformed_records'], 1)
        self.assertTrue(report['notes'])

    def test_audit_errors_are_not_reported_as_no_attacks(self):
        journal = self.root / 'bin' / 'journalctl'
        journal.write_text('#!/bin/sh\necho "permission denied" >&2\nexit 1\n')
        journal.chmod(0o755)
        self.config.unlink()
        self.assertIn('permission denied', self.run_cli('audit', ok=False))

    def test_no_history_and_unowned_table(self):
        self.run_cli('rollback', ok=False)
        (self.root / 'kernel.json').write_text(json.dumps({'system': 'unchanged', 'acl': 'table inet portguard {}\n'}))
        self.assertIn('没有状态记录', self.run_cli('apply', ok=False))

if __name__ == '__main__':
    unittest.main(verbosity=2)
