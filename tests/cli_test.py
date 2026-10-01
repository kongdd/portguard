#!/usr/bin/env python3
"""Full CLI subprocess tests with a fake nft for deterministic fault injection."""
import json
import os
from pathlib import Path
import shutil
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

    def tearDown(self):
        self.temp.cleanup()

    def write(self, allow, protected='[22]', port='5200-5300'):
        self.config.write_text(f'# Keep this comment\nprotected_ports={protected}\n[rules.nas]\nports=["{port}"]\nallow={json.dumps(allow)}\n')

    def run_cli(self, *args, ok=True, env=None):
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
        row('portguard DROP SRC=2001:db8::1 DST=2001:db8::2 PROTO=TCP DPT=5202', ssh=False)
        row('Failed password for root from 198.51.100.1 port 1234 ssh2', ago=90000)
        row('Accepted password for root from 192.0.2.2 port 1234 ssh2')
        fixture.write_text(''.join(json.dumps(r) + '\n' for r in rows))
        journal = self.root / 'bin' / 'journalctl'
        journal.write_text('#!/usr/bin/env python3\nfrom pathlib import Path\nimport os,sys\nroot=Path(os.environ["FAKE_NFT_DIR"])\n(root/"journal_args").write_text(" ".join(sys.argv[1:]))\nprint((root/"journal.jsonl").read_text(),end="")\n')
        journal.chmod(0o755)
        self.config.unlink()  # audit must not need firewall.toml or nft.
        result = json.loads(self.run_cli('audit', '--json'))
        self.assertEqual(len(result['entries']), 2)
        first = result['entries'][0]
        self.assertEqual(first['ip'], '192.0.2.1')
        self.assertEqual(first['ssh_failures'], 3)
        self.assertEqual(first['ssh_successes'], 1)
        self.assertEqual(result['entries'][1]['destination_ports'], [5202])
        filtered = json.loads(self.run_cli('audit', '--ip', '2001:db8::1', '--json'))
        self.assertEqual(len(filtered['entries']), 1)
        minimum = json.loads(self.run_cli('audit', '--min-events', '3', '--limit', '1', '--json'))
        self.assertEqual(len(minimum['entries']), 1)
        self.assertIn('SYSLOG_IDENTIFIER=sshd + _TRANSPORT=kernel',
                      (self.root/'journal_args').read_text().replace(' SYSLOG_IDENTIFIER=sshd-session', ''))
        self.run_cli('audit', '--since', '中文', ok=False)
        self.run_cli('audit', '--limit', '0', ok=False)

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
