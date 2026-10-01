#!/usr/bin/env python3
"""Exercise real journalctl ingestion using synthetic sshd messages (not real attacks)."""
import json
import os
from pathlib import Path
import subprocess

binary = Path(os.environ.get('PORTGUARD_BIN', 'target/debug/portguard')).resolve()
source = '192.0.2.254'
def audit():
    result = subprocess.check_output([str(binary), 'audit', '--since', '1m', '--ip', source, '--json'], text=True)
    entries = json.loads(result)['entries']
    return entries[0] if entries else {'ssh_failures': 0, 'ssh_successes': 0, 'denied_packets_logged': 0}

before = audit()
for message in [
    f'Failed password for invalid user portguard_test from {source} port 60321 ssh2',
    f'Invalid user portguard_test from {source} port 60321',
    f'Failed publickey for portguard_test from {source} port 60321 ssh2',
    f'Accepted publickey for portguard_test from {source} port 60321 ssh2',
]:
    subprocess.run(['logger', '-t', 'sshd', '--', message], check=True)
# A syslog message impersonating kernel text must not count as a kernel drop.
subprocess.run(['logger', '-t', 'kernel', '--', f'portguard DROP SRC={source} DPT=5202'], check=True)
subprocess.run(['journalctl', '--sync'], check=True)
after = audit()
assert after['ssh_failures'] - before['ssh_failures'] == 2, after
assert after['ssh_successes'] - before['ssh_successes'] == 1, after
assert after['denied_packets_logged'] == before['denied_packets_logged'], after
print('PASS: real journalctl query, SSH aggregation and syslog/kernel separation')
