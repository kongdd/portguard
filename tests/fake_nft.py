#!/usr/bin/env python3
"""Fault-injection backend only. Never used by the shipped binary or installer."""
import json
import os
from pathlib import Path
import sys
import time

root = Path(os.environ['FAKE_NFT_DIR'])
state = root / 'kernel.json'
args = [a for a in sys.argv[1:] if a != '-nn']
kernel = json.loads(state.read_text()) if state.exists() else {'system': 'unchanged', 'acl': ''}

def die(message):
    print(message, file=sys.stderr)
    sys.exit(1)

if args == ['list', 'tables']:
    print('table inet system_firewall')
    if kernel['acl']:
        print('table inet portguard')
elif args == ['list', 'table', 'inet', 'portguard']:
    if (root / 'fail_snapshot_once').exists():
        (root / 'fail_snapshot_once').unlink()
        die('injected snapshot failure')
    print(kernel['acl'], end='')
elif args in [['-c', '-f', '-'], ['-f', '-']]:
    body = sys.stdin.read()
    if 'flush ruleset' in body or 'system_firewall' in body:
        die('attempt to alter unrelated firewall')
    if args[0] == '-c':
        if (root / 'fail_check_once').exists():
            (root / 'fail_check_once').unlink()
            die('injected validation failure')
        sys.exit(0)
    if (root / 'fail_apply_once').exists():
        (root / 'fail_apply_once').unlink()
        die('injected atomic apply failure')
    prefix = 'delete table inet portguard\n'
    if body.startswith(prefix):
        body = body[len(prefix):]
    kernel['acl'] = body
    state.write_text(json.dumps(kernel))
    with (root / 'batches.log').open('a') as f:
        f.write(json.dumps(sys.argv[1:]) + '\n')
    if (root / 'crash_after_apply').exists():
        (root / 'crash_after_apply').unlink()
        (root / 'applied.marker').touch()
        time.sleep(30)
    if (root / 'snapshot_after_apply').exists():
        (root / 'snapshot_after_apply').unlink()
        (root / 'fail_snapshot_once').touch()
else:
    die('unexpected nft arguments: ' + repr(args))
