#!/usr/bin/env python3
"""Reproducible index benchmark using synthetic logs; no network or firewall changes."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

parser = argparse.ArgumentParser()
parser.add_argument('--records', type=int, default=500000)
args = parser.parse_args()
if args.records <= 0:
    parser.error('--records must be positive')
binary = Path(os.environ.get('PORTGUARD_BIN', 'target/release/portguard')).resolve()
with tempfile.TemporaryDirectory(prefix='portguard-index-bench-') as directory:
    root = Path(directory)
    journal = root / 'journalctl'
    journal.write_text('''#!/usr/bin/env python3
import json,os,sys
start=int(sys.argv[sys.argv.index("--since")+1].lstrip("@"))
end=int(sys.argv[sys.argv.index("--until")+1].lstrip("@"))
stamp=int(os.environ["BENCH_STAMP"])
if start<=stamp<end:
    for i in range(int(os.environ["BENCH_RECORDS"])):
        print(json.dumps({"__CURSOR":"bench-"+str(i),"__REALTIME_TIMESTAMP":str(stamp*1000000),
            "SYSLOG_IDENTIFIER":"sshd","MESSAGE":"Invalid user root from 192.0.2.1 port 1234"}))
''')
    journal.chmod(0o755)
    env = dict(os.environ, PATH=str(root) + ':' + os.environ['PATH'],
               BENCH_STAMP=str(int(time.time()) - 40 * 86400), BENCH_RECORDS=str(args.records))
    command = [str(binary), 'audit', '--since', '100d', '--no-geo', '--json',
               '--index-path', str(root / 'audit.sqlite3')]
    def run(extra=()):
        start = time.monotonic()
        report = json.loads(subprocess.check_output([*command, *extra], env=env, text=True))
        return time.monotonic() - start, report
    cold, initial = run()
    warm, cached = run()
    direct, uncached = run(('--no-index',))
    assert initial['entries'] == cached['entries'] == uncached['entries']
    assert cached['index']['imported_records'] == 0
    assert cached['scanned_records'] == args.records
    assert cached['entries'][0]['ssh_invalid_users'] == args.records
    print(f'Synthetic records: {args.records:,}; identical indexed/direct counts')
    print(f'Cold index: {cold:.3f}s; warm query: {warm:.3f}s; direct parse: {direct:.3f}s')
    print(f'Warm speedup vs direct parse: {direct / warm:.1f}x')
