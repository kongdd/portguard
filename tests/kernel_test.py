#!/usr/bin/env python3
"""Real nftables + TCP/UDP tests. Must run in a NEW network namespace."""
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading

parent = os.environ.get('PORTGUARD_TEST_PARENT_NS')
if not parent or os.readlink('/proc/self/ns/net') == parent:
    raise SystemExit('Refusing to run: create a separate network namespace first (see README).')
binary = Path(os.environ.get('PORTGUARD_BIN', 'target/debug/portguard')).resolve()
env = os.environ.copy()
env.pop('SSH_CONNECTION', None)

def nft(script):
    subprocess.run(['nft', '-f', '-'], input=script, text=True, check=True, capture_output=True)

subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
subprocess.run(['ip', '-6', 'addr', 'add', '::2/128', 'dev', 'lo'], check=True)
nft('table inet system_test { chain input { type filter hook input priority 0; policy accept; } }')
original = subprocess.check_output(['nft', '-nn', 'list', 'table', 'inet', 'system_test'], text=True)
servers = []
stop = threading.Event()

def echo(server, udp):
    while not stop.is_set():
        try:
            if udp:
                data, address = server.recvfrom(1024)
                server.sendto(data, address)
            else:
                connection, _ = server.accept()
                with connection:
                    connection.settimeout(0.3)
                    data = connection.recv(1024)
                    if data:
                        connection.sendall(data)
        except (TimeoutError, OSError):
            pass

for family, address in [(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')]:
    for udp in (False, True):
        server = socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
        if family == socket.AF_INET6:
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        server.bind((address, 55202))
        if not udp:
            server.listen()
        server.settimeout(0.1)
        threading.Thread(target=echo, args=(server, udp), daemon=True).start()
        servers.append(server)

def reaches(source, udp=False):
    family = socket.AF_INET6 if ':' in source else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as client:
        client.settimeout(0.3)
        client.bind((source, 0))
        try:
            client.connect(('::1' if family == socket.AF_INET6 else '127.0.0.1', 55202))
            client.send(b'test')
            return client.recv(16) == b'test'
        except (TimeoutError, OSError):
            return False

with tempfile.TemporaryDirectory() as folder:
    config = Path(folder) / 'firewall.toml'
    def write(allow, enabled=True, ports=None):
        config.write_text('protected_ports=[22]\n[rules.test]\nenabled=' + str(enabled).lower() + '\nports=' + json.dumps(ports or ['55200-55205']) + '\nallow=' + json.dumps(allow) + '\n')
    def cli(*args, ok=True):
        r = subprocess.run([str(binary), '-c', str(config), *args], env=env, text=True, capture_output=True)
        assert (r.returncode == 0) == ok, r.stdout + r.stderr
        return r
    def assert_policy(v4, v6, description):
        for udp in (False, True):
            assert reaches('127.0.0.2', udp) == v4, description + ' IPv4 allowed source'
            assert not reaches('127.0.0.3', udp), description + ' IPv4 denied source'
            assert reaches('::2', udp) == v6, description + ' IPv6'
        print('PASS:', description)
    write(['127.0.0.2', '::2'])
    cli('check')
    cli('apply')
    assert_policy(True, True, 'dual-stack TCP/UDP range filtering')
    # Overlapping CIDRs in a single allowlist merge correctly in actual nftables sets.
    write(['127.0.0.2/31', '127.0.0.2', '::2'])
    cli('apply')
    for udp in (False, True):
        assert reaches('127.0.0.2', udp)
        assert reaches('127.0.0.3', udp)
        assert reaches('::2', udp)
    print('PASS: overlapping CIDRs merged')
    cli('rollback')
    assert_policy(True, True, 'rollback restores filtering')
    write(['127.0.0.2'])
    cli('apply')
    assert_policy(True, False, 'IPv4 allowlist does not permit IPv6')
    cli('rollback')
    assert_policy(True, True, 'dual-stack rollback')
    old = subprocess.check_output(['nft', '-nn', 'list', 'table', 'inet', 'portguard'], text=True)
    write(['*'], ports=['20-30'])
    cli('apply', ok=False)
    assert old == subprocess.check_output(['nft', '-nn', 'list', 'table', 'inet', 'portguard'], text=True)
    print('PASS: protected SSH rejection preserves rules')
    write([])
    cli('apply')
    for source in ('127.0.0.2', '127.0.0.3', '::2'):
        for udp in (False, True):
            assert not reaches(source, udp)
    print('PASS: empty allowlist denies both families/protocols')
    write(['*'])
    cli('apply')
    for source in ('127.0.0.2', '127.0.0.3', '::2'):
        for udp in (False, True):
            assert reaches(source, udp)
    print('PASS: wildcard removes local filtering')
    nft('add rule inet system_test input tcp dport 55202 drop')
    assert not reaches('127.0.0.2')
    nft('flush chain inet system_test input')
    print('PASS: wildcard respects other firewall tables')
    write([], enabled=False)
    cli('apply')
    assert reaches('127.0.0.3')
    cli('disable')
    assert 'portguard' not in subprocess.check_output(['nft', 'list', 'tables'], text=True)
    assert original == subprocess.check_output(['nft', '-nn', 'list', 'table', 'inet', 'system_test'], text=True)
    print('PASS: disable removes only our table')
stop.set()
for server in servers:
    server.close()
print('All real-kernel tests passed.')
