#!/usr/bin/env python3
"""Actual parser/command acceptance in an ephemeral CI-only network namespace."""
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
from unittest.mock import patch
assert os.geteuid() == 0 and os.environ.get('GITHUB_ACTIONS') == 'true'
spec = importlib.util.spec_from_file_location('firewall_acceptance', Path(__file__).with_name('host-security-firewall.py'))
f = importlib.util.module_from_spec(spec)
spec.loader.exec_module(f)
if sys.argv[1:] != ['--namespace']:
    assert not sys.argv[1:]
    subprocess.run(['/usr/bin/unshare', '--net', sys.executable, '-I', __file__, '--namespace'], check=True, timeout=60)
    print('Isolated firewall namespace: real rules, counters, policy and set changes passed')
    raise SystemExit(0)
# Never change the runner's host firewall. This child has a separate network
# namespace. The production collector must reject it before any command executes.
assert not f.host_namespace()
try:
    f.snapshot_once()
    raise AssertionError('Non-host namespace accepted')
except ValueError:
    pass

def run(*arguments):
    return subprocess.run(arguments, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5).stdout
run('/usr/sbin/ip', 'link', 'set', 'lo', 'up')
run('/usr/sbin/nft', 'add', 'table', 'inet', 'appgog_ci')
run('/usr/sbin/nft', 'add', 'chain', 'inet', 'appgog_ci', 'input', '{ type filter hook input priority 0; policy accept; }')
run('/usr/sbin/nft', 'add', 'rule', 'inet', 'appgog_ci', 'input', 'counter', 'accept')
run('/usr/sbin/nft', 'add', 'set', 'inet', 'appgog_ci', 'allowed', '{ type ipv4_addr; }')
run('/usr/sbin/iptables', '-A', 'OUTPUT', '-p', 'udp', '-j', 'ACCEPT')
# This explicit test-only override lets the exact production capture/parser
# operate on controlled fixtures; it is never installed into the collector.
with patch.object(f, 'host_namespace', return_value=True):
    before = f.snapshot()
    assert f.valid_snapshot(before) and before['rules'] > 0
    original_counters = run('/usr/sbin/nft', '-j', 'list', 'ruleset')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as receiver, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        receiver.bind(('127.0.0.1', 0)); receiver.settimeout(2)
        sender.sendto(b'counter-only-test', receiver.getsockname())
        assert receiver.recv(64) == b'counter-only-test'
    assert original_counters != run('/usr/sbin/nft', '-j', 'list', 'ruleset')
    assert f.snapshot() == before, 'Traffic counters changed configuration fingerprint'
    run('/usr/sbin/nft', 'add', 'element', 'inet', 'appgog_ci', 'allowed', '{ 203.0.113.10 }')
    changed_set = f.snapshot()
    assert changed_set != before and changed_set['sources']['nftables'] != before['sources']['nftables']
    run('/usr/sbin/iptables', '-P', 'INPUT', 'DROP')
    assert f.snapshot() != changed_set, 'iptables policy change not detected'
