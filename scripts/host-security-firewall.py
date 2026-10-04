#!/usr/bin/env python3
"""Independent, fixed-command host firewall collector; never changes firewall rules."""
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

spec = importlib.util.spec_from_file_location('appgog_host_security_helpers', Path(__file__).with_name('host-security-agent.py'))
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
STATE_DIR = Path('/var/lib/appgog-security')
CONFIG = Path('/usr/local/lib/appgog-security/response-config.json')
REPORT = STATE_DIR / 'firewall-report.json'
BASELINE = STATE_DIR / 'firewall-baseline.json'
NAMESPACE_PROOF = STATE_DIR / 'firewall-namespace.json'
SERVICE_COLLECTION = False
COMMANDS = (
    ('nftables', '/usr/sbin/nft', ('-j', '-s', '-n', 'list', 'ruleset'), True),
    ('iptables', '/usr/sbin/iptables-save', ('-M', '/bin/false'), True),
    ('ip6tables', '/usr/sbin/ip6tables-save', ('-M', '/bin/false'), True),
    ('iptables-legacy', '/usr/sbin/iptables-legacy-save', ('-M', '/bin/false'), False),
    ('ip6tables-legacy', '/usr/sbin/ip6tables-legacy-save', ('-M', '/bin/false'), False),
)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def installation_root():
    item = json.loads(agent.read_state(CONFIG, 32768))
    root = item.get('root') if isinstance(item, dict) else None
    if not isinstance(item, dict) or type(item.get('schema')) is not int or item['schema'] != 1 or not isinstance(root, str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+', root) or str(Path(root).resolve()) != root:
        raise ValueError('installation contract unavailable')
    return root


def trusted_alias_chain(path):
    pending, current, hops = list(Path(path).parts[1:]), Path('/'), 0
    while pending:
        current = current / pending.pop(0)
        metadata = current.lstat()
        if metadata.st_uid != 0:
            raise ValueError('untrusted executable path owner')
        if stat.S_ISLNK(metadata.st_mode):
            hops += 1
            if hops > 40:
                raise ValueError('executable alias depth')
            linked = Path(os.readlink(current))
            linked = linked if linked.is_absolute() else current.parent / linked
            # Normalise dot components without following additional links yet.
            linked = Path(os.path.normpath(str(linked)))
            pending = list(linked.parts[1:]) + pending
            current = Path('/')
        else:
            if metadata.st_mode & 0o022 or (pending and not stat.S_ISDIR(metadata.st_mode)):
                raise ValueError('untrusted executable path')
    return current


def trusted_executable(path):
    # Distribution alternatives may be symlinks; the final file and every resolved
    # parent must be root-owned and non-writable to other users.
    target = trusted_alias_chain(path)
    metadata = target.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022 or not metadata.st_mode & 0o111:
        raise ValueError('untrusted inspection binary')
    for folder in (target.parent, *target.parent.parents):
        metadata = folder.stat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('untrusted inspection directory')
    # Keep the original basename: distro xtables multicall dispatch uses argv[0].
    # Validate original parent entries too; /usr/sbin may resolve through /sbin.
    for folder in (Path(path).parent, *Path(path).parent.parents):
        metadata = folder.stat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('untrusted invocation directory')
    return path


def invocation_id():
    value = os.environ.get('INVOCATION_ID', '')
    if not re.fullmatch(r'[a-f0-9]{32}', value):
        raise ValueError('service invocation unavailable')
    return value


def boot_id():
    with open('/proc/sys/kernel/random/boot_id', 'r', encoding='ascii') as stream:
        value = stream.read(128).strip()
    if not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', value):
        raise ValueError('boot identity unavailable')
    return value


def prepare_namespace():
    # A fixed privileged preflight reads kernel identity only. It never reads
    # rules, launches tools, accepts paths, or writes outside this private file.
    invocation = invocation_id()
    host, current = os.stat('/proc/1/ns/net'), os.stat('/proc/self/ns/net')
    if (current.st_dev, current.st_ino) != (host.st_dev, host.st_ino):
        raise ValueError('preflight is not in the host namespace')
    agent.atomic_json(NAMESPACE_PROOF, {'schema': 1, 'invocation': invocation,
        'boot': boot_id(), 'created': time.monotonic(),
        'dev': host.st_dev, 'ino': host.st_ino})


def host_namespace():
    current = os.stat('/proc/self/ns/net')
    if SERVICE_COLLECTION:
        # The reduced-capability collector cannot inspect PID 1 through procfs.
        # Consume only the private proof refreshed by ExecStartPre for this
        # exact systemd activation and boot. Never fall back on a denied lookup.
        proof = json.loads(agent.read_state(NAMESPACE_PROOF, 1024), object_pairs_hook=unique_object)
        if not isinstance(proof, dict) or set(proof) != {'schema', 'invocation', 'boot', 'created', 'dev', 'ino'} or type(proof.get('schema')) is not int or proof['schema'] != 1:
            raise ValueError('invalid namespace proof')
        if proof['invocation'] != invocation_id() or proof['boot'] != boot_id():
            raise ValueError('foreign namespace proof')
        now = time.monotonic()
        if type(proof['created']) not in (int, float) or not 0 <= proof['created'] <= now:
            raise ValueError('invalid namespace proof time')
        if now - proof['created'] > 120 or any(type(proof[field]) is not int or not 0 <= proof[field] < 2 ** 64 for field in ('dev', 'ino')):
            raise ValueError('stale or invalid namespace proof')
        identity = (proof['dev'], proof['ino'])
    else:
        # Normal root CLI always checks PID 1 directly, ignoring any saved proof.
        host = os.stat('/proc/1/ns/net')
        identity = (host.st_dev, host.st_ino)
    if (current.st_dev, current.st_ino) != identity:
        return False
    binary = trusted_executable('/usr/bin/systemd-detect-virt')
    result = subprocess.run([binary, '--container', '--quiet'], stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2,
        cwd='/', env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C'})
    if result.returncode not in (0, 1):
        raise ValueError('container detection unavailable')
    return result.returncode == 1


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def validate_json_budget(value):
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > 32 or count > 32768:
            raise ValueError('JSON complexity budget')
        if isinstance(item, dict):
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif type(item) not in (str, int, bool, type(None)):
            raise ValueError('unsupported JSON value')


def nft_snapshot(payload):
    if len(payload) > 262144:
        raise ValueError('nftables byte budget')
    data = json.loads(payload, object_pairs_hook=unique_object)
    validate_json_budget(data)
    if not isinstance(data, dict) or set(data) != {'nftables'} or not isinstance(data['nftables'], list) or len(data['nftables']) > 4096:
        raise ValueError('invalid nftables snapshot')
    items, metadata_seen, rules = [], False, 0
    allowed = {'table', 'chain', 'rule', 'set', 'map', 'element', 'flowtable', 'counter', 'quota', 'limit', 'ct helper', 'ct timeout', 'ct expectation', 'synproxy', 'secmark'}
    for item in data['nftables']:
        if not isinstance(item, dict) or len(item) != 1:
            raise ValueError('invalid nftables entry')
        kind, value = next(iter(item.items()))
        if kind == 'metainfo':
            if metadata_seen or not isinstance(value, dict) or type(value.get('json_schema_version')) is not int or value['json_schema_version'] != 1:
                raise ValueError('unsupported nftables schema')
            metadata_seen = True
            continue
        if kind not in allowed or not isinstance(value, dict):
            raise ValueError('unsupported nftables object')
        # Do not discard unfamiliar expression fields: their exact content is
        # included in the digest. Rule order and dynamic set elements are retained.
        items.append(item)
        rules += kind == 'rule'
    if not metadata_seen:
        raise ValueError('missing nftables schema')
    return {'digest': digest(items), 'rules': rules}


def iptables_snapshot(payload):
    if len(payload) > 262144:
        raise ValueError('iptables byte budget')
    text = payload.decode('utf-8', errors='strict') if isinstance(payload, bytes) else payload
    lines, table, count = [], None, 0
    for line in text.splitlines():
        if not line or line.startswith('#'):
            continue
        if len(line) > 8192:
            raise ValueError('iptables line budget')
        if line.startswith('*'):
            if table is not None or not re.fullmatch(r'\*[A-Za-z0-9_-]+', line):
                raise ValueError('invalid table header')
            table = line[1:]
        elif line == 'COMMIT':
            if table is None:
                raise ValueError('unexpected table commit')
            table = None
        elif line.startswith(':'):
            if table is None or not re.fullmatch(r':[A-Za-z0-9_.:+-]+ [A-Za-z-]+ \[\d+:\d+\]', line):
                raise ValueError('invalid chain')
            # Chain traffic counts do not represent configuration changes.
            line = re.sub(r'\[\d+:\d+\]$', '[0:0]', line)
        elif line.startswith('-A '):
            if table is None:
                raise ValueError('rule outside table')
            count += 1
        else:
            raise ValueError('unsupported iptables output')
        lines.append(line)
        if len(lines) > 8192:
            raise ValueError('iptables rule budget')
    if table is not None:
        raise ValueError('incomplete iptables output')
    return {'digest': digest(lines), 'rules': count}


def snapshot_once(deadline=None):
    if not host_namespace():
        raise ValueError('not the host network namespace')
    sources = {}
    deadline = deadline if deadline is not None else time.monotonic() + 15
    for name, path, arguments, required in COMMANDS:
        if time.monotonic() >= deadline:
            raise ValueError('snapshot time budget')
        try:
            binary = trusted_executable(path)
        except FileNotFoundError:
            if required or Path(path).is_symlink():
                raise ValueError('required inspection tool missing')
            continue
        payload = agent.bounded_command_output([binary, *arguments])
        if time.monotonic() > deadline:
            raise ValueError('snapshot time budget')
        sources[name] = nft_snapshot(payload) if name == 'nftables' else iptables_snapshot(payload)
    return {'digest': digest(sources), 'sources': sources,
            'rules': sum(value['rules'] for value in sources.values())}


def snapshot():
    deadline = time.monotonic() + 30
    first, second = snapshot_once(deadline), snapshot_once(deadline)
    if first != second:
        raise ValueError('firewall changed during capture')
    return first


def valid_snapshot(item):
    if not isinstance(item, dict) or set(item) != {'digest', 'sources', 'rules'} or not isinstance(item.get('digest'), str) or not re.fullmatch(r'[a-f0-9]{64}', item['digest']):
        return False
    sources = item['sources']
    names = {row[0] for row in COMMANDS}
    if not isinstance(sources, dict) or not {'nftables', 'iptables', 'ip6tables'} <= sources.keys() <= names:
        return False
    for value in sources.values():
        if not isinstance(value, dict) or set(value) != {'digest', 'rules'} or not isinstance(value.get('digest'), str) or not re.fullmatch(r'[a-f0-9]{64}', value['digest']) or type(value['rules']) is not int or not 0 <= value['rules'] <= 8192:
            return False
    return type(item['rules']) is int and item['rules'] == sum(value['rules'] for value in sources.values()) and item['digest'] == digest(sources)


def collect():
    root = installation_root()
    result = {'schema': 1, 'root': root, 'checked_at': datetime.now(timezone.utc).isoformat(), 'state': 'unavailable'}
    try:
        current = snapshot()
        if not valid_snapshot(current):
            raise ValueError('invalid firewall summary')
        result.update(state='finished', snapshot=current)
    except (OSError, ValueError, TypeError, RecursionError, subprocess.TimeoutExpired):
        pass
    agent.atomic_json(REPORT, result)
    return result


def approve(expected):
    if not re.fullmatch(r'[a-f0-9]{64}', expected):
        raise ValueError('exact SHA-256 fingerprint required')
    root, current = installation_root(), snapshot()
    if not valid_snapshot(current) or current['digest'] != expected:
        raise ValueError('firewall changed or approval does not match')
    # Persist a fresh independent observation before advancing trust. Failed writes,
    # unavailable collection or intervening rule changes leave the old baseline intact.
    observed = collect()
    if observed.get('state') != 'finished' or observed.get('root') != root or observed.get('snapshot') != current:
        raise ValueError('firewall changed or follow-up collection unavailable')
    agent.atomic_json(BASELINE, {'schema': 1, 'root': root, 'approved_at': datetime.now(timezone.utc).isoformat(), 'snapshot': current})


def main(arguments):
    global SERVICE_COLLECTION
    if os.geteuid() != 0:
        raise ValueError('root required')
    if arguments == ['prepare-namespace']:
        prepare_namespace()
    elif arguments == ['collect-service']:
        SERVICE_COLLECTION = True
        collect()
    elif arguments == ['collect']:
        collect()
    elif arguments == ['fingerprint']:
        print(snapshot()['digest'])
    elif len(arguments) == 2 and arguments[0] == 'approve':
        approve(arguments[1])
        print('防火墙基线已批准；请重新扫描核对，不自动改规则。')
    elif arguments == ['status']:
        report = json.loads(agent.read_state(REPORT, 32768))
        print(json.dumps(report, ensure_ascii=False))
    elif arguments == ['menu']:
        print('运行时防火墙：只读检查宿主当前网络命名空间，不自动修复规则。')
        print('先通过可信控制台检查实际 nftables/iptables 规则；合法 Docker 网络变化也会告警。')
        while True:
            action = input('1.采集  2.指纹与批准  3.状态  0.返回：').strip()
            if action in ('0', ''):
                return
            if action == '1':
                collect()
                print('已采集，后台重新扫描后显示结论。')
            elif action == '2':
                current = snapshot()
                print('当前指纹：' + current['digest'])
                value = input('独立核验合法后输入完整 SHA-256（留空取消）：').strip()
                if value:
                    approve(value)
            elif action == '3':
                main(['status'])
    else:
        raise ValueError('use collect|fingerprint|approve SHA256|status|menu')


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, TypeError, RecursionError, subprocess.TimeoutExpired):
        print('防火墙检查不可用或批准失败；请核对工具、权限与完整指纹，旧基线保留。', file=sys.stderr)
        raise SystemExit(1)
