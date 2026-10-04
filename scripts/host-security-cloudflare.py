#!/usr/bin/env python3
"""Fixed Cloudflare GET-only collector. Secrets and baselines stay outside business containers."""
import getpass
import hashlib
import json
import os
import re
import ssl
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

CONFIG_DIR = Path('/etc/appgog-security')
STATE_DIR = Path('/var/lib/appgog-security')
CONFIG = CONFIG_DIR / 'cloudflare-monitor.json'
TOKEN = CONFIG_DIR / 'cloudflare-read.token'
BASELINE = STATE_DIR / 'cloudflare-baseline.json'
REPORT = STATE_DIR / 'cloudflare-report.json'
API = 'https://api.cloudflare.com/client/v4'
MAX_BYTES = 1024 * 1024
MAX_REQUESTS = 32
DEADLINE_SECONDS = 30
GROUPS = {
    'dns': 'Cloudflare DNS',
    'workers': 'Cloudflare Workers 路由',
    'rules': 'Cloudflare 重定向与安全规则',
    'settings': 'Cloudflare HTTPS 与站点设置',
}
HEX_ID = re.compile(r'[a-f0-9]{32}\Z')
DIGEST = re.compile(r'[a-f0-9]{64}\Z')


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True,
        separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def private_parent(path, create=False, require_private=True):
    parent = Path(path).absolute().parent
    if create and not parent.exists():
        private_parent(parent, require_private=False)
        parent.mkdir(mode=0o700)
    for folder in (parent, *parent.parents):
        metadata = folder.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('untrusted parent')
    if require_private and parent.stat().st_mode & 0o077:
        raise ValueError('state directory must be private')


def read_private(path, limit=MAX_BYTES):
    private_parent(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_nlink != 1 or before.st_mode & 0o077:
            raise ValueError('untrusted private file')
        data = os.read(fd, limit + 1)
        after = os.fstat(fd)
        if len(data) > limit or len(data) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('incomplete private file')
        return data
    finally:
        os.close(fd)


def write_private(path, payload):
    private_parent(path, create=True)
    if path.exists() or path.is_symlink():
        read_private(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_json(path, value):
    payload = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()
    if len(payload) > MAX_BYTES:
        raise ValueError('state size limit')
    write_private(path, payload)


def load_config():
    value = json.loads(read_private(CONFIG, 4096))
    if not isinstance(value, dict) or set(value) != {'schema', 'zone_id'} or value['schema'] != 1 or not isinstance(value['zone_id'], str) or not HEX_ID.fullmatch(value['zone_id']):
        raise ValueError('invalid scope')
    token = read_private(TOKEN, 512).decode('ascii').strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{20,256}', token):
        raise ValueError('invalid credential')
    return value, token


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        raise ValueError('redirect rejected')


class Client:
    def __init__(self, token):
        self.token = token
        self.deadline = time.monotonic() + DEADLINE_SECONDS
        self.requests = 0
        # Ignore environment proxy settings. TLS verification always stays enabled.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()))

    def get(self, path):
        if not (re.fullmatch(r'/zones/[a-f0-9]{32}(?:/(?:workers/routes|pagerules|rulesets/[a-f0-9]{32}|settings/(?:ssl|always_use_https|min_tls_version|security_level)))?', path)
                or re.fullmatch(r'/zones/[a-f0-9]{32}/dns_records\?page=[1-4]&per_page=1000', path)
                or re.fullmatch(r'/zones/[a-f0-9]{32}/rulesets\?per_page=50(?:&cursor=(?:[A-Za-z0-9._~-]|%[0-9A-F]{2}){1,1536})?', path)):
            raise ValueError('endpoint outside read-only allowlist')
        self.requests += 1
        remaining = self.deadline - time.monotonic()
        if self.requests > MAX_REQUESTS or remaining <= 0:
            raise ValueError('request budget exhausted')
        request = urllib.request.Request(API + path, method='GET',
            headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/json'})
        with self.opener.open(request, timeout=min(5, remaining)) as response:
            if response.status != 200 or response.geturl() != API + path:
                raise ValueError('unexpected API response')
            chunks, size = [], 0
            while True:
                if time.monotonic() > self.deadline:
                    raise ValueError('response deadline exceeded')
                chunk = response.read(min(65536, MAX_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > MAX_BYTES:
                    raise ValueError('API response exceeds budget')
        payload = json.loads(b''.join(chunks))
        if not isinstance(payload, dict) or payload.get('success') is not True or 'result' not in payload or payload.get('errors'):
            raise ValueError('unsuccessful API response')
        return payload


def list_result(payload, maximum=4096):
    rows = payload.get('result')
    if not isinstance(rows, list) or len(rows) > maximum or any(not isinstance(row, dict) for row in rows):
        raise ValueError('incomplete collection')
    info = payload.get('result_info')
    if info is not None:
        if not isinstance(info, dict) or not isinstance(info.get('cursors', {}), dict) or info.get('total_pages', 1) not in (0, 1) or info.get('total_count', len(rows)) != len(rows) or info.get('cursors', {}).get('after') or info.get('cursor'):
            raise ValueError('unexpected pagination')
    return rows


def dns_snapshot(client, prefix):
    rows, expected, pages = [], None, None
    for page in range(1, 5):
        payload = client.get(prefix + '/dns_records?page=' + str(page) + '&per_page=1000')
        part = payload.get('result')
        info = payload.get('result_info')
        if not isinstance(part, list) or any(not isinstance(row, dict) for row in part) or len(part) > 1000 or not isinstance(info, dict):
            raise ValueError('invalid DNS page')
        total, total_pages = info.get('total_count'), info.get('total_pages')
        if type(total) is not int or type(total_pages) is not int or not 0 <= total <= 4000 or not 0 <= total_pages <= 4 or info.get('page') != page or info.get('count', len(part)) != len(part):
            raise ValueError('DNS coverage limit')
        if expected is not None and (expected != total or pages != total_pages):
            raise ValueError('DNS changed during pagination')
        expected, pages = total, total_pages
        rows.extend(part)
        if page >= max(1, pages):
            break
    if len(rows) != expected:
        raise ValueError('incomplete DNS collection')
    ids = [row.get('id') for row in rows]
    if any(not isinstance(item, str) or not HEX_ID.fullmatch(item) for item in ids) or len(set(ids)) != len(ids):
        raise ValueError('duplicate DNS records')
    for row in rows:
        if any(not isinstance(row.get(key), str) for key in ('name', 'type', 'content')) or type(row.get('ttl')) is not int:
            raise ValueError('malformed DNS record')
    # Exclude timestamps; compare semantic fields and provider record identities.
    clean = [{key: value for key, value in row.items() if key not in {'created_on', 'modified_on', 'comment_modified_on', 'tags_modified_on'}} for row in rows]
    return {'records': sorted(clean, key=lambda row: row['id'])}


def ruleset_listing(client, prefix):
    rows, cursors = [], set()
    path = prefix + "/rulesets?per_page=50"
    for _page in range(4):
        payload = client.get(path)
        part = payload.get("result")
        info = payload.get("result_info", {})
        if not isinstance(part, list) or any(not isinstance(row, dict) for row in part) or len(part) > 16 or not isinstance(info, dict):
            raise ValueError("invalid ruleset page")
        pagination = info.get("cursors", {})
        if not isinstance(pagination, dict) or set(pagination) - {"after"}:
            raise ValueError("invalid ruleset pagination")
        rows.extend(part)
        if len(rows) > 16:
            raise ValueError("ruleset coverage limit")
        cursor = pagination.get("after")
        if cursor is None:
            return rows
        if not isinstance(cursor, str) or not 1 <= len(cursor) <= 512 or cursor in cursors or not part:
            raise ValueError("ruleset cursor did not advance")
        cursors.add(cursor)
        path = prefix + "/rulesets?per_page=50&cursor=" + urllib.parse.quote(cursor, safe="")
    raise ValueError("ruleset page budget")

def snapshot_group(client, zone, group):
    prefix = '/zones/' + zone
    if group == 'dns':
        return dns_snapshot(client, prefix)
    if group == 'workers':
        routes = list_result(client.get(prefix + '/workers/routes'))
        if any(not isinstance(row.get('pattern'), str) or not isinstance(row.get('id'), str) or not HEX_ID.fullmatch(row['id']) for row in routes):
            raise ValueError('malformed Worker route')
        return {'routes': sorted(routes, key=lambda row: row['id'])}
    if group == 'rules':
        listed = ruleset_listing(client, prefix)
        ids = [row.get('id') for row in listed]
        if any(not isinstance(item, str) or not HEX_ID.fullmatch(item) for item in ids) or len(set(ids)) != len(ids):
            raise ValueError('invalid ruleset identities')
        rulesets = []
        for identifier in sorted(ids):
            row = client.get(prefix + '/rulesets/' + identifier)['result']
            if not isinstance(row, dict) or row.get('id') != identifier or not isinstance(row.get('rules'), list) or len(row['rules']) > 1000 or any(not isinstance(rule, dict) for rule in row['rules']):
                raise ValueError('incomplete ruleset')
            rulesets.append(row)
        page_rules = list_result(client.get(prefix + '/pagerules'), maximum=100)
        if any(not isinstance(row.get('id'), str) or not HEX_ID.fullmatch(row['id']) or not isinstance(row.get('actions'), list) or not isinstance(row.get('targets'), list) for row in page_rules):
            raise ValueError('malformed Page Rule')
        return {'rulesets': rulesets, 'page_rules': sorted(page_rules, key=lambda row: row['id'])}
    if group == 'settings':
        zone_row = client.get(prefix)['result']
        if not isinstance(zone_row, dict) or zone_row.get('id') != zone or type(zone_row.get('paused')) is not bool or not isinstance(zone_row.get('name_servers'), list) or not isinstance(zone_row.get('status'), str):
            raise ValueError('zone identity mismatch')
        settings = {}
        for key in ('ssl', 'always_use_https', 'min_tls_version', 'security_level'):
            row = client.get(prefix + '/settings/' + key)['result']
            if not isinstance(row, dict) or row.get('id') != key or 'value' not in row:
                raise ValueError('incomplete settings')
            settings[key] = row['value']
        return {'zone': {key: zone_row[key] for key in ('id', 'paused', 'name_servers', 'status')}, 'settings': settings}
    raise ValueError('unknown collection')


def capture(config, client):
    snapshots = {}
    for group in GROUPS:
        try:
            value = snapshot_group(client, config['zone_id'], group)
            # Store only hashes and bounded counts, never DNS contents/rule expressions.
            count = sum(len(item) if isinstance(item, list) else 1 for item in value.values())
            if count > 5000:
                raise ValueError('summary count exceeds budget')
            snapshots[group] = {'digest': digest(value), 'count': count}
        except (OSError, ValueError, TypeError, KeyError, RecursionError, urllib.error.URLError):
            snapshots[group] = None
    return snapshots


def valid_baseline(value, config):
    if not isinstance(value, dict) or set(value) != {'schema', 'zone_id', 'approved_at', 'snapshots'} or value.get('schema') != 1 or value.get('zone_id') != config['zone_id'] or not isinstance(value.get('approved_at'), str):
        return False
    snapshots = value.get('snapshots')
    return isinstance(snapshots, dict) and set(snapshots) == set(GROUPS) and all(
        isinstance(row, dict) and set(row) == {'digest', 'count'} and isinstance(row.get('digest'), str) and DIGEST.fullmatch(row['digest']) and type(row.get('count')) is int and 0 <= row['count'] <= 5000
        for row in snapshots.values())


def result_rows(snapshots, baseline, detail=None):
    rows = []
    for group, label in GROUPS.items():
        current = snapshots.get(group)
        if detail is not None or current is None:
            state, text = 'unavailable', detail or '读取失败、权限不足、响应异常或超过检查上限；不能判断安全'
        elif baseline is None:
            state, text = 'unavailable', '已读取配置，尚未由独立管理通道核验并批准可信基线'
        elif current != baseline['snapshots'][group]:
            state, text = 'finding', '配置与已批准基线不符；请独立核对合法变更和 Cloudflare 审计记录'
        else:
            state, text = 'ok', '已完整读取本项受控范围，配置与已批准基线一致'
        rows.append({'id': 'cloudflare.' + group, 'name': label, 'state': state, 'detail': text,
            'scope': 'Cloudflare single zone; read-only', 'evidence': current})
    return rows


def collect():
    config, token = load_config()
    snapshots = capture(config, Client(token))
    try:
        baseline = json.loads(read_private(BASELINE))
        if not valid_baseline(baseline, config):
            baseline = None
    except (OSError, ValueError, TypeError, RecursionError):
        baseline = None
    report = {'schema': 1, 'checked_at': now(), 'checks': result_rows(snapshots, baseline)}
    write_json(REPORT, report)
    return config, snapshots, report


def collect_safe():
    try:
        return collect()[2]
    except (OSError, ValueError, TypeError, RecursionError):
        report = {'schema': 1, 'checked_at': now(), 'checks': result_rows({}, None,
            '未配置 Cloudflare 只读身份，或私有配置/令牌不可用；文件查杀不能判断 CF 安全')}
        write_json(REPORT, report)
        return report


def approve(expected):
    if not isinstance(expected, str) or not DIGEST.fullmatch(expected):
        raise ValueError('approval requires fingerprint')
    config, snapshots, _report = collect()
    fingerprint = digest({'zone_id': config['zone_id'], 'snapshots': snapshots})
    if any(row is None for row in snapshots.values()) or expected != fingerprint:
        raise ValueError('incomplete or changed candidate')
    write_json(BASELINE, {'schema': 1, 'zone_id': config['zone_id'], 'approved_at': now(), 'snapshots': snapshots})
    collect_safe()


def preview():
    config, snapshots, _report = collect()
    for group, name in GROUPS.items():
        row = snapshots[group]
        print(name + ': ' + (str(row['count']) + ' 项 · ' + row['digest'] if row else '不可用'))
    if all(row is not None for row in snapshots.values()):
        print('候选指纹：' + digest({'zone_id': config['zone_id'], 'snapshots': snapshots}))
        print('先在可信 Cloudflare 控制台核对配置；批准只接受该精确指纹，后续变化不会自动学习。')
    else:
        print('覆盖不完整，禁止批准。')


def configure():
    if not sys.stdin.isatty():
        raise ValueError('interactive terminal required')
    zone = input('Cloudflare Zone ID（32位小写十六进制）：').strip()
    if not HEX_ID.fullmatch(zone):
        raise ValueError('invalid zone')
    token = getpass.getpass('限定该 Zone 的只读 API Token（输入不回显）：').strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{20,256}', token):
        raise ValueError('invalid token')
    # No write credentials are needed or sent to the business API.
    write_private(TOKEN, token.encode())
    write_json(CONFIG, {'schema': 1, 'zone_id': zone})
    print('只读身份已保存在 root 私有配置；现有基线保留。')


def menu():
    while True:
        print('\nCloudflare 只读配置监测\n 1. 配置只读身份\n 2. 检查并预览候选指纹\n 3. 独立核验后批准基线\n 0. 返回')
        choice = input('请选择：').strip()
        if choice == '0':
            return
        try:
            if choice == '1':
                configure()
            elif choice == '2':
                preview()
            elif choice == '3':
                approve(input('输入已经独立核验的完整候选指纹：').strip())
                print('已批准；后台将在本机扫描时读取新结果。')
        except (OSError, ValueError, TypeError):
            print('操作未完成：检查权限、私有文件、API读取范围或候选指纹。现有基线未被自动替换。')


def main():
    if os.name != 'posix' or os.geteuid() != 0:
        raise ValueError('root Linux management required')
    args = sys.argv[1:]
    if args == ['collect']:
        print(json.dumps(collect_safe(), ensure_ascii=False))
    elif args == ['configure']:
        configure()
    elif args == ['preview']:
        preview()
    elif len(args) == 2 and args[0] == 'approve':
        approve(args[1])
    elif args == ['menu']:
        menu()
    else:
        raise ValueError('usage: cloudflare menu|configure|preview|approve FINGERPRINT|collect')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, TypeError, EOFError, KeyboardInterrupt):
        print('Cloudflare 检查未完成：请核对私有配置、只读权限、完整覆盖和批准指纹。', file=sys.stderr)
        sys.exit(1)
