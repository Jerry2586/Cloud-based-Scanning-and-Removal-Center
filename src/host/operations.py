#!/usr/bin/env python3
"""Evidence-bound local management. Fixed Unix actions; no paths or commands from clients."""
import contextlib
import datetime
import fcntl
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location('operations_response', Path(__file__).with_name('response.py'))
r = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r)
a = r.a
SCHEMA = 'ironcurtain-operations/v1'
ACTIONS = {'ports', 'review', 'quarantine', 'restore', 'discover', 'enroll'}


def digest(value):
    return hashlib.sha256(a.canonical(value)).hexdigest()


def display(value, maximum):
    # Evidence digests use the original value; only display text is flattened.
    return ''.join(c if ord(c) >= 32 and ord(c) != 127 else ' ' for c in value)[:maximum]


def fresh(value, max_age=900):
    if not a.valid_timestamp(value):
        return False
    age = datetime.datetime.now(datetime.timezone.utc).timestamp() - r.timestamp(value)
    return -30 <= age <= max_age


def ports(value):
    if not isinstance(value, list) or len(value) > 128 or any(type(v) is not int or not 1 <= v <= 65535 for v in value) or len(set(value)) != len(value):
        raise ValueError('端口须为 1–65535 的不重复整数，每种协议最多 128 项')
    return sorted(value)


def validate(value):
    if not isinstance(value, dict) or not isinstance(value.get('action'), str) or value['action'] not in ACTIONS:
        raise ValueError('管理动作无效')
    action = value['action']
    keys = {'discover': {'action'}, 'enroll': {'action', 'revision', 'inventory', 'ids'}, 'ports': {'action', 'revision', 'tcp', 'udp'}, 'review': {'action', 'id', 'evidence', 'status', 'reason'},
            'quarantine': {'action', 'id', 'confirm'}, 'restore': {'action', 'id', 'confirm'}}[action]
    if set(value) != keys:
        raise ValueError('请求含缺失或未支持字段')
    if action == 'discover':
        return value
    if action == 'enroll':
        r.identifier(value['revision']); r.identifier(value['inventory'])
        ids = value['ids']
        if not isinstance(ids, list) or not 1 <= len(ids) <= 32 or any(not isinstance(v, str) or len(v) != 16 or any(c not in '0123456789abcdef' for c in v) for v in ids) or len(set(ids)) != len(ids):
            raise ValueError('请选择 1–32 个不重复的当前保护候选')
    elif action == 'ports':
        r.identifier(value['revision'])
        ports(value['tcp']); ports(value['udp'])
    else:
        r.identifier(value['id'])
        if action == 'review':
            r.identifier(value['evidence'])
            if value['status'] not in ('open', 'investigating', 'accepted') or not isinstance(value['reason'], str) or not 4 <= len(value['reason'].strip()) <= 240 or any(ord(c) < 32 or ord(c) == 127 for c in value['reason']):
                raise ValueError('请选择处理状态并填写 4–240 字的原因')
        elif value['confirm'] != ('quarantine' if action == 'quarantine' else 'restore-original'):
            raise ValueError('请明确确认本次文件操作')
    return value


@contextlib.contextmanager
def lease(path):
    fd = a.secure_fd(path, root_controlled=True, flags=os.O_RDWR | os.O_CREAT)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_nlink != 1 or meta.st_mode & 0o077:
            raise ValueError('管理锁不受信任')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def persist(path, value):
    # Atomic replace plus directory fsync is required for a durable transaction boundary.
    a.atomic_json(path, value)
    fd = os.open(Path(path).parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def valid_job(value, audit=False):
    if not isinstance(value, dict) or value.get('state') not in ('idle', 'running', 'complete', 'failed', 'interrupted'):
        return False
    if value['state'] == 'idle':
        return not audit and value == {'state': 'idle'}
    if not isinstance(value.get('id'), str) or len(value['id']) != 32 or any(c not in '0123456789abcdef' for c in value['id']):
        return False
    if not isinstance(value.get('action'), str) or value['action'] not in ACTIONS or not a.valid_timestamp(value.get('started_at')) or not isinstance(value.get('reason'), str) or len(value['reason']) > 500 or any(ord(c) < 32 or ord(c) == 127 for c in value['reason']):
        return False
    if value['state'] != 'running' and (not a.valid_timestamp(value.get('finished_at')) or value['finished_at'] < value['started_at']):
        return False
    if audit and (value['state'] == 'running' or not isinstance(value.get('target'), str) or len(value['target']) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in value['target'])):
        return False
    return True


def service_restart():
    subprocess.run(['/usr/bin/systemctl', 'restart', 'ironcurtain-agent.service'], stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=35)
    subprocess.run(['/usr/bin/systemctl', 'is-active', '--quiet', 'ironcurtain-agent.service'], stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=5)


class Operations:
    def __init__(self, profile='/etc/ironcurtain/local/profile.json', state='/var/lib/ironcurtain/local/agent',
                 lock='/run/lock/ironcurtain-local.lock', restart=service_restart):
        self.profile = Path(profile)
        self.state = Path(state)
        self.directory = self.state / 'operations'
        # Verify the parent before creating any persistent files.
        parent = a.secure_fd(self.state / '.operations-control', root_controlled=True, flags=os.O_RDWR | os.O_CREAT)
        os.close(parent)
        self.directory.mkdir(mode=0o700, exist_ok=True)
        # Refuse shared ownership and permissions before creating files inside the directory.
        meta = self.directory.lstat()
        if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o077:
            raise ValueError('管理状态目录异常')
        fd = a.secure_fd(self.directory / '.control', root_controlled=True, flags=os.O_RDWR | os.O_CREAT)
        os.close(fd)
        self.lock_path, self.restart = lock, restart
        self.mutex = threading.Lock()
        self.job_file = self.directory / 'job.json'
        self.review_file = self.directory / 'reviews.json'
        self.audit_file = self.directory / 'audit.json'
        self.transaction_file = self.directory / 'port-transaction.json'
        self.discovery_file = self.directory / 'scope-discovery.json'
        self.runner = a.Runner()
        self.pending = [Path('/opt/ironcurtain/local/admin-transaction.json'), Path('/opt/ironcurtain/local/transaction.json')]
        if self.transaction_file.exists() or self.transaction_file.is_symlink():
            with lease(self.lock_path):
                self.recover_ports()
        self.job = self.read(self.job_file, {'state': 'idle'})
        if not valid_job(self.job):
            raise ValueError('管理任务记录无法核验')
        if self.job.get('state') == 'running':
            self.job.update(state='interrupted', reason='管理服务重启中断任务，请核对实际文件和配置后重新操作', finished_at=a.utc())
            audit = self.read(self.audit_file, [])
            if not isinstance(audit, list) or len(audit) > 128 or not all(valid_job(v, audit=True) for v in audit):
                raise ValueError('管理审计无法核验')
            audit = [v for v in audit if v['id'] != self.job['id']]
            audit.append({**self.job, 'target': self.job.get('target', 'interrupted-operation')})
            persist(self.audit_file, audit[-128:])
            persist(self.job_file, self.job)
        self.thread = None
        self.last_action = 0

    def read(self, path, default):
        try:
            fd = a.secure_fd(path, root_controlled=True)
            with os.fdopen(fd, 'rb') as stream:
                meta = os.fstat(stream.fileno())
                if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_nlink != 1 or meta.st_mode & 0o077 or meta.st_size > 262144:
                    raise ValueError('管理证据或状态文件不受信任')
                data = stream.read(262145)
                after = os.fstat(stream.fileno())
                if len(data) > 262144 or (meta.st_ino, meta.st_mtime_ns, meta.st_size) != (after.st_ino, after.st_mtime_ns, after.st_size):
                    raise ValueError('管理证据读取期间发生变化')
                return json.loads(data)
        except FileNotFoundError:
            return default

    def config(self):
        return a.profile_validate(a.private_json(self.profile))

    def reviews(self):
        value = self.read(self.review_file, {})
        if not isinstance(value, dict) or len(value) > 128 or any(not isinstance(k, str) or not a.DIGEST.fullmatch(k) or not isinstance(v, dict) or v.get('status') not in ('open', 'investigating', 'accepted') or not isinstance(v.get('reason'), str) or not 4 <= len(v['reason'].strip()) <= 240 or any(ord(c) < 32 or ord(c) == 127 for c in v['reason']) or not a.DIGEST.fullmatch(str(v.get('evidence', ''))) or not a.valid_timestamp(v.get('updated_at')) for k, v in value.items()):
            raise ValueError('风险处置记录无法核验')
        return value

    def risk_snapshot(self, profile):
        revision = digest(profile)
        items, sources = {}, {'engine_coverage': '0/4', 'truncated': False}
        reviews = self.reviews()
        def add(source, rule, target, evidence, title, detail, severity, observed):
            key = digest({'source': source, 'rule': rule, 'target': target})
            decision = reviews.get(key)
            if decision and (decision['evidence'] != evidence or not fresh(decision['updated_at'], 7 * 86400)):
                decision = None
            items[key] = {'id': key, 'source': source, 'rule': display(rule, 256), 'target': display(target, 256), 'evidence': evidence,
                          'title': display(title, 160), 'detail': display(detail, 500), 'severity': severity, 'observed_at': observed,
                          'fresh': fresh(observed), 'review': decision or {'status': 'open', 'reason': '', 'updated_at': None}}
        report = self.read(self.state / 'last-report.json', {})
        checks = report.get('checks', [])
        valid = report.get('state') == 'finished' and report.get('profile_digest') == revision and isinstance(checks, list) and len(checks) == len(a.IDS) and [v.get('id') if isinstance(v, dict) else None for v in checks] == a.IDS and all(a.valid_saved_check(v) for v in checks)
        sources['environment'] = 'current' if valid and fresh(report.get('checked_at')) else 'historical' if valid else 'unavailable'
        if valid:
            for item in checks:
                if item['state'] in ('finding', 'warning', 'unavailable'):
                    add('environment', item['id'], item['scope'], item['evidence_digest'], item['name'], item['detail'], item['severity'], item['checked_at'])
        multi = self.read(self.state / 'multi-engine-report.json', {})
        valid_multi = a.multi_engine.valid(multi, revision) and multi.get('state') in ('finished', 'partial', 'failed', 'cancelled')
        sources['engines'] = 'current' if valid_multi and fresh(multi.get('updated_at')) else 'historical' if valid_multi else 'unavailable'
        if valid_multi:
            for engine in multi['engines']:
                if engine['state'] not in ('complete', 'partial'):
                    continue
                for item in engine['findings']:
                    # Include package/version detail for CVEs; different affected packages stay separate.
                    target = item['target'] + (' · ' + item['detail'] if item['kind'] == 'vulnerability' else '')
                    add(item['kind'], item['rule'], target, engine.get('evidence_digest') or digest(item), item['rule'], item['detail'], item['severity'], multi['updated_at'])
            sources['engine_coverage'] = str(multi['coverage']) + '/4'
            sources['truncated'] = any(e['finding_total'] > len(e['findings']) for e in multi['engines'])
        sources['truncated'] = sources['truncated'] or len(items) > 96
        return sorted(items.values(), key=lambda v: ({'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(v['severity'], 5), v['id']))[:96], sources

    def snapshot(self):
        profile = self.config()
        risks, sources = self.risk_snapshot(profile)
        # Read the receipt and its audit under the same completion boundary as run().
        # A query must never combine a completed job with the preceding audit file.
        with self.mutex:
            audit = self.read(self.audit_file, [])
            if not isinstance(audit, list) or len(audit) > 128 or not all(valid_job(v, audit=True) for v in audit):
                raise ValueError('管理审计无法核验')
            job = dict(self.job)
        result = {'schema': SCHEMA, 'state': 'ready', 'policy': {'revision': digest(profile), 'tcp': sorted(set(profile['approved_tcp_ports'])), 'udp': sorted(set(profile['approved_udp_ports']))},
                  'scope': self.scope_snapshot(profile), 'job': job, 'risks': risks, 'sources': sources, 'audit': audit[-12:], 'quarantine': a.findings.quarantine_status(self.state)}
        # Bound UTF-8 bytes, not character counts. Preserve coverage and report truncation.
        while len(a.canonical(result)) > 262144 and result['risks']:
            result['risks'].pop()
            result['sources']['truncated'] = True
        while len(a.canonical(result)) > 262144 and result['scope']['discovery']['candidates']:
            result['scope']['discovery']['candidates'].pop()
            result['scope']['discovery']['truncated'] = True
        if len(a.canonical(result)) > 262144:
            raise ValueError('管理响应超出预算')
        return result

    def discovery_record(self, record=None):
        if record is None: record = self.read(self.discovery_file, None)
        if record is None: return None
        if not isinstance(record, dict) or set(record) != {'schema', 'profile_revision', 'inventory', 'directories'} or record['schema'] != 'ironcurtain-scope-discovery/v1' or not a.DIGEST.fullmatch(str(record['profile_revision'])) or not a.inventory.valid_inventory(record['inventory']):
            raise ValueError('保护候选记录无法核验，请重新发现')
        directories = record['directories']
        expected = {v['id'] for v in record['inventory']['candidates'] if v['kind'] != 'containers'}
        if not isinstance(directories, dict) or set(directories) != expected or any(not isinstance(v, list) or len(v) != 2 or any(type(n) is not int or n < 0 for n in v) for v in directories.values()):
            raise ValueError('候选目录身份无法核验，请重新发现')
        ids = [v['id'] for v in record['inventory']['candidates']]
        if len(ids) != len(set(ids)): raise ValueError('保护候选重复，请重新发现')
        containers = {v['name']: v for v in record['inventory']['containers']}
        for item in record['inventory']['candidates']:
            if item['kind'] == 'containers' and not a.DIGEST.fullmatch(str(containers.get(item['value'], {}).get('container_id', ''))):
                raise ValueError('候选容器身份无法核验，请重新发现')
        return record

    def scope_snapshot(self, profile):
        discovery = {'state': 'unavailable', 'revision': None, 'observed_at': None, 'candidates': [], 'count': 0, 'truncated': False, 'issues': []}
        try: record = self.discovery_record()
        except ValueError:
            record = None
            discovery['issues'] = ['候选记录无法核验，请重新发现']
        if record:
            inventory = record['inventory']
            discovery.update(state='ready' if record['profile_revision'] == digest(profile) and fresh(inventory['observed_at'], 120) else 'stale', revision=digest(record), observed_at=inventory['observed_at'], count=len(inventory['candidates']), issues=inventory['issues'][:8])
            for item in inventory['candidates']:
                enrolled = any(v['name'] == item['value'] for v in profile['containers']) if item['kind'] == 'containers' else item['value'] in profile[item['kind']]
                discovery['candidates'].append({k: item[k] for k in ('id', 'kind', 'value', 'origin')} | {'enrolled': enrolled})
        return {'program_roots': profile['program_roots'], 'business_roots': profile['business_roots'], 'containers': [v['name'] for v in profile['containers']], 'discovery': discovery}

    def directory_identity(self, value):
        if not a.inventory.safe_path(value): raise ValueError('候选目录路径异常，请重新发现')
        try:
            fd = a.secure_fd(value, flags=os.O_RDONLY | os.O_DIRECTORY)
            try:
                meta = os.fstat(fd)
                return [meta.st_dev, meta.st_ino]
            finally: os.close(fd)
        except (OSError, ValueError): raise ValueError('候选目录已变化或包含链接，请重新发现') from None

    def discover_scope(self, profile):
        inventory = a.inventory.discover(self.runner)
        if not a.inventory.valid_inventory(inventory): raise ValueError('主机发现未生成有效记录，请检查本机服务')
        directories = {}
        for item in inventory['candidates']:
            if item['kind'] != 'containers':
                directories[item['id']] = self.directory_identity(item['value'])
        record = {'schema': 'ironcurtain-scope-discovery/v1', 'profile_revision': digest(profile), 'inventory': inventory, 'directories': directories}
        if len(a.canonical(record)) > 262144: raise ValueError('保护候选超出证据预算，请在 Linux 菜单分批配置')
        self.discovery_record(record)
        persist(self.discovery_file, record)
        return '已发现 %d 个保护候选；请在两分钟内选择并纳管。缺失的资产在覆盖说明中保留。' % len(inventory['candidates'])

    def apply_enrollment(self, value, profile):
        record = self.discovery_record()
        if value['revision'] != digest(profile) or not record or record['profile_revision'] != digest(profile):
            raise ValueError('保护配置已变化，请重新发现后选择')
        if value['inventory'] != digest(record): raise ValueError('保护候选已变化，请重新发现后选择')
        inventory = record['inventory']
        candidate = a.profile_validate(a.inventory.enroll(profile, inventory, value['ids']))
        selected = {v['id']: v for v in inventory['candidates']}
        containers = {v['name']: v for v in inventory['containers']}
        deadline = time.monotonic() + 20
        for ident in value['ids']:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise ValueError('候选复核达到时间上限，请分批选择并重新发现')
            item = selected[ident]
            if item['kind'] != 'containers':
                if self.directory_identity(item['value']) != record['directories'][ident]: raise ValueError('候选目录已被替换，请重新发现')
            else:
                code, raw = self.runner(['docker', 'inspect', '--type', 'container', '--', item['value']], seconds=min(3, remaining), maximum=262144)
                try:
                    rows = json.loads(raw)
                    observed = containers[item['value']]
                    if code != 0 or not isinstance(rows, list) or len(rows) != 1 or rows[0].get('Name') != '/' + item['value'] or rows[0].get('Id') != observed['container_id'] or rows[0].get('Image') != observed['image_id']: raise ValueError()
                except (ValueError, TypeError, KeyError, AttributeError): raise ValueError('候选容器已变化或无法核验，请重新发现') from None
        if not fresh(inventory['observed_at'], 120): raise ValueError('资产候选记录已过期，请重新发现')
        if self.config() != profile: raise ValueError('保护配置已变化，请重新发现后选择')
        if candidate == profile: raise ValueError('所选对象已纳管，请刷新保护范围')
        self.apply_profile(profile, candidate, 'ironcurtain-scope-transaction/v1')
        return '保护范围已启用。请重新扫描验证；纳管不会批准镜像或文件签名基线。'

    def remove_transaction(self):
        self.transaction_file.unlink()
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)

    def recover_ports(self):
        transaction = self.read(self.transaction_file, None)
        if transaction is None: return
        if not isinstance(transaction, dict) or set(transaction) != {'schema', 'previous', 'candidate', 'phase'} or transaction.get('schema') not in ('ironcurtain-port-transaction/v1', 'ironcurtain-scope-transaction/v1') or transaction.get('phase') not in ('prepared', 'applied', 'committed'):
            raise ValueError('配置恢复记录无法核验')
        previous = a.profile_validate(transaction['previous'])
        candidate = a.profile_validate(transaction['candidate'])
        if transaction['schema'] == 'ironcurtain-port-transaction/v1':
            if candidate != dict(previous, approved_tcp_ports=ports(candidate['approved_tcp_ports']), approved_udp_ports=ports(candidate['approved_udp_ports'])):
                raise ValueError('端口事务包含其他配置变更，保留现场等待核查')
        else:
            names = ('program_roots', 'business_roots', 'containers')
            if candidate != dict(previous, **{k: candidate[k] for k in names}) or any(candidate[k][:len(previous[k])] != previous[k] for k in names):
                raise ValueError('保护范围事务包含未允许的配置变更，保留现场等待核查')
            for key in names:
                added = candidate[key][len(previous[key]):]
                if key != 'containers' and any(not a.inventory.safe_path(v) for v in added): raise ValueError('保护范围事务路径异常')
                if key == 'containers' and any(set(v) != {'name'} for v in added): raise ValueError('纳管不能批准镜像')
                values = [v['name'] for v in candidate[key]] if key == 'containers' else candidate[key]
                if len(values) != len(set(values)): raise ValueError('保护范围事务重复')
        current = self.config()
        if current != previous and current != candidate:
            raise ValueError('保护配置已被外部修改，保留事务等待人工核查')
        if transaction['phase'] == 'committed' and current != candidate:
            raise ValueError('已提交事务与当前配置不一致，保留现场等待核查')
        if transaction['phase'] != 'committed':
            persist(self.profile, previous)
            self.restart()
        self.remove_transaction()

    def apply_ports(self, value, profile):
        if value['revision'] != digest(profile):
            raise ValueError('保护配置已变化，请刷新端口策略后重试')
        candidate = dict(profile, approved_tcp_ports=ports(value['tcp']), approved_udp_ports=ports(value['udp']))
        a.profile_validate(candidate)
        self.apply_profile(profile, candidate, 'ironcurtain-port-transaction/v1')
        return '端口检测白名单已启用，请重新检查监听。此操作不关闭端口或修改防火墙。'

    def apply_profile(self, profile, candidate, schema):
        transaction = {'schema': schema, 'previous': profile, 'candidate': candidate, 'phase': 'prepared'}
        persist(self.transaction_file, transaction)
        try:
            persist(self.profile, candidate)
            persist(self.transaction_file, dict(transaction, phase='applied'))
            self.restart()
            persist(self.transaction_file, dict(transaction, phase='committed'))
            self.remove_transaction()
        except Exception as error:
            try: self.recover_ports()
            except Exception:
                raise ValueError('保护配置事务待恢复，请停止重试并在 Linux 菜单检查服务') from error
            raise ValueError('新策略未完成启用，已核对并恢复配置；请刷新状态') from error

    def execute(self, value, profile):
        action = value['action']
        if action == 'discover': return self.discover_scope(profile)
        if action == 'enroll': return self.apply_enrollment(value, profile)
        if action == 'ports':
            return self.apply_ports(value, profile)
        if action == 'review':
            items, _ = self.risk_snapshot(profile)
            found = next((v for v in items if v['id'] == value['id']), None)
            if not found or not found['fresh'] or found['evidence'] != value['evidence']:
                raise ValueError('风险证据已变化或超过 15 分钟，请重新检查')
            decisions = self.reviews()
            if value['id'] not in decisions and len(decisions) >= 128:
                oldest = min(decisions, key=lambda key: decisions[key]['updated_at'])
                del decisions[oldest]
            decisions[value['id']] = {'status': value['status'], 'reason': value['reason'].strip(), 'evidence': value['evidence'], 'updated_at': a.utc()}
            persist(self.review_file, decisions)
            return '风险受理状态已保存；检测结论保留，请修复后重新检查验证。'
        record = r.quarantine(self.state, profile, value['id']) if action == 'quarantine' else r.restore(self.state, profile, value['id'])
        return '文件路径已隔离；已有进程可能仍在运行，请重新扫描并检查行为事件。' if action == 'quarantine' else '已取回原始隔离内容（root:0600），保留副本；请重新查杀，不能视为干净恢复。'

    def trigger(self, value):
        value = validate(value)
        with self.mutex:
            if self.job.get('state') == 'running':
                return 409, {'error': '已有处置任务执行中，请等待完成'}
            if self.last_action and time.monotonic() - self.last_action < 1:
                return 409, {'error': '操作过于频繁，请稍后重试'}
            guard = lease(self.lock_path)
            try:
                guard.__enter__()
            except BlockingIOError:
                return 409, {'error': '本机检测、更新或管理正在运行，请等待结束'}
            except (OSError, ValueError):
                return 503, {'error': '本机管理锁不可用，请检查服务'}
            try:
                if any(path.exists() or path.is_symlink() for path in self.pending):
                    guard.__exit__(None, None, None)
                    return 409, {'error': '本机存在待恢复的安装或管理事务，请先在 Linux 菜单恢复'}
                self.recover_ports()
                profile = self.config()
                job = {'id': uuid.uuid4().hex, 'state': 'running', 'action': value['action'], 'started_at': a.utc(), 'reason': '受控管理任务已受理', 'target': value.get('id', 'protection-scope' if value['action'] in ('discover', 'enroll') else 'port-policy')}
                persist(self.job_file, job)
                self.job = job
                self.last_action = time.monotonic()
                self.thread = threading.Thread(target=self.run, args=(value, profile, guard), daemon=True)
                self.thread.start()
            except BaseException:
                if self.job.get('state') == 'running':
                    self.job = dict(self.job, state='failed', finished_at=a.utc(), reason='管理任务无法启动，请核对状态')
                    try: persist(self.job_file, self.job)
                    except Exception: pass
                guard.__exit__(None, None, None)
                raise
            return 202, {'schema': SCHEMA, 'state': 'running', 'job': dict(job)}

    def run(self, value, profile, guard):
        try:
            # If an earlier process died, preserve journalled response state and require the user to reissue the action.
            reason = self.execute(value, profile)
            state = 'complete'
        except ValueError as error:
            reason, state = display(str(error), 500), 'failed'
        except Exception:
            reason, state = '处置未完成，请核对服务日志与实际状态；不能视为修复成功', 'failed'
        try:
            with self.mutex:
                job = dict(self.job, state=state, reason=reason, finished_at=a.utc())
                audit = self.read(self.audit_file, [])
                if not isinstance(audit, list) or len(audit) > 128 or not all(valid_job(v, audit=True) for v in audit):
                    raise ValueError('audit invalid')
                audit.append({**job, 'target': value.get('id', 'protection-scope' if value['action'] in ('discover', 'enroll') else 'port-policy')})
                persist(self.audit_file, audit[-128:])
                persist(self.job_file, job)
                self.job = job
        except Exception:
            with self.mutex:
                self.job = dict(self.job, state='failed', finished_at=a.utc(), reason='操作结果持久化失败，请核对实际状态和审计，不要直接重试')
        finally:
            guard.__exit__(None, None, None)


def handler(operations):
    class Handler(http.server.BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)
        def allowed(self):
            _, uid, gid = struct.unpack('3i', self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            return uid == 0 or (uid == 10001 and gid == 10001)
        def send(self, status, value):
            payload = a.canonical(value)
            if len(payload) > 262144:
                status, payload = 503, a.canonical({'error': '管理响应超出预算'})
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers(); self.wfile.write(payload)
        def do_GET(self):
            if not self.allowed(): return self.send(403, {'error': '身份未授权'})
            if self.path != '/operations': return self.send(404, {'error': '接口不存在'})
            try: self.send(200, operations.snapshot())
            except Exception: self.send(503, {'state': 'unavailable', 'error': '本机处置服务无法核验'})
        def do_POST(self):
            if not self.allowed(): return self.send(403, {'error': '身份未授权'})
            if self.path != '/operations': return self.send(404, {'error': '接口不存在'})
            lengths = self.headers.get_all('Content-Length') or []
            if self.headers.get('Transfer-Encoding') or len(lengths) != 1 or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= 4096 or self.headers.get_content_type() != 'application/json':
                return self.send(400, {'error': '请求格式或长度无效'})
            try:
                raw = self.rfile.read(int(lengths[0]))
                if len(raw) != int(lengths[0]): raise ValueError('请求不完整')
                def unique(pairs):
                    value = {}
                    for key, item in pairs:
                        if key in value: raise ValueError('不接受重复字段')
                        value[key] = item
                    return value
                value = json.loads(raw, object_pairs_hook=unique)
                self.send(*operations.trigger(value))
            except (ValueError, TypeError): self.send(400, {'error': '处置请求无效，请核对字段与确认信息'})
            except Exception: self.send(503, {'error': '本机处置服务不可用'})
        def log_message(self, *_): pass
    return Handler


def serve():
    if os.geteuid() != 0: raise SystemExit('root required')
    directory = Path('/run/ironcurtain-operations-local')
    meta = directory.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != 0 or meta.st_gid != 10001 or stat.S_IMODE(meta.st_mode) != 0o750:
        raise ValueError('socket directory invalid')
    fd = a.secure_fd(directory / '.control', root_controlled=True, flags=os.O_RDWR | os.O_CREAT)
    os.close(fd)
    path = directory / 'control.sock'
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0: raise ValueError('socket invalid')
        with socket.socket(socket.AF_UNIX) as probe:
            probe.settimeout(1)
            try: probe.connect(str(path))
            except ConnectionRefusedError: path.unlink()
            else: raise ValueError('socket already active')
    operations = Operations()
    with socketserver.UnixStreamServer(str(path), handler(operations)) as server:
        os.chown(path, 0, 10001); os.chmod(path, 0o660)
        server.serve_forever(poll_interval=0.5)


if __name__ == '__main__':
    if sys.argv[1:] == ['recover']:
        # Caller must already own the exclusive installer/manager lock.
        if os.geteuid() != 0: raise SystemExit('root required')
        instance = Operations.__new__(Operations)
        instance.profile = Path('/etc/ironcurtain/local/profile.json')
        instance.state = Path('/var/lib/ironcurtain/local/agent')
        instance.directory = instance.state / 'operations'
        instance.transaction_file = instance.directory / 'port-transaction.json'
        instance.restart = service_restart
        instance.recover_ports()
    elif sys.argv[1:]: raise SystemExit('unsupported arguments')
    else: serve()
