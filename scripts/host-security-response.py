#!/usr/bin/env python3
"""Root-only local containment. No web, cloud, SSH or arbitrary command execution."""
import fcntl
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

DIRECTORY = Path('/usr/local/lib/appgog-security')
STATE = Path('/var/lib/appgog-security')
CONFIG = DIRECTORY / 'response-config.json'
INCIDENT = STATE / 'incident.json'
POLICY = STATE / 'response-policy.json'
IMAGE = STATE / 'approved-image.json'
AGENT = None
ROOT = None
VERSION = None


def trusted(path, directory=False):
    path = Path(path).absolute()
    for item in reversed((path, *path.parents)):
        metadata = item.lstat()
        is_dir = stat.S_ISDIR(metadata.st_mode)
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError('unsafe root-owned path')
        if item == path:
            if is_dir != directory or (not directory and not stat.S_ISREG(metadata.st_mode)):
                raise ValueError('unexpected file type')
        elif not is_dir:
            raise ValueError('unsafe parent')
    return path


def read(path):
    trusted(path)
    return json.loads(AGENT.read_state(path, 32768))


def now():
    return datetime.now(timezone.utc).isoformat()


def docker(*args):
    result = subprocess.run(['/usr/bin/docker', *args], capture_output=True, text=True,
                            timeout=45, check=False, env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'})
    if result.returncode != 0 or len(result.stdout.encode()) > 262144:
        raise RuntimeError('Docker action failed; inspect daemon via trusted console')
    return result.stdout


def inspect(identifier):
    if not re.fullmatch(r'[a-f0-9]{64}', identifier):
        raise ValueError('invalid full container identity')
    payload = json.loads(docker('inspect', identifier))
    if not isinstance(payload, list) or len(payload) != 1 or payload[0].get('Id') != identifier:
        raise ValueError('container identity mismatch')
    item = payload[0]
    labels = item.get('Config', {}).get('Labels', {})
    if labels.get('com.docker.compose.project') != 'appgog' or labels.get('com.docker.compose.service') != 'appgog':
        raise ValueError('foreign container')
    working = Path(labels.get('com.docker.compose.project.working_dir', ''))
    if not working.is_absolute():
        raise ValueError('missing Compose installation identity')
    resolved = working.resolve()
    if resolved != ROOT:
        resolved.relative_to(ROOT / 'releases')
    files = labels.get('com.docker.compose.project.config_files', '').split(',')
    if len(files) != 1 or Path(files[0]).name not in {'compose.yaml', 'compose.license.yaml', 'compose.build.yaml'}:
        raise ValueError('unexpected Compose configuration')
    if Path(files[0]).resolve().parent != resolved:
        raise ValueError('foreign Compose configuration')
    return item


def target():
    identifiers = docker('ps', '-aq', '--no-trunc', '--filter', 'label=com.docker.compose.project=appgog',
                         '--filter', 'label=com.docker.compose.service=appgog').split()
    if len(identifiers) != 1:
        raise ValueError('expected exactly one owned APPGOG container; no action taken')
    return inspect(identifiers[0])


def incident():
    if not INCIDENT.exists() and not INCIDENT.is_symlink():
        return None
    item = read(INCIDENT)
    if item.get('schema') != 1 or item.get('root') != str(ROOT) or item.get('state') not in {
        'isolating', 'contained', 'containment_failed', 'source_repaired', 'recovering', 'released'
    }:
        raise ValueError('invalid incident record; manual investigation required')
    if not re.fullmatch(r'[a-f0-9]{64}', item.get('container_id', '')):
        raise ValueError('invalid incident container')
    return item


def save(item, state):
    item['state'], item['updated_at'] = state, now()
    AGENT.atomic_json(INCIDENT, item)


def stop(item):
    # Persist the incident before either irreversible external side effect.
    identifier = item['container_id']
    inspect(identifier)
    docker('update', '--restart=no', identifier)
    docker('stop', '--time', '20', identifier)
    if inspect(identifier).get('State', {}).get('Running') is not False:
        raise RuntimeError('container is still running')


def isolate(reason='manual'):
    item = incident()
    if item and item['state'] != 'released':
        owned = target()
        if owned['Id'] != item['container_id']:
            raise ValueError('replacement container detected; containment kept')
        try:
            stop(item)
            save(item, 'contained')
        except Exception:
            save(item, 'containment_failed')
            raise
        return item
    owned = target()
    policy = owned.get('HostConfig', {}).get('RestartPolicy', {})
    if policy.get('Name') not in {'no', 'always', 'unless-stopped', 'on-failure'}:
        raise ValueError('unknown restart policy')
    # Evidence is fixed and redacted: never persist inspect Env, secret contents or raw logs.
    checks = AGENT.scan()
    evidence = [{key: row.get(key) for key in ('id', 'state', 'severity', 'evidence_digest')} for row in checks]
    item = {'schema': 1, 'root': str(ROOT), 'version': VERSION, 'container_id': owned['Id'],
            'image_id': owned.get('Image'), 'restart_policy': policy, 'reason': reason,
            'created_at': now(), 'checks': evidence, 'source_repaired': False}
    save(item, 'isolating')
    try:
        stop(item)
        save(item, 'contained')
    except Exception:
        save(item, 'containment_failed')
        raise
    return item


def baseline_pin(path):
    return AGENT.approved_baseline_pin(trusted(path))


def approve_image(expected):
    if not re.fullmatch(r'sha256:[a-f0-9]{64}', expected):
        raise ValueError('supply independently verified full image ID')
    active = incident()
    if active and active['state'] != 'released':
        raise ValueError('cannot approve a new image during an incident')
    item = target()
    if item.get('Image') != expected or item.get('State', {}).get('Health', {}).get('Status') != 'healthy':
        raise ValueError('image identity/health mismatch')
    if (AGENT.integrity_check()['state'] != 'ok' or AGENT.host_configuration_check()['state'] != 'ok'
            or AGENT.container_contract_check()['state'] != 'ok'):
        raise ValueError('source, host baseline or container contract requires investigation')
    AGENT.atomic_json(IMAGE, {'schema': 1, 'root': str(ROOT), 'version': VERSION,
                              'image_id': expected, 'program_baseline': baseline_pin(AGENT.BASELINE),
                              'host_baseline': baseline_pin(AGENT.HOST_BASELINE), 'approved_at': now()})
    return {'image_id': expected, 'state': 'approved', 'trust': 'local-root-approval'}


def recovery_checks():
    checks = [AGENT.integrity_check(), AGENT.host_configuration_check(), AGENT.secret_permissions_check(),
              AGENT.malware_scan(), AGENT.business_malware_scan(), AGENT.sqlite_health_check()]
    if any(row['state'] != 'ok' for row in checks):
        raise ValueError('fresh source/host/permissions/business antivirus and SQLite health checks did not all pass')


def resume(confirmation):
    if confirmation != 'APPROVE-DATA-AND-RESUME':
        raise ValueError('root must review writable data and confirm APPROVE-DATA-AND-RESUME')
    item = incident()
    if not item or item['state'] == 'released':
        raise ValueError('no active incident')
    owned = target()
    if owned['Id'] != item['container_id'] or owned.get('State', {}).get('Running') is not False:
        raise ValueError('expected the original stopped container')
    pin = read(IMAGE)
    if pin.get('schema') != 1 or pin.get('root') != str(ROOT) or pin.get('version') != VERSION or \
            pin.get('image_id') != owned.get('Image') or item.get('image_id') != owned.get('Image'):
        raise ValueError('image was not independently approved before the incident')
    if pin.get('program_baseline') != baseline_pin(AGENT.BASELINE) or pin.get('host_baseline') != baseline_pin(AGENT.HOST_BASELINE):
        raise ValueError('baseline differs from pre-incident image approval; refuse to bless incident changes')
    recovery_checks()
    save(item, 'recovering')
    try:
        docker('start', item['container_id'])
        for attempt in range(45):
            current = target()
            if current['Id'] != item['container_id']:
                raise ValueError('concurrent replacement')
            if current.get('State', {}).get('Health', {}).get('Status') == 'healthy':
                break
            time.sleep(2)
        else:
            raise RuntimeError('recovered service did not become healthy')
        recovery_checks()
        if AGENT.container_contract_check()['state'] != 'ok':
            raise ValueError('running container contract failed')
        policy = item['restart_policy']
        flag = policy['Name']
        if flag == 'on-failure' and policy.get('MaximumRetryCount', 0):
            flag += ':' + str(int(policy['MaximumRetryCount']))
        docker('update', '--restart=' + flag, item['container_id'])
        item['data_reviewed_by_root_at'] = now()
        save(item, 'released')
    except Exception:
        try:
            stop(item)
            save(item, 'contained')
        except Exception:
            save(item, 'containment_failed')
            raise
        raise
    return {'state': 'released', 'updated_at': item['updated_at']}


def set_policy(value):
    if value not in {'alert-only', 'auto-contain'}:
        raise ValueError('invalid local policy')
    AGENT.atomic_json(POLICY, {'schema': 1, 'root': str(ROOT), 'mode': value, 'updated_at': now()})
    return {'mode': value}


def evaluate():
    active = incident()
    if active and active['state'] != 'released':
        # Retry incomplete containment and counter normal restart attempts without deleting anything.
        return isolate('existing-incident')
    if not POLICY.exists():
        return {'mode': 'alert-only', 'action': 'none'}
    policy = read(POLICY)
    if policy.get('schema') != 1 or policy.get('root') != str(ROOT):
        raise ValueError('invalid local policy')
    if policy.get('mode') != 'auto-contain':
        return {'mode': 'alert-only', 'action': 'none'}
    checks = {row['id']: row for row in AGENT.scan()}
    malware = checks.get('malware.program', {}).get('state') == 'finding'
    program = checks.get('integrity.program', {}).get('state') == 'finding'
    # Two independent positive findings. Unknown, lost cloud connection and hash drift alone never isolate.
    if malware and program:
        return isolate('malware-and-program-drift')
    return {'mode': 'auto-contain', 'action': 'none'}


def initialize():
    global AGENT, ROOT, VERSION
    for name in ('host-security-agent.py', 'host-security-response.py', 'host-security-repair.py', 'release-public.pem'):
        trusted(DIRECTORY / name)
    spec = importlib.util.spec_from_file_location('host_agent', DIRECTORY / 'host-security-agent.py')
    AGENT = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(AGENT)
    cfg = json.loads(AGENT.read_regular(trusted(CONFIG), 32768))
    if cfg.get('schema') != 1 or not re.fullmatch(r'\d+\.\d+\.\d+', cfg.get('version', '')):
        raise ValueError('invalid independent installation contract')
    ROOT = trusted(cfg['root'], directory=True)
    VERSION = cfg['version']
    AGENT.ROOT = ROOT


def dispatch(args):
    if args == ['status']:
        item = incident()
        return {'state': item['state'] if item else 'clear', 'updated_at': item.get('updated_at') if item else None}
    if args == ['guard']:
        item = incident()
        if item and item['state'] != 'released':
            raise ValueError('local incident blocks normal start/update/restore; use independent recovery menu')
        return {'state': 'clear'}
    if args == ['isolate']:
        item = isolate()
        return {'state': item['state'], 'updated_at': item['updated_at']}
    if args == ['evaluate']:
        return evaluate()
    if len(args) == 2 and args[0] == 'resume':
        return resume(args[1])
    if len(args) == 2 and args[0] == 'policy':
        return set_policy(args[1])
    if len(args) == 2 and args[0] == 'approve-image':
        return approve_image(args[1])
    if len(args) == 2 and args[0] in {'cache-release', 'repair-source'}:
        spec = importlib.util.spec_from_file_location('repair', DIRECTORY / 'host-security-repair.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.execute(sys.modules[__name__], args)
    raise ValueError('usage: status|isolate|evaluate|policy alert-only|policy auto-contain|approve-image SHA256|cache-release DIR|repair-source VERSION|resume APPROVE-DATA-AND-RESUME')


def menu():
    while True:
        print('\nAPPGOG 本地安全事故中心（独立 root 通道）')
        print('  1. 查看隔离状态\n  2. 隔离本机 APPGOG 容器（先留证，不删除数据）')
        print('  3. 导入签名发布包作为离线修复缓存\n  4. 用离线签名缓存修复当前版本源码')
        print('  5. 事故前核验并固定镜像身份\n  6. 严格核验后解除误报隔离')
        print('  7. 开启双证据自动隔离\n  8. 切回只告警模式\n  0. 返回')
        choice = input('请选择：').strip()
        if choice in {'', '0'}:
            return
        args = None
        if choice == '1':
            args = ['status']
        elif choice == '2' and input('同机部署授权与打包会一起暂停。输入 ISOLATE 确认：') == 'ISOLATE':
            args = ['isolate']
        elif choice == '3':
            args = ['cache-release', input('包含正式 ZIP、清单、清单签名的 root 私有目录：').strip()]
        elif choice == '4' and input('保持容器停止，只修当前签名源码。输入 REPAIR 确认：') == 'REPAIR':
            args = ['repair-source', VERSION]
        elif choice == '5':
            print('先独立核验镜像及发布来源，再填写完整 sha256: 镜像 ID；这是本机批准，不是发布方镜像签名。')
            args = ['approve-image', input('完整镜像 ID：').strip()]
        elif choice == '6':
            print('先人工复核数据库、密钥、客户文件、可写卷及事故范围；无法确认时迁至干净主机。')
            args = ['resume', input('确认复核后输入 APPROVE-DATA-AND-RESUME：').strip()]
        elif choice == '7' and input('每五分钟评估，病毒阳性并且源码偏移才隔离。输入 AUTO-CONTAIN：') == 'AUTO-CONTAIN':
            args = ['policy', 'auto-contain']
        elif choice == '8':
            args = ['policy', 'alert-only']
        if args:
            subprocess.run(['/usr/bin/python3', '-I', str(DIRECTORY / 'host-security-response.py'), *args], check=False)


def main():
    if os.geteuid() != 0:
        raise SystemExit('root required')
    os.umask(0o077)
    initialize()
    if sys.argv[1:] == ['menu']:
        menu()
        return
    AGENT.private_directory(STATE)
    lock = STATE / 'response.lock'
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise ValueError('unsafe response lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        print(json.dumps(dispatch(sys.argv[1:]), ensure_ascii=False))
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Avoid returning raw subprocess stderr, environment variables or paths carrying credentials.
        print('Local response refused: ' + type(error).__name__ + ' - ' + str(error)[:160], file=sys.stderr)
        raise SystemExit(1)
