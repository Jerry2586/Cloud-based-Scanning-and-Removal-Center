#!/usr/bin/env python3
"""Bounded host discovery. Observations are never a trusted baseline or an allowlist."""
import importlib.util
import argparse, datetime, hashlib, itertools, json, os, pathlib, re, stat, time

_env_spec = importlib.util.spec_from_file_location('ironcurtain_environment', pathlib.Path(__file__).with_name('environment.py'))
environment = importlib.util.module_from_spec(_env_spec); _env_spec.loader.exec_module(environment)

NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$')
MAX_CONTAINERS = 32
EXCLUDED = ('/proc', '/sys', '/dev', '/run', '/etc/ironcurtain', '/var/lib/ironcurtain', '/var/lib/ironcurtain-antivirus', '/opt/ironcurtain')

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')

def safe_path(value):
    if not isinstance(value, str) or len(value) > 1024 or re.search(r'[\x00-\x1f\x7f]', value): return False
    p = pathlib.PurePosixPath(value)
    if not p.is_absolute() or str(p) != value or '..' in p.parts: return False
    return value not in ('/', '/etc', '/opt', '/srv', '/var', '/var/lib', '/var/lib/docker', '/var/lib/docker/volumes') and not any(value == x or value.startswith(x + '/') for x in EXCLUDED)

def real_directory(value):
    if not safe_path(value): return False
    try:
        p = pathlib.Path(value)
        return p.is_dir() and str(p.resolve(strict=True)) == value
    except (OSError, ValueError): return False

def candidate(kind, value, origin):
    ident = hashlib.sha256((kind + '\0' + value).encode()).hexdigest()[:16]
    return {'id': ident, 'kind': kind, 'value': value, 'origin': origin}

def parse_listeners(text, protocol):
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if fields and fields[0] in ('tcp', 'udp'): fields = fields[1:]
        if len(fields) < 5: raise ValueError('invalid listener output')
        local = fields[3]; port = local.rsplit(':', 1)[-1]
        if not port.isdigit() or not 1 <= int(port) <= 65535: raise ValueError('invalid listener port')
        processes = re.findall(r'\("([^"\x00-\x1f]{1,80})",pid=(\d+)', line)
        rows.append({'protocol': protocol, 'address': local[:160], 'port': int(port),
                     'processes': [{'name': name, 'pid': int(pid)} for name, pid in processes[:4]]})
        if len(rows) > 128: raise ValueError('listener inventory truncated')
    return rows

def discover(run, roots=('/opt', '/srv', '/var/www'), exists=real_directory, previous=None):
    result = {'schema': 'ironcurtain-inventory/v1', 'observed_at': now(), 'containers': [],
              'listeners': [], 'candidates': [], 'issues': [], 'container_state': 'unavailable',
              'listener_state': 'unavailable', 'directory_state': 'complete', 'drift': [], 'drift_state': 'first-observation'}
    suggestions = {}
    deadline = time.monotonic() + 20
    execute = run
    def run(args, maximum=262144):
        remaining = deadline - time.monotonic()
        if remaining <= 0: return None, 'discovery time budget exceeded'
        return execute(args, seconds=min(3, remaining), maximum=maximum)
    def suggest(kind, value, origin):
        if exists(value): suggestions[(kind, value)] = candidate(kind, value, origin)
    result['environment'] = environment.discover(run, previous=previous.get('environment') if isinstance(previous, dict) else None)
    for root in roots:
        try:
            entries = list(itertools.islice(pathlib.Path(root).iterdir(), 65))
            if len(entries) > 64: result['directory_state'] = 'partial'
            for entry in entries[:64]: suggest('program_roots', str(entry), '常见网站/应用目录')
        except FileNotFoundError: pass
        except OSError: result['directory_state'] = 'partial'
    code, text = run(['docker', 'ps', '-a', '--format', '{{.Names}}'])
    if code == 0:
        names = text.splitlines()
        if any(not NAME.fullmatch(x) for x in names) or len(names) != len(set(names)):
            result['issues'].append('Docker 容器清单格式异常')
        else:
            result['container_state'] = 'partial' if len(names) > MAX_CONTAINERS else 'complete'
            for name in names[:MAX_CONTAINERS]:
                if time.monotonic() >= deadline:
                    result['container_state'] = 'partial'; result['issues'].append('容器发现达到时间上限'); break
                code, raw = run(['docker', 'inspect', '--type', 'container', '--', name])
                try:
                    items = json.loads(raw)
                    if code != 0 or not isinstance(items, list) or len(items) != 1: raise ValueError()
                    item = items[0]
                    if item.get('Name') != '/' + name: raise ValueError()
                    image = item.get('Image', '')
                    if not re.fullmatch(r'sha256:[a-f0-9]{64}', image): raise ValueError()
                    host = item.get('HostConfig') or {}; config = item.get('Config') or {}
                    risks = []
                    if host.get('Privileged'): risks.append('特权容器')
                    if host.get('PidMode') == 'host': risks.append('共享宿主 PID')
                    if host.get('NetworkMode') == 'host': risks.append('共享宿主网络')
                    if host.get('CapAdd'): risks.append('额外 Linux 权限')
                    mounts = []
                    if not isinstance(item.get('Mounts', []), list) or len(item.get('Mounts', [])) > 32: raise ValueError()
                    user = config.get('User', '')
                    if not isinstance(user, str) or len(user) > 80 or re.search(r'[\x00-\x1f\x7f]', user): raise ValueError()
                    for mount in item.get('Mounts', []):
                        source = mount.get('Source', ''); target = mount.get('Destination', '')
                        if not isinstance(source, str) or not isinstance(target, str): raise ValueError()
                        if len(source) > 1024 or len(target) > 1024 or re.search(r'[\x00-\x1f\x7f]', source + target): raise ValueError()
                        mounts.append({'source': source, 'target': target, 'writable': mount.get('RW') is True})
                        if source in ('/', '/etc', '/proc', '/sys', '/dev') or source.endswith('/docker.sock'):
                            risks.append('敏感宿主挂载')
                        if mount.get('Type') in ('bind', 'volume'): suggest('business_roots', source, '容器挂载目录：' + name)
                    data = item.get('GraphDriver', {}).get('Data') or {}
                    writable = data.get('UpperDir', '')
                    # Enroll only an actual upper layer, never the merged view or whole Docker store.
                    if isinstance(writable, str) and '/overlay' in writable and writable.endswith('/diff'):
                        suggest('business_roots', writable, '容器可写层：' + name)
                    process_code, process_text = run(['docker', 'top', name, '-eo', 'pid,comm'], maximum=32768)
                    process_count = max(0, len(process_text.splitlines()) - 1) if process_code == 0 else None
                    diff_code, diff_text = run(['docker', 'diff', '--', name], maximum=32768)
                    changes = diff_text.splitlines() if diff_code == 0 else []
                    valid_diff = all(re.fullmatch(r'[ACD] /[^\x00-\x1f\x7f]*', line) for line in changes)
                    row = {'name': name, 'image_id': image, 'running': item.get('State', {}).get('Running') is True,
                           'readonly': host.get('ReadonlyRootfs') is True, 'user': user,
                           'risks': sorted(set(risks)), 'mounts': mounts, 'process_count': process_count,
                           'filesystem_state': 'observed' if diff_code == 0 and valid_diff else 'unavailable',
                           'changed_paths': len(changes) if diff_code == 0 and valid_diff else None,
                           'changes_digest': hashlib.sha256(diff_text.encode()).hexdigest() if diff_code == 0 and valid_diff else None}
                    if process_count is None or row['filesystem_state'] != 'observed':
                        result['container_state'] = 'partial'; result['issues'].append('容器进程或可写层未完成读取：' + name)
                    result['containers'].append(row)
                    suggestions[('containers', name)] = candidate('containers', name, 'Docker 容器（不自动批准镜像）')
                except (ValueError, TypeError, KeyError, AttributeError):
                    result['container_state'] = 'partial'; result['issues'].append('容器读取失败：' + name)
    for protocol, args in [('tcp', ['ss', '-H', '-l', '-n', '-t', '-p']), ('udp', ['ss', '-H', '-l', '-n', '-u', '-p'])]:
        code, text = run(args, maximum=65536)
        try:
            if code != 0: raise ValueError()
            result['listeners'].extend(parse_listeners(text, protocol))
        except ValueError: result['issues'].append(protocol.upper() + ' 监听进程读取失败')
    if len(result['listeners']) > 128:
        result['listeners'] = result['listeners'][:128]; result['issues'].append('监听进程清单超过上限')
    result['listener_state'] = 'complete' if not any('监听进程' in x for x in result['issues']) else 'partial'
    result['candidates'] = sorted(suggestions.values(), key=lambda x: (x['kind'], x['value']))[:128]
    if len(suggestions) > 128: result['directory_state'] = 'partial'
    if valid_inventory(previous):
        old = {x['name']: x for x in previous.get('containers', []) if isinstance(x, dict) and isinstance(x.get('name'), str)}
        new = {x['name']: x for x in result['containers']}
        if previous.get('container_state') == result['container_state'] == 'complete':
            for name in sorted(set(old) | set(new)):
                if name not in old: result['drift'].append('新增容器：' + name)
                elif name not in new: result['drift'].append('容器消失：' + name)
                elif any(old[name].get(k) != new[name].get(k) for k in ('image_id', 'readonly', 'user', 'risks', 'mounts')):
                    result['drift'].append('容器配置/镜像变化：' + name)
                elif old[name].get('changes_digest') and new[name].get('changes_digest') and old[name]['changes_digest'] != new[name]['changes_digest']:
                    result['drift'].append('容器可写层变化，需复核：' + name)
        if previous.get('listener_state') == result['listener_state'] == 'complete':
            port_set = lambda rows: {(x['protocol'], x['address'], tuple(sorted({p['name'] for p in x['processes']}))) for x in rows}
            if port_set(previous.get('listeners', [])) != port_set(result['listeners']): result['drift'].append('监听地址、端口或进程归属变化')
        result['drift_state'] = 'compared' if previous.get('container_state') == result['container_state'] == 'complete' and previous.get('listener_state') == result['listener_state'] == 'complete' else 'partial'
    result['drift'] = result['drift'][:64]
    return result

def valid_inventory(value):
    if not isinstance(value,dict) or value.get('schema') != 'ironcurtain-inventory/v1': return False
    if 'environment' in value and not environment.valid(value['environment']): return False
    try:
        stamp=value['observed_at']
        if not isinstance(stamp,str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z',stamp): return False
        datetime.datetime.fromisoformat(stamp.replace('Z','+00:00'))
        if any(value.get(k) not in ('complete','partial','unavailable') for k in ('directory_state','container_state','listener_state')): return False
        if value.get('drift_state') not in ('first-observation','compared','partial'): return False
        for key,limit in (('containers',32),('listeners',128),('candidates',128),('issues',128),('drift',128)):
            if not isinstance(value.get(key),list) or len(value[key])>limit: return False
        if any(not isinstance(x,str) or len(x)>180 or re.search(r'[\x00-\x1f\x7f]',x) for key in ('issues','drift') for x in value[key]): return False
        for x in value['containers']:
            if not isinstance(x,dict) or not isinstance(x.get('name'),str) or not NAME.fullmatch(x['name']): return False
            if type(x.get('running')) is not bool or type(x.get('readonly')) is not bool: return False
            if not isinstance(x.get('image_id'),str) or not re.fullmatch(r'sha256:[a-f0-9]{64}',x['image_id']): return False
            if not isinstance(x.get('risks'),list) or len(x['risks'])>8 or any(not isinstance(y,str) or len(y)>180 or re.search(r'[\x00-\x1f\x7f]',y) for y in x['risks']): return False
            if any(x.get(k) is not None and (type(x[k]) is not int or x[k]<0) for k in ('process_count','changed_paths')): return False
            if not isinstance(x.get('user'),str) or len(x['user'])>80 or re.search(r'[\x00-\x1f\x7f]',x['user']): return False
            if x.get('filesystem_state') not in ('observed','unavailable'): return False
            if x['filesystem_state']=='observed':
                if type(x.get('changed_paths')) is not int or not isinstance(x.get('changes_digest'),str) or not re.fullmatch(r'[a-f0-9]{64}',x['changes_digest']): return False
            elif x.get('changed_paths') is not None or x.get('changes_digest') is not None: return False
            if not isinstance(x.get('mounts'),list) or len(x['mounts'])>32: return False
            for mount in x['mounts']:
                if not isinstance(mount,dict) or type(mount.get('writable')) is not bool: return False
                if any(not isinstance(mount.get(k),str) or len(mount[k])>1024 or re.search(r'[\x00-\x1f\x7f]',mount[k]) for k in ('source','target')): return False
        if len({x['name'] for x in value['containers']}) != len(value['containers']): return False
        for x in value['listeners']:
            if not isinstance(x,dict) or x.get('protocol') not in ('tcp','udp') or type(x.get('port')) is not int or not 1<=x['port']<=65535: return False
            if not isinstance(x.get('address'),str) or len(x['address'])>160 or re.search(r'[\x00-\x1f\x7f]',x['address']): return False
            if not isinstance(x.get('processes'),list) or len(x['processes'])>4: return False
            for process in x['processes']:
                if not isinstance(process,dict) or not isinstance(process.get('name'),str) or not 1<=len(process['name'])<=80 or re.search(r'[\x00-\x1f\x7f]',process['name']) or type(process.get('pid')) is not int or process['pid']<=0: return False
        for x in value['candidates']:
            if not isinstance(x,dict) or x.get('kind') not in ('program_roots','business_roots','containers'): return False
            if not isinstance(x.get('value'),str) or not isinstance(x.get('origin'),str) or len(x['origin'])>180 or re.search(r'[\x00-\x1f\x7f]',x['origin']): return False
            if x['kind']=='containers':
                if not NAME.fullmatch(x['value']): return False
            elif not safe_path(x['value']): return False
            if x.get('id') != candidate(x['kind'],x['value'],x['origin'])['id']: return False
        return True
    except (KeyError,ValueError,TypeError): return False

def protection(profile, inventory, engine, checks, checked_at=None):
    if not valid_inventory(inventory): inventory = {}
    enrolled = {x['name'] for x in profile.get('containers', [])}
    discovered = {x['name'] for x in inventory.get('containers', [])}
    issues = []
    roots = profile.get('program_roots', []) + profile.get('business_roots', [])
    if not roots: issues.append('尚未配置任何文件扫描目录')
    if not engine.get('installed') or engine.get('state') != 'configured': issues.append('病毒引擎/官方病毒库尚未就绪')
    if profile.get('program_roots') and not profile.get('baseline'): issues.append('程序目录缺少独立签名基线')
    if profile.get('config_files') and not profile.get('baseline'): issues.append('关键配置缺少独立签名基线')
    if any(not x.get('image_id') for x in profile.get('containers', [])): issues.append('已纳管容器尚未批准可信镜像')
    if inventory.get('directory_state') != 'complete': issues.append('应用目录候选发现未完成')
    if inventory.get('container_state') != 'complete': issues.append('Docker 容器发现未完成')
    if discovered - enrolled: issues.append('存在未纳管容器')
    if inventory.get('listener_state') != 'complete': issues.append('监听端口/进程发现未完成')
    if not profile.get('approved_tcp_ports') or not profile.get('approved_udp_ports'): issues.append('TCP/UDP 端口允许清单尚未全部配置')
    if not checked_at or len(checks) != 25: issues.append('尚无本次完整核验报告')
    try:
        observed=datetime.datetime.fromisoformat(inventory.get('observed_at','').replace('Z','+00:00'))
        age=(datetime.datetime.now(datetime.timezone.utc)-observed).total_seconds()
        if age < -30 or age > 900: issues.append('资产发现报告过期或时间异常')
    except (ValueError,TypeError): issues.append('资产发现报告时间无效')
    if checked_at:
        try:
            age = (datetime.datetime.now(datetime.timezone.utc) - datetime.datetime.fromisoformat(checked_at.replace('Z', '+00:00'))).total_seconds()
            if age < -30 or age > 900: issues.append('核验报告过期或时间异常')
        except (ValueError, TypeError): issues.append('核验报告时间无效')
    env = inventory.get('environment', {})
    if not isinstance(env, dict): env = {}
    if not environment.valid(env) or any(env.get(k) != 'complete' for k in ('system_state','package_state','service_state')): issues.append('系统软件/服务环境清单未完整核验')
    if env.get('changes'): issues.append('系统软件或服务发生变化，请复核')
    if inventory.get('drift'): issues.append('检测到容器/监听环境变化，请复核')
    if any(x.get('risks') for x in inventory.get('containers', [])): issues.append('发现高权限或敏感挂载容器')
    states = [x.get('state') for x in checks]
    if 'unavailable' in states: issues.append('仍有不可用的核验项目')
    if 'finding' in states: issues.append('核验发现风险，需处置')
    if 'warning' in states: issues.append('核验有待复核项目')
    return {'schema': 'ironcurtain-protection/v1', 'state': 'attention' if 'finding' in states or any(x.get('risks') for x in inventory.get('containers', [])) else 'incomplete' if issues else 'ready',
            'checked_at': checked_at, 'issues': issues[:16], 'program_roots': len(profile.get('program_roots', [])),
            'business_roots': len(profile.get('business_roots', [])), 'enrolled_containers': len(enrolled),
            'discovered_containers': len(discovered), 'unenrolled_containers': len(discovered - enrolled),
            'file_scope': 'configured-directories-only', 'monitor_interval_seconds': 300,
            'trust': 'independent-signatures-required'}

def enroll(profile, inventory, ids):
    if not valid_inventory(inventory): raise ValueError('资产候选记录无效，请重新发现')
    age=(datetime.datetime.now(datetime.timezone.utc)-datetime.datetime.fromisoformat(inventory['observed_at'].replace('Z','+00:00'))).total_seconds()
    if age < -30 or age > 120: raise ValueError('资产候选记录已过期，请重新发现')
    candidates = {x['id']: x for x in inventory.get('candidates', [])}
    if not ids or len(ids) > 64 or len(set(ids)) != len(ids) or any(x not in candidates for x in ids): raise ValueError('选择无效，请重新发现')
    result = json.loads(json.dumps(profile))
    for ident in ids:
        item = candidates[ident]; key = item['kind']; value = item['value']
        if key not in ('program_roots', 'business_roots', 'containers'): raise ValueError('unsupported candidate')
        if key == 'containers':
            if not NAME.fullmatch(value): raise ValueError('unsafe container')
            values = result.setdefault(key, [])
            if not any(x['name'] == value for x in values): values.append({'name': value})
        else:
            if not real_directory(value): raise ValueError('目录变化、包含链接或不可读，请重新发现')
            values = result.setdefault(key, [])
            if value not in values: values.append(value)
        if len(values) > 32: raise ValueError('范围超过上限，请分批纳管')
    return result

if __name__ == '__main__':
    import agent
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=['discover', 'enroll']); parser.add_argument('--profile', required=True); parser.add_argument('--inventory'); parser.add_argument('--output'); args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0: raise SystemExit('请在 Linux 使用 root 执行')
    profile = agent.profile_validate(agent.private_json(args.profile))
    if args.action == 'discover':
        value = discover(agent.Runner())
        if args.output: agent.atomic_json(args.output, value)
        for index, item in enumerate(value['candidates'], 1): print('%d. [%s] %s · %s' % (index, item['kind'], item['value'], item['origin']))
        for issue in value['issues']: print('未完成：' + issue)
        print('自动发现仅用于选择保护范围；不会批准镜像、端口或签名基线。')
    else:
        value = agent.private_json(args.inventory)
        indices = [int(x.strip()) for x in input().split(',')]
        if any(x < 1 or x > len(value['candidates']) for x in indices): raise SystemExit('选择序号无效')
        proposed = agent.profile_validate(enroll(profile, value, [value['candidates'][x - 1]['id'] for x in indices]))
        if not args.output: raise SystemExit('missing staged output')
        agent.atomic_json(args.output, proposed)


def _public_inventory(value):
    if not isinstance(value, dict) or value.get('schema') != 'ironcurtain-inventory/v1': return {'state': 'unavailable'}
    return {'schema': value['schema'], 'observed_at': value['observed_at'], 'container_state': value['container_state'],
            'listener_state': value['listener_state'], 'directory_state': value['directory_state'],
            'container_count': len(value['containers']), 'listener_count': len(value['listeners']), 'candidate_count': len(value['candidates']),
            'containers': [{k: x[k] for k in ('name', 'running', 'readonly', 'risks', 'process_count', 'filesystem_state', 'changed_paths')} for x in value['containers'][:8]],
            'listeners': value['listeners'][:8], 'candidates': value['candidates'][:8], 'issues': value['issues'][:8],
            'environment': environment.public(value.get('environment')), 'drift': value['drift'][:8], 'drift_state': value['drift_state'], 'truncated': len(value['containers']) > 8 or len(value['listeners']) > 8 or len(value['candidates']) > 8 or len(value['issues']) > 8 or len(value['drift']) > 8}


def public_inventory(value):
    try:
        if not valid_inventory(value): return {'state': 'unavailable'}
        for key, limit in (('containers',32),('listeners',128),('candidates',128),('issues',128),('drift',128)):
            if not isinstance(value.get(key), list) or len(value[key]) > limit: return {'state': 'unavailable'}
        if any(not isinstance(x, dict) for key in ('containers','listeners','candidates') for x in value[key]): return {'state': 'unavailable'}
        if any(not isinstance(x, str) for key in ('issues','drift') for x in value[key]): return {'state': 'unavailable'}
        return _public_inventory(value)
    except (TypeError, KeyError, ValueError): return {'state': 'unavailable'}
