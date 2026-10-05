"""Fixed, bounded Linux software/service inventory. No secrets or shell execution."""
import hashlib
import json
import pathlib
import platform
import re

SCHEMA = 'ironcurtain-environment/v1'
STATES = ('complete', 'partial', 'unavailable')
MAX_PACKAGES = 4096
MAX_SERVICES = 512
TOKEN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.+:~%/@=-]{0,159}$')
UNIT = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.@\\:-]{0,159}\.service$')

def text(value, limit=180):
    return isinstance(value, str) and len(value) <= limit and not re.search(r'[\x00-\x1f\x7f]', value)

def digest(rows):
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()

def read_release():
    # OS release data is a fixed public file, never a profile/browser-provided path.
    with pathlib.Path('/etc/os-release').open('rb') as stream:
        raw = stream.read(8193)
    if len(raw) > 8192: raise ValueError('os-release exceeds budget')
    fields = {}
    for line in raw.decode('utf-8', 'strict').splitlines():
        key, sep, value = line.partition('=')
        if sep and key in ('PRETTY_NAME', 'ID', 'VERSION_ID'):
            value = value.strip().strip('"').strip("'")
            if not text(value, 160): raise ValueError('invalid release field')
            fields[key] = value
    if not fields.get('ID'): raise ValueError('missing distribution')
    return fields

def packages(raw, manager):
    rows = []
    for line in raw.splitlines():
        fields = line.split('\t')
        if manager == 'dpkg':
            if len(fields) != 3 or len(fields[0]) != 3: raise ValueError('invalid dpkg output')
            if fields[0][:2] != 'ii': continue
            name, version = fields[1:]
        else:
            if len(fields) != 2: raise ValueError('invalid rpm output')
            name, version = fields
        if not TOKEN.fullmatch(name) or not TOKEN.fullmatch(version): raise ValueError('invalid package token')
        rows.append({'name': name, 'version': version})
        if len(rows) > MAX_PACKAGES: return sorted(rows[:MAX_PACKAGES], key=lambda x: (x['name'], x['version'])), 'partial'
    if len({(x['name'], x['version']) for x in rows}) != len(rows): raise ValueError('duplicate package')
    return sorted(rows, key=lambda x: (x['name'], x['version'])), 'complete'

def services(raw):
    rows = []
    for line in raw.splitlines():
        fields = line.split()
        if len(fields) < 4 or not UNIT.fullmatch(fields[0]) or any(not TOKEN.fullmatch(x) for x in fields[1:4]):
            raise ValueError('invalid service output')
        rows.append(dict(zip(('name', 'load', 'active', 'sub'), fields[:4])))
        if len(rows) > MAX_SERVICES: return sorted(rows[:MAX_SERVICES], key=lambda x: x['name']), 'partial'
    if len({x['name'] for x in rows}) != len(rows): raise ValueError('duplicate service')
    return sorted(rows, key=lambda x: x['name']), 'complete'

def discover(run, previous=None, release_reader=read_release, kernel_reader=platform.release):
    value = {'schema': SCHEMA, 'os': {}, 'kernel': '', 'system_state': 'unavailable',
             'package_manager': 'unknown', 'package_state': 'unavailable', 'service_state': 'unavailable',
             'packages': [], 'services': [], 'issues': [], 'changes': [], 'change_state': 'first-observation'}
    try:
        release = release_reader(); kernel = kernel_reader()
        if not text(kernel, 160) or not kernel or not isinstance(release, dict) or not release.get('ID') or not all(text(v,160) for v in release.values()): raise ValueError('invalid system metadata')
        value.update(os={k: release[k] for k in ('PRETTY_NAME','ID','VERSION_ID') if k in release}, kernel=kernel, system_state='complete')
    except (OSError, ValueError, UnicodeError): value['issues'].append('Linux 系统版本读取失败')
    code, raw = run(['dpkg-query', '-W', '-f=${db:Status-Abbrev}\t${binary:Package}\t${Version}\n'], maximum=1024*1024)
    manager = 'dpkg'
    if code is None and raw == 'dependency unavailable':
        code, raw = run(['rpm', '-qa', '--qf', '%{NAME}.%{ARCH}\t%{VERSION}-%{RELEASE}\n'], maximum=1024*1024)
        manager = 'rpm'
    try:
        if code != 0: raise ValueError('package query failed')
        value['packages'], value['package_state'] = packages(raw, manager)
        value['package_manager'] = manager
    except (ValueError, TypeError): value['issues'].append('系统软件清单未完成读取；不代表没有安装软件')
    code, raw = run(['systemctl', 'list-units', '--type=service', '--all', '--plain', '--no-legend', '--no-pager', '--full'], maximum=262144)
    try:
        if code != 0: raise ValueError('service query failed')
        value['services'], value['service_state'] = services(raw)
    except (ValueError, TypeError): value['issues'].append('系统服务清单未完成读取；不代表没有运行服务')
    if value['package_state'] == 'partial': value['issues'].append('软件清单达到 4096 条上限，覆盖不完整')
    if value['service_state'] == 'partial': value['issues'].append('服务清单达到 512 条上限，覆盖不完整')
    if valid(previous):
        comparisons = []
        for key, state, label in [('packages','package_state','系统软件'), ('services','service_state','系统服务')]:
            if value[state] == previous[state] == 'complete':
                comparisons.append(True)
                def group(rows):
                    grouped = {}
                    for row in rows:
                        grouped.setdefault(row['name'], []).append(row)
                    return {name: sorted(items, key=lambda x: json.dumps(x,sort_keys=True)) for name,items in grouped.items()}
                old, new = group(previous[key]), group(value[key])
                for ident in sorted(set(old) | set(new)):
                    if ident not in old: value['changes'].append(label+'新增：'+ident)
                    elif ident not in new: value['changes'].append(label+'移除：'+ident)
                    elif new[ident] != old[ident]: value['changes'].append(label+('版本变化：' if key == 'packages' else '状态变化：')+ident)
            else: comparisons.append(False)
        comparisons.append(value['system_state'] == previous['system_state'] == 'complete')
        if comparisons[-1]:
            if value['os'] != previous['os'] or value['kernel'] != previous['kernel']: value['changes'].append('系统版本或内核发生变化')
        value['change_state'] = 'compared' if all(comparisons) else 'partial'
    value['changes_total'] = len(value['changes'])
    value['changes'] = value['changes'][:32]
    value['packages_digest'] = digest(value['packages'])
    value['services_digest'] = digest(value['services'])
    return value

def valid(value):
    if not isinstance(value, dict) or value.get('schema') != SCHEMA: return False
    if any(value.get(k) not in STATES for k in ('system_state','package_state','service_state')): return False
    if value.get('package_manager') not in ('dpkg','rpm','unknown') or value.get('change_state') not in ('first-observation','compared','partial'): return False
    if not isinstance(value.get('os'),dict) or set(value['os'])-{'PRETTY_NAME','ID','VERSION_ID'} or not all(text(v,160) for v in value['os'].values()) or not text(value.get('kernel'),160): return False
    if value['system_state'] == 'complete' and (not value['os'].get('ID') or not value['kernel']): return False
    for key, limit in [('issues',8),('changes',32)]:
        if not isinstance(value.get(key),list) or len(value[key])>limit or not all(text(x,180) for x in value[key]): return False
    if type(value.get('changes_total')) is not int or not len(value['changes']) <= value['changes_total'] <= 2*(MAX_PACKAGES+MAX_SERVICES)+1: return False
    for key, limit in [('packages',MAX_PACKAGES),('services',MAX_SERVICES)]:
        rows = value.get(key)
        if not isinstance(rows,list) or len(rows)>limit or not all(isinstance(x,dict) for x in rows): return False
        if key == 'packages':
            if any(set(x)!= {'name','version'} or not all(isinstance(x[k],str) and TOKEN.fullmatch(x[k]) for k in ('name','version')) for x in rows): return False
        else:
            if any(set(x)!= {'name','load','active','sub'} or not isinstance(x['name'],str) or not UNIT.fullmatch(x['name']) or not all(isinstance(x[k],str) and TOKEN.fullmatch(x[k]) for k in ('load','active','sub')) for x in rows): return False
        identities = [(x['name'],x['version']) for x in rows] if key == 'packages' else [x['name'] for x in rows]
        if len(set(identities)) != len(rows): return False
        if value[key[:-1]+'_state'] == 'unavailable' and rows: return False
        if value.get(key+'_digest') != digest(rows): return False
    return True

def public(value):
    if not valid(value): return {'state':'unavailable'}
    return {k:value[k] for k in ('schema','os','kernel','system_state','package_manager','package_state','service_state','issues','changes','change_state','changes_total','packages_digest','services_digest')} | {
        'package_count':len(value['packages']), 'service_count':len(value['services']),
        'running_services':sum(x['active']=='active' for x in value['services']),
        'failed_services':sum(x['active']=='failed' for x in value['services']),
        'packages':value['packages'][:32], 'services':sorted(value['services'], key=lambda x:(x['active']!='failed',x['active']!='active',x['name']))[:16],
        'truncated':len(value['packages'])>32 or len(value['services'])>16 or value['changes_total']>32}
