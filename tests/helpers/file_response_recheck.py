"""Official database: real HTTP enrollment, checkup, quarantine, restore and recheck."""
import fcntl
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time

from response_recheck import complete_operation, recheck, require_disposable


def file_response_recheck(api):
    require_disposable()
    spec = importlib.util.spec_from_file_location('official_response_agent', Path(__file__).resolve().parents[2] / 'src/host/agent.py')
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    profile_path = Path('/etc/ironcurtain/local/profile.json')
    original = agent.profile_validate(json.loads(profile_path.read_text()))
    fixture = Path(tempfile.mkdtemp(prefix='ironcurtain-official-response-', dir='/srv'))
    clean = fixture / 'clean.txt'
    infected = fixture / 'eicar.txt'
    content = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    assert len(content) == 68
    clean.write_text('Harmless disposable acceptance fixture.\n')
    infected.write_bytes(content)
    expected = None
    try:
        discovered = complete_operation(api, {'action': 'discover'})
        inventory = discovered['scope']['discovery']
        assert inventory['state'] == 'ready'
        choices = [item for item in inventory['candidates'] if item['kind'] == 'program_roots' and item['value'] == str(fixture)]
        assert len(choices) == 1, 'Disposable file scope not discovered'
        expected = dict(original, program_roots=original['program_roots'] + [str(fixture)])
        enrolled = complete_operation(api, {'action': 'enroll', 'revision': discovered['policy']['revision'], 'inventory': inventory['revision'], 'ids': [choices[0]['id']]})
        assert agent.profile_validate(json.loads(profile_path.read_text())) == expected
        digest = agent.fullscan.profile_digest(expected)
        initial = recheck(api, 'checkup', digest, enrolled['job'])
        hits = [item for item in initial['findings'] if item['path'] == str(infected)]
        assert len(hits) == 1 and 'eicar' in hits[0]['signature'].lower(), 'Official engine did not detect EICAR through panel checkup'
        hit = hits[0]
        assert hit['sha256'] == hashlib.sha256(content).hexdigest()
        assert initial['antivirus']['source'] == 'xuanwu-signed'
        assert not any(item['path'] == str(clean) for item in initial['findings']), 'Clean file reported infected'
        isolated = complete_operation(api, {'action': 'quarantine', 'id': hit['id'], 'confirm': 'quarantine'})
        assert not infected.exists(), 'Completed quarantine left source file present'
        vault = Path('/var/lib/ironcurtain/local/agent/quarantine')
        blob = vault / (hit['id'] + '.blob')
        assert blob.read_bytes() == content, 'Quarantine lost original evidence'
        assert any(item['id'] == hit['id'] and item['state'] == 'quarantined' for item in isolated['quarantine']['items'])
        after_isolation = recheck(api, 'checkup', digest, isolated['job'])
        assert after_isolation['task_id'] != initial['task_id']
        assert not any(item['path'] == str(infected) for item in after_isolation['findings']), 'Isolated source still reported as present'
        assert after_isolation['findings_state'] == 'complete', 'Incomplete findings cannot prove isolation'
        restored = complete_operation(api, {'action': 'restore', 'id': hit['id'], 'confirm': 'restore-original'})
        assert infected.read_bytes() == content and blob.read_bytes() == content
        metadata = infected.stat()
        assert metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) == 0o600
        assert '不能视为干净恢复' in restored['job']['reason']
        after_restore = recheck(api, 'checkup', digest, restored['job'])
        assert after_restore['task_id'] not in (initial['task_id'], after_isolation['task_id'])
        hits = [item for item in after_restore['findings'] if item['path'] == str(infected)]
        assert len(hits) == 1 and hits[0]['sha256'] == hit['sha256'] and 'eicar' in hits[0]['signature'].lower(), 'Restored EICAR incorrectly declared clean'
        assert clean.read_text() == 'Harmless disposable acceptance fixture.\n'
        print('Real official engine HTTP closure: enrolled -> detected -> isolated -> fresh absent report -> original restored -> fresh infected report passed.')
    finally:
        current = agent.profile_validate(json.loads(profile_path.read_text()))
        if current != original:
            assert expected is not None and current == expected, 'Profile changed outside disposable file probe'
            with open('/run/lock/ironcurtain-local.lock', 'rb') as guard:
                deadline = time.monotonic() + 30
                while True:
                    try:
                        fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        assert time.monotonic() < deadline, 'Cleanup lease unavailable'
                        time.sleep(.25)
                agent.atomic_json(profile_path, original)
                subprocess.run(['systemctl', 'restart', 'ironcurtain-agent.service'], check=True, timeout=30)
        # Only this probe's unique fixture is removed. Quarantine evidence stays
        # on the disposable runner; no product or unrelated file is deleted.
        shutil.rmtree(fixture)
