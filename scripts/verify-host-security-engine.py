#!/usr/bin/env python3
"""CI-only real ClamAV execution using a synthetic rule, not an official feed."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch
import zipfile

if os.environ.get('GITHUB_ACTIONS') != 'true' or sys.platform != 'linux':
    raise SystemExit('Only isolated Linux GitHub Actions runners are supported')
spec = importlib.util.spec_from_file_location('appgog_acceptance_agent', sys.argv[1])
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)
assert agent.SCANNER.is_file(), 'real distribution clamscan required'
with tempfile.TemporaryDirectory(prefix='appgog-engine-ci-') as temp:
    root = Path(temp)
    agent.ROOT = root
    for name in agent.PROGRAM_DIRS:
        (root / name).mkdir()
    for name in agent.PROGRAM_ROOT_FILES:
        (root / name).write_text(json.dumps({'version': '1.2.68'}) if name == 'package.json' else 'clean fixture')
    agent.CLAM_DATABASE = root / 'test-only-db'
    agent.CLAM_DATABASE.mkdir()
    # Synthetic test rule: validates real engine exit codes and limit alerts only.
    marker = b'APPGOG_ACCEPTANCE_ONLY_PATTERN_93af01c7'
    (agent.CLAM_DATABASE / 'acceptance.ndb').write_text('Appgog.CI.Pattern:0:*:' + marker.hex() + '\n')
    target = root / 'apps' / 'fixture.bin'
    target.write_bytes(b'clean fixture')
    # A local test rule is not a fresh official daily database.
    assert agent.malware_scan()['state'] == 'unavailable'
    with patch.object(agent, 'daily_database_identity', return_value={'test-only': True}):
        assert agent.malware_scan()['state'] == 'ok', 'real clean engine path'
        target.write_bytes(marker)
        assert agent.malware_scan()['state'] == 'finding', 'real detection exit code'
        assert target.read_bytes() == marker, 'read-only engine must not remove or repair files'
        target.write_bytes(b'clean fixture')
        archive = root / 'apps' / 'limits.zip'
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr('oversized.txt', b'Z' * (9 * 1024 * 1024))
        assert agent.malware_scan()['state'] == 'unavailable', 'ZIP coverage limit must not report clean'
        archive.unlink()
        (agent.CLAM_DATABASE / 'acceptance.ndb').write_text('invalid database')
        assert agent.malware_scan()['state'] == 'unavailable', 'real engine database failure'
    target.write_bytes(b'Z' * agent.MAX_FILE_BYTES)
    assert agent.malware_scan()['state'] == 'unavailable', 'input limit must fail closed'
print('Real ClamAV synthetic-rule acceptance: clean, detection, limits, read-only and failures passed')
