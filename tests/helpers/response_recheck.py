"""Disposable Linux acceptance helpers for real authenticated response/recheck."""
from datetime import datetime, timezone
import os
import re
import time


def require_disposable():
    if os.name != 'posix' or os.geteuid() != 0 or os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('IRONCURTAIN_ACCEPT_DISPOSABLE_RUNNER') != '1':
        raise RuntimeError('Requires explicit disposable root Linux CI')


def timestamp(value):
    assert isinstance(value, str), 'Missing task timestamp'
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    assert result.tzinfo is not None, 'Task timestamp must include timezone'
    return result


def complete_operation(api, value, timeout=90):
    require_disposable()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        code, result = api('/api/operations', value)
        if code == 202:
            break
        assert code in (409, 429), 'Operation refused: HTTP ' + str(code)
        time.sleep(.5)
    else:
        raise AssertionError('Operation not accepted within bounded wait')
    job = result['job']
    identity = job['id']
    assert re.fullmatch('[a-f0-9]{32}', identity)
    assert job['action'] == value['action'] and job['state'] == 'running'
    while time.monotonic() < deadline:
        code, result = api('/api/operations')
        assert code == 200, 'Operations status unavailable'
        job = result['job']
        assert job['id'] == identity, 'Operation identity changed'
        if job['state'] != 'running':
            assert job['state'] == 'complete', 'Operation failed: ' + job.get('reason', '')
            assert timestamp(job['finished_at']) >= timestamp(job['started_at'])
            assert any(item['id'] == identity and item['state'] == 'complete' for item in result['audit']), 'Completed operation missing audit'
            return result
        time.sleep(.25)
    raise AssertionError('Operation did not complete within bounded wait')


def recheck(api, action, profile_digest, operation=None, timeout=240):
    require_disposable()
    assert action in ('scan', 'checkup') and re.fullmatch('[a-f0-9]{64}', profile_digest)
    if operation is not None:
        assert operation['state'] == 'complete'
        timestamp(operation['finished_at'])
    ready_deadline = time.monotonic() + 20
    while True:
        code, previous = api('/api/scan')
        if code == 200 and previous.get('state') in ('idle', 'running', 'finished'):
            break
        assert code in (200, 503) and time.monotonic() < ready_deadline, 'Cannot read report before recheck'
        time.sleep(.25)
    old_identity = previous.get('task_id')
    accepted_at = datetime.now(timezone.utc)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        code, accepted = api('/api/' + action, {})
        if code == 202:
            break
        # Real cooldown/management exclusion is allowed; never reset the agent clock.
        assert code in (409, 429), 'Recheck refused: HTTP ' + str(code)
        time.sleep(1)
    else:
        raise AssertionError('Recheck not accepted within bounded wait')
    identity = accepted.get('task_id')
    assert accepted['state'] == 'running' and isinstance(identity, str) and re.fullmatch('[a-f0-9]{32}', identity)
    assert identity != old_identity, 'Old report reused as accepted recheck'
    while time.monotonic() < deadline:
        code, result = api('/api/scan')
        assert code == 200, 'Recheck status unavailable'
        assert result.get('task_id') == identity, 'Recheck report identity changed'
        assert result.get('profile_digest') == profile_digest, 'Recheck loaded wrong policy'
        assert result['state'] in ('running', 'finished'), 'Environment recheck failed'
        task = result.get('checkup', {})
        done = result['state'] == 'finished' if action == 'scan' else task.get('state') in ('finished', 'partial')
        if action == 'checkup':
            assert task.get('task_id') == identity, 'Checkup identity changed'
            assert task.get('state') in ('running', 'finished', 'partial'), 'Checkup failed'
        if done:
            started = timestamp(result['started_at'])
            assert started.timestamp() >= accepted_at.timestamp() - 1, 'Historical report returned'
            if operation is not None:
                assert started >= timestamp(operation['finished_at']), 'Recheck predates response completion'
            assert timestamp(result['checked_at']) >= started
            checks = result['checks']
            assert len(checks) == 25 and len({item['id'] for item in checks}) == 25, 'Incomplete environment report'
            assert all(timestamp(item['checked_at']) >= started for item in checks), 'Old checks mixed into new report'
            if action == 'checkup':
                files = result['full_scan']
                assert task['stage'] == 'complete' and task['profile_digest'] == profile_digest
                assert task['environment_at'] == result['checked_at']
                assert files.get('task_id') == identity and files.get('profile_digest') == profile_digest
                assert files['state'] == 'finished', 'File scan failed or incomplete'
                assert timestamp(files['started_at']) >= timestamp(task['environment_at'])
                assert timestamp(files['finished_at']) <= timestamp(task['updated_at'])
            return result
        time.sleep(.25)
    raise AssertionError('Recheck did not finish within bounded wait')
