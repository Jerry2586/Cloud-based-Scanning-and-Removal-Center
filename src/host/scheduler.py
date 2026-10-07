"""Fixed periodic detection. Callbacks run outside the state lock; no commands from callers."""
import copy, datetime, json, pathlib, re, threading, time

IDS = ('quick', 'files', 'engines')
LIMITS = {'quick': (300, 86400), 'files': (3600, 604800), 'engines': (1800, 604800)}
DEFAULTS = {'quick': {'enabled': True, 'interval_seconds': 300}, 'files': {'enabled': False, 'interval_seconds': 86400}, 'engines': {'enabled': False, 'interval_seconds': 21600}}
STATES = ('idle', 'dispatching', 'running', 'complete', 'partial', 'failed', 'unavailable', 'deferred', 'interrupted')
TIMES = ('next_at', 'last_attempt_at', 'last_started_at', 'last_finished_at')

def timestamp(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', value): raise ValueError('invalid schedule timestamp')
    return datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()

def stamp(value):
    return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

def validate_config(value):
    if not isinstance(value, dict) or set(value) != {'revision', 'jobs'}: raise ValueError('invalid schedule config')
    if type(value['revision']) is not int or not 1 <= value['revision'] <= 1000000000: raise ValueError('invalid schedule revision')
    jobs = value['jobs']
    if not isinstance(jobs, dict) or set(jobs) != set(IDS): raise ValueError('invalid schedule jobs')
    for key, item in jobs.items():
        if not isinstance(item, dict) or set(item) != {'enabled', 'interval_seconds'}: raise ValueError('invalid schedule job')
        low, high = LIMITS[key]
        if type(item['enabled']) is not bool or type(item['interval_seconds']) is not int or not low <= item['interval_seconds'] <= high: raise ValueError('invalid schedule interval')
    return copy.deepcopy(value)

def empty_record():
    return {'state': 'idle', 'task_id': None, 'next_at': None, 'last_attempt_at': None, 'last_started_at': None, 'last_finished_at': None, 'attempts': 0}

def validate_record(key, value):
    if not isinstance(value, dict) or set(value) != set(empty_record()): raise ValueError('invalid schedule record')
    if value['state'] not in STATES or type(value['attempts']) is not int or not 0 <= value['attempts'] <= 1000000000: raise ValueError('invalid schedule state')
    task = value['task_id']
    if task is not None and (not isinstance(task, str) or not re.fullmatch(r'[a-f0-9]{' + ('64' if key == 'engines' else '32') + '}', task)): raise ValueError('invalid schedule task identity')
    for field in TIMES:
        if value[field] is not None: timestamp(value[field])
    state, attempt, started, finished = (value[x] for x in ('state', 'last_attempt_at', 'last_started_at', 'last_finished_at'))
    if state == 'idle':
        if task is not None or value['attempts'] != 0 or any((attempt, started, finished)): raise ValueError('invalid idle record')
    else:
        if value['attempts'] < 1 or attempt is None: raise ValueError('missing attempt identity')
        if (task is None) != (started is None): raise ValueError('unbound scheduled task')
        if started is not None and started != attempt: raise ValueError('invalid start identity')
        if state in ('dispatching', 'running'):
            if finished is not None or value['next_at'] is not None: raise ValueError('active task has terminal timestamp')
            if (state == 'running') != (task is not None): raise ValueError('invalid active task identity')
        elif finished is None or finished < attempt: raise ValueError('invalid finish timestamp')
        if state in ('complete', 'partial', 'failed') and task is None: raise ValueError('completion without task')
        if state == 'deferred' and task is not None: raise ValueError('deferred task already started')
    return copy.deepcopy(value)

class Scheduler:
    def __init__(self, directory, read, write, start, observe, clock=time.monotonic, wall=time.time):
        self.file = pathlib.Path(directory) / 'schedule.json'
        self.read, self.write, self.start, self.observe = read, write, start, observe
        self.clock, self.wall = clock, wall
        self.lock, self.gate = threading.Lock(), threading.Lock()
        self.config = {'revision': 1, 'jobs': copy.deepcopy(DEFAULTS)}
        self.records = {key: empty_record() for key in IDS}
        self.due = {}; self.available = True
        now, mono = self.wall(), self.clock()
        try:
            saved = self.read(self.file, 16384)
            if not isinstance(saved, dict) or set(saved) != {'schema', 'config', 'records'} or saved['schema'] != 'ironcurtain-schedule-storage/v1': raise ValueError('invalid schedule storage')
            self.config = validate_config(saved['config'])
            if not isinstance(saved['records'], dict) or set(saved['records']) != set(IDS): raise ValueError('invalid schedule storage jobs')
            self.records = {key: validate_record(key, saved['records'][key]) for key in IDS}
            for key in IDS:
                record, job = self.records[key], self.config['jobs'][key]
                interrupted = record['state'] in ('running', 'dispatching')
                if interrupted: record.update(state='interrupted', last_finished_at=stamp(max(now, timestamp(record['last_attempt_at']))))
                delay = job['interval_seconds'] if interrupted else max(0, min(job['interval_seconds'], timestamp(record['next_at']) - now)) if record['next_at'] else job['interval_seconds']
                self.due[key] = mono + delay
                record['next_at'] = stamp(now + delay) if job['enabled'] else None
        except FileNotFoundError:
            for key in IDS:
                delay = 0 if key == 'quick' else self.config['jobs'][key]['interval_seconds']
                self.due[key] = mono + delay
                self.records[key]['next_at'] = stamp(now + delay) if self.config['jobs'][key]['enabled'] else None
        except (OSError, ValueError, TypeError, KeyError):
            self.available = False
        if self.available:
            with self.lock: self.persist()

    def persist(self):
        try:
            self.write(self.file, {'schema': 'ironcurtain-schedule-storage/v1', 'config': self.config, 'records': self.records})
            return True
        except (OSError, ValueError):
            self.available = False; return False

    def status(self):
        with self.lock:
            return {'schema': 'ironcurtain-schedule/v1', 'state': 'ready' if self.available else 'unavailable', 'config': copy.deepcopy(self.config), 'records': copy.deepcopy(self.records)}

    def configure(self, value):
        try: requested = validate_config(value)
        except (ValueError, TypeError): return 400, {'state': 'unavailable'}
        if not self.gate.acquire(blocking=False): return 409, {'state': 'unavailable'}
        try:
            with self.lock:
                if not self.available: return 503, self._error()
                if requested['revision'] != self.config['revision'] or any(x['state'] in ('running', 'dispatching') for x in self.records.values()): return 409, self._error()
                if self.config['revision'] == 1000000000: return 503, self._error()
                self.config = {'revision': self.config['revision'] + 1, 'jobs': requested['jobs']}
                now, mono = self.wall(), self.clock()
                for key in IDS:
                    job = self.config['jobs'][key]
                    self.due[key] = mono + job['interval_seconds']
                    self.records[key]['next_at'] = stamp(now + job['interval_seconds']) if job['enabled'] else None
                if not self.persist(): return 503, self._error()
            return 200, self.status()
        finally: self.gate.release()

    def _error(self):
        return {'state': 'unavailable'}

    def next(self, key, delay):
        self.due[key] = self.clock() + delay
        self.records[key]['next_at'] = stamp(self.wall() + delay) if self.config['jobs'][key]['enabled'] else None

    def tick(self):
        if not self.gate.acquire(blocking=False): return
        try:
            with self.lock:
                if not self.available: return
                running = [(key, value['task_id']) for key, value in self.records.items() if value['state'] == 'running']
            for key, identity in running:
                try: observed = self.observe(key, identity)
                except Exception: observed = 'unavailable'
                if observed not in ('running', 'complete', 'partial', 'failed', 'unavailable', 'interrupted'): observed = 'unavailable'
                if observed != 'running':
                    with self.lock:
                        record = self.records[key]
                        record.update(state=observed, last_finished_at=stamp(max(self.wall(), timestamp(record['last_started_at']))))
                        self.next(key, self.config['jobs'][key]['interval_seconds'])
                        if not self.persist(): return
            with self.lock:
                if any(x['state'] == 'running' for x in self.records.values()): return
                eligible = [key for key in IDS if self.config['jobs'][key]['enabled'] and self.due[key] <= self.clock()]
                if not eligible: return
                key = min(eligible, key=lambda item: self.due[item])
                record = self.records[key]
                record.update(state='dispatching', task_id=None, last_started_at=None, last_finished_at=None, next_at=None, last_attempt_at=stamp(self.wall()), attempts=min(1000000000, record['attempts'] + 1))
                if not self.persist(): return
            # Agent callbacks acquire their own lock. Never call under scheduler.lock.
            try: code, result = self.start(key)
            except Exception: code, result = 503, {}
            with self.lock:
                identity = result.get('job_id' if key == 'engines' else 'task_id') if isinstance(result, dict) else None
                if code == 202 and isinstance(identity, str) and re.fullmatch(r'[a-f0-9]{' + ('64' if key == 'engines' else '32') + '}', identity):
                    record.update(state='running', task_id=identity, last_started_at=record['last_attempt_at'], next_at=None)
                else:
                    record['state'] = 'deferred' if code in (409, 429) else 'unavailable'
                    record['last_finished_at'] = stamp(max(self.wall(), timestamp(record['last_attempt_at'])))
                    self.next(key, 60 if code in (409, 429) else self.config['jobs'][key]['interval_seconds'])
                self.persist()
        finally: self.gate.release()

    def interrupt(self):
        with self.gate:
            with self.lock:
                if not self.available: return
                for key, record in self.records.items():
                    if record['state'] in ('running', 'dispatching'):
                        record.update(state='interrupted', last_finished_at=stamp(max(self.wall(), timestamp(record['last_attempt_at']))))
                        self.next(key, self.config['jobs'][key]['interval_seconds'])
                self.persist()

    def run(self, stop):
        try:
            while not stop.is_set():
                self.tick()
                if stop.wait(5): break
        finally: self.interrupt()
