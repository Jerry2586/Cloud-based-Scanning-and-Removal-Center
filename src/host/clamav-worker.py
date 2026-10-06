#!/usr/bin/env python3
"""Fixed Go adapter: reuse the pinned file queue and managed official database."""
import hashlib, importlib.util, json, os, pathlib, signal, sys, threading, time
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('ironcurtain_worker_agent', pathlib.Path(__file__).with_name('agent.py'))
host = importlib.util.module_from_spec(spec); spec.loader.exec_module(host)

def main():
    if len(sys.argv) != 4 or os.geteuid() != 0: raise SystemExit(2)
    profile_file, state_dir, expected = sys.argv[1:]
    profile = host.private_json(profile_file); host.profile_validate(profile)
    if host.fullscan.profile_digest(profile) != expected: raise SystemExit(2)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    state = pathlib.Path(state_dir) / 'multi-clamav'
    engine = host.antivirus.engine_status()
    def emit(value):
        value = {**value, 'findings': list(value['findings'])}
        while True:
            encoded = json.dumps(value, ensure_ascii=False, separators=(',', ':'))
            if len(encoded.encode('utf-8')) <= 12000: break
            if not value['findings']: raise ValueError('worker report exceeds budget')
            value['findings'].pop()
        print(encoded, flush=True)
    empty = {'id':'clamav','state':'unavailable','detail':'保护目录、官方病毒库或 ClamAV 未就绪','completed':0,'total':0,'finding_total':0,'findings':[]}
    if not (profile['program_roots'] or profile['business_roots']) or not engine.get('installed') or engine.get('state') != 'configured' or engine.get('update_state') == 'running':
        emit(empty); return
    last = 0
    def text(value, limit): return ''.join(' ' if ord(c)<32 or ord(c)==127 else c for c in value)[:limit]
    def publish(report):
        nonlocal last
        host.atomic_json(state / 'full-scan-report.json', report)
        final = report.get('state') in ('finished','partial','failed','paused','interrupted')
        if not final and time.monotonic() - last < 1: return
        last = time.monotonic()
        value = {'id':'clamav','state':'complete' if report.get('state') == 'finished' else 'failed' if report.get('state') == 'failed' else 'partial' if final else 'running',
            'detail':'仅扫描纳管目录；复用文件身份核验与可恢复队列',
            'completed':report.get('processed',0),'total':report.get('indexed',0),'finding_total':report.get('infected',0),
            'findings':[{'kind':'malware','severity':'high','target':text(x['path'],256),'rule':text(x['signature'],160),
                         'detail':'sha256=' + x['sha256']} for x in report.get('findings',[])[:16]],
            'evidence_digest':hashlib.sha256(host.canonical(report)).hexdigest()}
        emit(value)
    task = host.fullscan.FullScan(profile, state, host.Runner(), host.secure_fd, engine,
        host.antivirus.DATABASE_DIR, publish, stop, database_status=host.antivirus.database_status)
    task.run()
if __name__ == '__main__': main()
