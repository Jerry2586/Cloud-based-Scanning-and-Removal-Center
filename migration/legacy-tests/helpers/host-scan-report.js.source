import { HOST_SCAN_IDS, hostScanCoverage } from '../../packages/core/src/host-scan-contract.js';
export function fullHostReport({ checked_at = new Date().toISOString(), overrides = {} } = {}) {
  const checks = HOST_SCAN_IDS.map(id => ({ id, name: id, state: 'ok', detail: 'bounded result',
    category: 'host', severity: 'info', checked_at, scope: 'fixed test scope', evidence_digest: 'a'.repeat(64),
    ...(overrides[id] ?? {}) }));
  const report = { state: 'finished', checked_at, checks, history: [], history_state: 'ok' };
  return { ...report, coverage: hostScanCoverage(report) };
}
