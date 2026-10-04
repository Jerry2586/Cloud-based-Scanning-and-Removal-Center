// Fixed report contract shared by the local API and its outbound summary.
export const HOST_SCAN_IDS = Object.freeze([
  'integrity.program',
  'host.configuration',
  'container.contract',
  'container.approved-image',
  'response.containment',
  'host.os-release',
  'host.systemd-state',
  'ssh.effective',
  'permissions.secret-inventory',
  'permissions.installation',
  'permissions.cron',
  'network.listeners',
  'network.udp-listeners',
  'network.routes',
  'host.kernel-security',
  'network.firewall',
  'malware.program',
  'malware.business',
  'database.sqlite',
  'host.process-executables',
  'host.failed-units',
  'cloudflare.dns',
  'cloudflare.workers',
  'cloudflare.rules',
  'cloudflare.settings'
]);
export const HOST_SCAN_SCHEMA = 'appgog-host-scan/v1';
export const CHECK_CATEGORIES = new Set(['host', 'container', 'permissions', 'ssh', 'network', 'malware']);
export const CHECK_SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical', 'unknown']);
export const CHECK_STATES = new Set(['ok', 'warning', 'finding', 'unavailable']);

export function safeTimestamp(value) {
  if (typeof value !== 'string' || value.length > 40 ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(value) ||
      !Number.isFinite(Date.parse(value)) || new Date(value).toISOString().slice(0, 19) !== value.slice(0, 19)) return null;
  return value;
}

export function validHostCheck(item) {
  return Boolean(item && typeof item.name === 'string' && item.name.length > 0 &&
    typeof item.detail === 'string' && CHECK_STATES.has(item.state) &&
    typeof item.id === 'string' && /^[a-z0-9][a-z0-9._-]{0,79}$/.test(item.id) &&
    CHECK_CATEGORIES.has(item.category) && CHECK_SEVERITIES.has(item.severity) &&
    safeTimestamp(item.checked_at) && typeof item.scope === 'string' && item.scope.length > 0 && item.scope.length <= 120 &&
    typeof item.evidence_digest === 'string' && /^[a-f0-9]{64}$/.test(item.evidence_digest));
}

export function completeHostScan(report) {
  if (!report || report.state !== 'finished' || !safeTimestamp(report.checked_at) ||
      !Array.isArray(report.checks) || report.checks.length < HOST_SCAN_IDS.length ||
      report.checks.length > HOST_SCAN_IDS.length + 1) return false;
  const seen = new Set();
  for (const item of report.checks) {
    if (!validHostCheck(item) || seen.has(item.id) ||
        (!HOST_SCAN_IDS.includes(item.id) && item.id !== 'host.history') ||
        Date.parse(item.checked_at) > Date.parse(report.checked_at) + 120000) return false;
    if (item.id === 'host.history' && (item.state !== 'unavailable' || report.history_state !== 'unavailable')) return false;
    seen.add(item.id);
  }
  return HOST_SCAN_IDS.every(id => seen.has(id));
}

export function hostScanCoverage(report) {
  return { schema: HOST_SCAN_SCHEMA, expected: HOST_SCAN_IDS.length,
    checked: new Set((report.checks ?? []).filter(item => HOST_SCAN_IDS.includes(item.id)).map(item => item.id)).size,
    complete: completeHostScan(report) };
}

export function freshHostScan(report, now = Date.now()) {
  const fresh = value => safeTimestamp(value) && Date.parse(value) >= now - 900000 && Date.parse(value) <= now + 120000;
  return Boolean(completeHostScan(report) && fresh(report.checked_at) && report.checks.every(item => fresh(item.checked_at)));
}

// Progress counts finished fixed checks (including unavailable), never elapsed time or estimated files.
export function hostScanProgress(report) {
  const p=report?.progress, checks=report?.checks;
  if (!['running','finished'].includes(report?.state) || !p || !Array.isArray(checks) || p.total!==HOST_SCAN_IDS.length || !Number.isInteger(p.completed) || p.completed<0 || p.completed>p.total || p.completed!==checks.length) return null;
  if (!checks.every((item,index)=>validHostCheck(item) && item.id===HOST_SCAN_IDS[index])) return null;
  if (p.current!==(p.completed<p.total ? HOST_SCAN_IDS[p.completed] : null)) return null;
  return {completed:p.completed,total:p.total,current:p.current};
}
