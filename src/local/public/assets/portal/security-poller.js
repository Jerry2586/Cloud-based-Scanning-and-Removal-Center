// Owns only polling lifecycle. Permissions and session validation stay in the BFF.
export function createSecurityPoller({ request, render, onError, allowed, session,
  schedule = setTimeout, cancel = clearTimeout }) {
  let generation = 0;
  let timer;
  let pending;
  function stop() {
    generation += 1;
    if (timer !== undefined) cancel(timer);
    timer = undefined;
    pending = undefined;
  }
  function run() {
    if (!allowed()) return Promise.resolve();
    if (pending) return pending;
    if (timer !== undefined) cancel(timer);
    timer = undefined;
    const version = generation;
    const identity = session();
    const current = () => version === generation && identity === session() && allowed();
    let delay = 20000;
    pending = Promise.resolve().then(request).then(report => {
      if (!current()) return;
      render(report);
      if (report.state === 'running' || ['indexing','scanning'].includes(report.full_scan?.state)) delay = 2000;
    }).catch(error => {
      if (current()) onError(error);
    }).finally(() => {
      if (version !== generation) return;
      pending = undefined;
      if (current()) timer = schedule(() => { timer = undefined; void run(); }, delay);
    });
    return pending;
  }
  function refresh() { stop(); return run(); }
  return Object.freeze({ run, refresh, stop });
}
