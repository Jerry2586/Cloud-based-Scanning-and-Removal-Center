/* Loaded before styles so a saved preference is applied before the first paint. */
(() => {
  const key = 'ironcurtain.theme';
  const allowed = ['light', 'dark', 'system'];
  const media = window.matchMedia('(prefers-color-scheme: dark)');
  let preference = 'system';
  try { const saved = localStorage.getItem(key); if (allowed.includes(saved)) preference = saved; } catch { /* Storage can be disabled; switching remains available. */ }
  function apply() {
    const theme = preference === 'system' ? (media.matches ? 'dark' : 'light') : preference;
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    document.querySelectorAll('[data-theme-choice]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.themeChoice === preference)));
    document.querySelectorAll('[data-theme-toggle]').forEach(button => {
      const label = theme === 'dark' ? '切换为日间主题' : '切换为夜间主题';
      button.setAttribute('aria-label', label); button.title = label;
      button.querySelectorAll('[data-theme-icon]').forEach(icon => { icon.hidden = icon.dataset.themeIcon === theme; });
      const text = button.querySelector('[data-theme-label]'); if (text) text.textContent = theme === 'dark' ? '日间' : '夜间';
    });
    document.querySelectorAll('[data-theme-status]').forEach(node => { node.textContent = (preference === 'system' ? '跟随系统 · ' : '') + (theme === 'dark' ? '夜间主题' : '日间主题'); });
  }
  function choose(value) {
    if (!allowed.includes(value)) return;
    preference = value;
    try { localStorage.setItem(key, value); } catch { /* Keep the preference for this page session. */ }
    apply();
  }
  apply();
  media.addEventListener('change', () => { if (preference === 'system') apply(); });
  document.addEventListener('DOMContentLoaded', () => {
    document.querySelectorAll('[data-theme-toggle]').forEach(button => button.addEventListener('click', () => choose(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark')));
    document.querySelectorAll('[data-theme-choice]').forEach(button => button.addEventListener('click', () => choose(button.dataset.themeChoice)));
    apply();
  }, { once: true });
})();
