import { createSecurityUi } from './security-ui.js';
const state = { csrf: null }; const $ = id => document.getElementById(id);
let noticeTimer;
function notify(message, error = false) { const node = $('notice'); node.textContent = message; node.dataset.error = String(error); node.hidden = false; clearTimeout(noticeTimer); noticeTimer = setTimeout(() => { node.hidden = true; }, 7000); }
function clearSession() { state.csrf = null; document.dispatchEvent(new Event('ironcurtain-session-cleared')); $('workspace').hidden = true; $('login-view').hidden = false; }
async function request(url, options = {}) {
  const headers = { ...(options.method === 'POST' ? { 'content-type': 'application/json', 'x-csrf-token': state.csrf || '' } : {}) };
  const response = await fetch(url, { credentials: 'same-origin', ...options, headers, body: options.body === undefined ? undefined : JSON.stringify(options.body) });
  const data = await response.json(); if (!response.ok) { if (response.status === 401) clearSession(); throw Error(data.error || data.reason || '请求失败，请稍后重试'); } return data;
}
const ui = createSecurityUi({ state, can: () => Boolean(state.csrf), request, notify });
function authenticated(value) { state.csrf = value.csrf; $('login-view').hidden = true; $('workspace').hidden = false; ui.bind(); ui.render(); }
$('login-form').addEventListener('submit', async event => {
  event.preventDefault(); const form = event.currentTarget; const button = form.querySelector('button'); button.disabled = true; $('login-error').textContent = '';
  try { const data = await request('/api/login', { method: 'POST', body: { username: form.elements.username.value, password: form.elements.password.value } }); form.elements.password.value = ''; authenticated(data); }
  catch (error) { $('login-error').textContent = error.message; } finally { button.disabled = false; }
});
document.querySelectorAll('[data-iron-logout]').forEach(button => button.addEventListener('click', async () => { try { await request('/api/logout', { method: 'POST', body: {} }); clearSession(); } catch(error) { notify(error.message, true); } }));
document.querySelectorAll('[data-iron-account]').forEach(button => button.addEventListener('click', () => notify('本机独立管理账号：admin；密码通过 ironcurtain 管理菜单维护。')));
try { const data = await request('/api/session'); if (data.authenticated) authenticated(data); } catch(error) { notify(error.message, true); }
