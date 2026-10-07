/* Shared helpers */
const CSRF = document.querySelector('meta[name="csrf"]')?.content || '';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

async function api(url, method = 'GET', body) {
  const opt = { method, headers: { 'X-Requested-With': 'fetch', 'X-CSRF-Token': CSRF } };
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  let res, data;
  try { res = await fetch(url, opt); data = await res.json(); }
  catch (e) { throw new Error('Network or server error. Please try again.'); }
  if (res.status === 401 && data.timeout) { location.href = `/${window.PORTAL}/logout?timeout=1`; throw new Error(data.error); }
  if (!res.ok || data.ok === false) throw new Error(data.error || 'Request failed');
  return data;
}

function toast(msg, type = 'ok') {
  let box = $('#toasts'); if (!box) { box = document.createElement('div'); box.id = 'toasts'; document.body.append(box); }
  const t = document.createElement('div'); t.className = 'toast ' + type; t.textContent = msg; box.append(t);
  setTimeout(() => { t.style.transition = '.4s'; t.style.opacity = 0; setTimeout(() => t.remove(), 400); }, 3800);
}

function countUp(el, to, dec = 0, suffix = '') {
  const dur = 1300, t0 = performance.now(); to = Number(to) || 0;
  (function step(t) {
    const p = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - p, 4);
    el.textContent = (to * e).toFixed(dec) + suffix;
    if (p < 1) requestAnimationFrame(step);
  })(t0);
}

function openModal(id) { $('#' + id).classList.add('open'); }
function closeModal(id) { $('#' + id).classList.remove('open'); }
document.addEventListener('click', e => {
  if (e.target.matches('[data-close]')) e.target.closest('.modal').classList.remove('open');
  if (e.target.classList?.contains('modal')) e.target.classList.remove('open');
  const pw = e.target.closest('[data-togglepw]');
  if (pw) { const i = pw.parentElement.querySelector('input'); i.type = i.type === 'password' ? 'text' : 'password'; }
});

function busy(btn, on) {
  if (on) { btn._h = btn.innerHTML; btn.disabled = true; btn.innerHTML = '<span class="spin"></span> Please wait'; }
  else { btn.disabled = false; btn.innerHTML = btn._h; }
}

function debounce(fn, ms = 300) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }

async function copyText(txt) {
  try { await navigator.clipboard.writeText(txt); toast('Copied to clipboard'); }
  catch { toast('Copy failed – select and copy manually', 'err'); }
}

/* Idle session timeout (mirrors the server-side timeout) */
(function idle() {
  const total = (window.SESSION_SECONDS || 0) * 1000;
  if (!total || !document.body.dataset.auth) return;
  let last = Date.now(), lastPing = Date.now(), warned = false;
  const bump = () => {
    last = Date.now(); warned = false; $('#idleModal')?.classList.remove('open');
    if (Date.now() - lastPing > 60000) { lastPing = Date.now(); fetch(`/${window.PORTAL}/ping`, { method: 'POST', headers: { 'X-CSRF-Token': CSRF, 'X-Requested-With': 'fetch' } }).catch(() => {}); }
  };
  ['click', 'keydown', 'mousemove', 'touchstart', 'scroll'].forEach(ev => addEventListener(ev, debounce(bump, 400), { passive: true }));
  setInterval(() => {
    const left = total - (Date.now() - last);
    if (left <= 0) location.href = `/${window.PORTAL}/logout?timeout=1`;
    else if (left < 60000 && !warned) { warned = true; $('#idleModal')?.classList.add('open'); }
    const c = $('#idleCount'); if (c) c.textContent = Math.max(0, Math.ceil(left / 1000));
  }, 1000);
})();

/* Mobile menu */
document.addEventListener('click', e => { if (e.target.closest('.menu-btn')) $('.side')?.classList.toggle('open'); });
