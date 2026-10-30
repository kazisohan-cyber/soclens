/*
 * IOC Triage page guard (every page, every frame, document_start).
 *  1. Credential guard: stops the corporate password being typed into any non-corporate site.
 *     Typed values never leave the browser: the service worker compares a salted PBKDF2 hash.
 *  2. Page scanner (top frame): sends light-weight login-page signals to the service worker for a verdict.
 */
(function () {
  'use strict';
  if (window.__VSPageGuard || !/^https?:$/.test(location.protocol)) return;
  window.__VSPageGuard = true;
  const UI = window.__VSUI;
  const isTop = window === window.top;

  // ===================================================== credential guard ===

  let ctx = null;
  // The service worker may still be starting, so retry. Checks made before this settles wait for it.
  const ctxReady = (async () => {
    for (let i = 0; i < 5 && !ctx; i++) {
      if (i) await new Promise((r) => setTimeout(r, 300 * i));
      const c = await UI.send({ type: 'credContext' });
      if (c && !c.error) ctx = c;
    }
  })();

  let locked = false;               // set once a reuse is caught; all submits are then blocked
  const inflight = new Map();       // input -> Promise<boolean match>
  const checked = new WeakMap();    // input -> last value sent for checking
  const BYPASS = Symbol('vs-bypass');

  const isCredInput = (t) => t instanceof HTMLInputElement && (t.type === 'password' || (t.type === 'text' && t.dataset.vsPw === '1'));

  // Remember fields that started as password (show/hide toggles flip them to text).
  document.addEventListener('focusin', (e) => {
    const t = e.target;
    if (t instanceof HTMLInputElement && t.type === 'password') t.dataset.vsPw = '1';
  }, true);

  document.addEventListener('input', (e) => {
    if (isCredInput(e.target)) check(e.target);
  }, true);

  function check(t) {
    const value = t.value;
    checked.set(t, value);
    const skip = () => !ctx || !ctx.enabled || ctx.trusted || !ctx.lens.includes(value.length);
    if (ctx && skip()) return;
    const p = ctxReady.then(() => (skip() ? null : UI.send({ type: 'credCheck', value }))).then((r) => {
      const hit = !!(r && r.match);
      if (hit && t.value === value) neutralise(t, r);
      if (inflight.get(t) === p) inflight.delete(t);
      return hit;
    });
    inflight.set(t, p);
  }

  // Autofill and page scripts can fill a field without an input event.
  function checkFilled() {
    document.querySelectorAll('input[type=password], input[data-vs-pw="1"]').forEach((i) => {
      if (i.value && checked.get(i) !== i.value) check(i);
    });
  }

  function neutralise(input, info) {
    locked = true;
    input.value = '';
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.blur();
    document.querySelectorAll('input[type=password]').forEach((i) => { i.value = ''; });
    const actions = [
      { label: 'Leave this site', kind: 'primary', onClick: () => { location.replace('about:blank'); } },
      { label: 'Stay (fields stay disabled)', onClick: (close) => close() }
    ];
    if (info.canTrust) actions.push({ label: 'This is my work site', kind: 'danger', onClick: (close) => { close(); confirmTrust(input); } });
    UI.modal({
      level: 'block',
      title: 'Stop — this is your work password',
      text: `You just typed your organisation password on ${location.hostname}. This site is not on your organisation's list, so IOC Triage cleared the field before it was sent.`,
      reasons: ['If you already pressed Sign in here before, change your password now',
        info.notified ? 'Your security team has been notified' : 'This is recorded in the activity log on this device only'],
      meta: location.href.slice(0, 300),
      actions
    });
  }

  // A second step on purpose: a phishing page can look identical, and Enter lands on "Keep protection".
  function confirmTrust(input) {
    UI.modal({
      level: 'warn',
      title: `Allow your work password on ${location.hostname}?`,
      text: 'Continue only if you opened this site yourself and you are sure of the address. A phishing site can look identical.',
      reasons: ['IOC Triage will stop guarding your work password on this exact address, and keep checking it for phishing',
        'Using a different password for this site is safer',
        'You can undo this in Settings under Credential guard data'],
      meta: location.hostname,
      actions: [
        { label: 'Keep protection', kind: 'primary', onClick: (close) => close() },
        { label: `Yes, allow ${location.hostname}`, onClick: async (close) => {
          const r = await UI.send({ type: 'credTrust' });
          close();
          if (!r || !r.ok) return;
          locked = false;
          if (ctx) ctx.trusted = true;
          input.focus();
        } }
      ]
    });
  }

  function pendingCheck() {
    const ps = [...inflight.values()];
    return ps.length ? Promise.all(ps).then((r) => r.some(Boolean)) : null;
  }

  // Hold submits/Enter/clicks for the few ms a credential check needs, then replay.
  function hold(e, replay) {
    if (e[BYPASS]) return;
    if (locked) { e.preventDefault(); e.stopImmediatePropagation(); return; }
    checkFilled();
    const p = pendingCheck();
    if (!p) return;
    e.preventDefault(); e.stopImmediatePropagation();
    p.then((hit) => { if (!hit && !locked) replay(); });
  }

  document.addEventListener('submit', (e) => {
    const form = e.target;
    maybeEnroll(form);
    hold(e, () => { form.requestSubmit ? form.requestSubmit() : form.submit(); });
  }, true);

  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || !(e.target instanceof HTMLInputElement)) return;
    maybeEnroll(e.target.form || document);
    const t = e.target;
    hold(e, () => { if (t.form) t.form.requestSubmit ? t.form.requestSubmit() : t.form.submit(); });
  }, true);

  document.addEventListener('click', (e) => {
    const b = e.target instanceof Element && e.target.closest('button, input[type=submit], input[type=button], [role=button]');
    if (!b) return;
    maybeEnroll(b.form || b.closest('form') || document);
    hold(e, () => {
      const ev = new MouseEvent('click', { bubbles: true, cancelable: true, view: window });
      ev[BYPASS] = true;
      b.dispatchEvent(ev);
    });
  }, true);

  // Learn the corporate password (as a salted hash) when the user signs in on a corporate login page.
  function maybeEnroll(scope) {
    if (!ctx || !ctx.enrollHere || !scope || !scope.querySelectorAll) return;
    scope.querySelectorAll('input[type=password], input[data-vs-pw="1"]').forEach((i) => {
      if (i.value && i.value.length >= 8) UI.send({ type: 'credEnroll', value: i.value }).then(() => UI.send({ type: 'credContext' }).then((c) => { ctx = c; }));
    });
  }

  // ======================================================== page scanner ===

  if (!isTop) return;

  // ================================== Verify: account typed on IdP pages ===
  // Only on identity-provider sign-in pages, and only the account name (never the password).
  if (/(^|\.)(login\.microsoftonline\.com|login\.microsoft\.com|login\.live\.com|accounts\.google\.com|okta\.com|oktapreview\.com)$/.test(location.hostname)) {
    const grab = () => {
      const f = document.querySelector('input[name=loginfmt], input#identifierId, input[name=identifier], input[type=email], input[name=username], input[autocomplete=username]');
      const v = f && f.value && f.value.trim();
      if (v && v.includes('@')) UI.send({ type: 'authHint', account: v });
    };
    document.addEventListener('submit', grab, true);
    document.addEventListener('keydown', (e) => { if (e.key === 'Enter') grab(); }, true);
    document.addEventListener('click', (e) => {
      if (e.target instanceof Element && e.target.closest('button, input[type=submit], [role=button]')) grab();
    }, true);
  }

  // ============================== device-code page opened from mail / chat ===
  if (/\/(deviceauth|devicelogin|remoteconnect|device)(\/|$)/i.test(location.pathname)) {
    let warned = false;
    const check = (retry) => UI.send({ type: 'deviceCodeCheck' }).then((r) => {
      if (warned) return;
      if (!(r && r.from)) { if (retry) setTimeout(() => check(false), 1000); return; }
      warned = true;
      UI.top({
        level: 'block', title: 'Did someone send you a sign-in code?',
        text: `This page signs a device in to your account with a code. It was opened from ${r.from}. If a message or caller asked you to enter a code here, stop: it gives them your account.`,
        reasons: ['Only enter a code you got from your own device (TV, phone, terminal) just now'],
        actions: [
          { label: 'Close this page', kind: 'primary', onClick: () => location.replace('about:blank') },
          { label: 'I started this myself', onClick: (close) => close() }
        ]
      });
    });
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', () => check(true), { once: true });
    else check(true);
  }

  let sentWithPassword = false;
  let shown = false;

  const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);

  function collect() {
    const pw = [...document.querySelectorAll('input[type=password]')].filter(visible);
    const s = { hasPassword: pw.length > 0, isHttp: location.protocol === 'http:', brandStrong: [], bodyText: '', formActions: [] };
    if (s.hasPassword) {
      const t = s.brandStrong;
      t.push(document.title || '');
      const og = document.querySelector('meta[property="og:site_name"], meta[name="application-name"]');
      if (og) t.push(og.content || '');
      // Logos inside "Sign in with Google / Microsoft" buttons are SSO, not impersonation: skip them.
      const sso = /(sign|log)\s?(in|up|on)\s+(with|using|via)|continue\s+with|connect\s+with/i;
      let n0 = 0;
      document.querySelectorAll('img[alt], img[src*="logo" i], [aria-label*="logo" i], svg title').forEach((n) => {
        if (n0 >= 30) return;
        const btn = n.closest('button, a, [role=button]');
        if (btn && sso.test((btn.innerText || btn.getAttribute('aria-label') || '') + ' ' + (n.getAttribute('alt') || ''))) return;
        n0++;
        t.push((n.getAttribute('alt') || n.getAttribute('aria-label') || n.textContent || '') + ' ' + (n.getAttribute('src') || '').split('/').pop());
      });
      const fav = document.querySelector('link[rel~="icon"]');
      if (fav) t.push(fav.getAttribute('href') || '');
      s.bodyText = ((document.body && document.body.innerText) || '').slice(0, 3000);
      pw.forEach((p) => { if (p.form && p.form.getAttribute('action')) s.formActions.push(p.form.action); });
    }
    return s;
  }

  async function scan() {
    const s = collect();
    if (s.hasPassword) sentWithPassword = true;
    const r = await UI.send({ type: 'pageSignals', signals: s });
    if (r && r.level === 'warn' && !shown) {
      shown = true;
      const actions = [
        { label: 'Leave this site', kind: 'primary', onClick: () => history.length > 1 ? history.back() : location.replace('about:blank') },
        { label: 'Report to security', onClick: (close, b) => { UI.send({ type: 'report', kind: 'site', url: location.href }); b.textContent = 'Reported ✓'; b.disabled = true; } },
        { label: 'Dismiss', kind: 'danger', onClick: (close) => close() }
      ];
      UI.top({
        level: 'warn', title: r.bypassed ? 'You chose to continue on a dangerous site' : 'This site looks suspicious',
        text: 'Do not enter passwords, payment or personal details here unless you are certain it is genuine.',
        reasons: r.reasons, actions
      });
    }
  }

  function start() {
    scan();
    if (sentWithPassword) return;
    // Late-rendered login forms (SPAs): re-scan once when a password field appears, for up to 15 s.
    let timer = null;
    const mo = new MutationObserver(() => {
      if (timer) return;
      timer = setTimeout(() => {
        timer = null;
        if (!sentWithPassword && document.querySelector('input[type=password]')) { mo.disconnect(); scan(); }
      }, 400);
    });
    mo.observe(document.documentElement, { childList: true, subtree: true });
    setTimeout(() => mo.disconnect(), 15000);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, { once: true });
  else start();
})();
