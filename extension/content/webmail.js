/*
 * IOC Triage webmail scanner (Gmail + Outlook on the web).
 * Reads the open message locally, asks the service worker for a verdict, then:
 *  - shows a warning banner above a suspicious email,
 *  - disables dangerous links (they can no longer be opened from the email),
 *  - asks for confirmation before opening suspicious links.
 * Only sender / subject / defanged links are ever reported to the SOC — never the body.
 */
(function () {
  'use strict';
  if (window.__VSWebmail) return;
  window.__VSWebmail = true;
  const UI = window.__VSUI;
  const CLIENT = location.hostname === 'mail.google.com' ? 'gmail' : 'outlook';
  const EMAIL_RE = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i;
  const done = new WeakSet();

  // ---------------------------------------------------------- extraction ---

  function bodies() {
    if (CLIENT === 'gmail') return document.querySelectorAll('div.a3s');
    return document.querySelectorAll('div[aria-label="Message body"], div[role="document"]');
  }

  function extract(body) {
    const email = { client: CLIENT, senderName: '', senderEmail: '', subject: '', text: '', links: [], attachments: [] };
    let scope;
    if (CLIENT === 'gmail') {
      scope = body.closest('.adn, [role="listitem"]') || document;
      const s = scope.querySelector('span.gD[email], span[email]');
      if (s) { email.senderEmail = s.getAttribute('email') || ''; email.senderName = s.getAttribute('name') || s.textContent || ''; }
      const h = document.querySelector('h2.hP');
      email.subject = h ? h.textContent : '';
      scope.querySelectorAll('.aV3, .aQA span, [download_url]').forEach((a) => email.attachments.push((a.textContent || a.getAttribute('download_url') || '').trim()));
    } else {
      scope = body.closest('[role="main"], [role="region"]') || document;
      for (const n of scope.querySelectorAll('[title], [aria-label], span')) {
        const v = (n.getAttribute('title') || '') + ' ' + (n.getAttribute('aria-label') || '') + ' ' + (n.childElementCount ? '' : n.textContent || '');
        const m = v.match(EMAIL_RE);
        if (m && !body.contains(n)) {
          email.senderEmail = m[0];
          email.senderName = (n.textContent || '').replace(EMAIL_RE, '').replace(/[<>]/g, '').trim();
          break;
        }
      }
      const h = scope.querySelector('[role="heading"]');
      email.subject = h ? h.textContent : '';
      scope.querySelectorAll('[title]').forEach((n) => {
        const t = n.getAttribute('title') || '';
        if (/\.[a-z0-9]{2,5}$/i.test(t) && !EMAIL_RE.test(t) && !body.contains(n)) email.attachments.push(t);
      });
    }
    email.text = (body.innerText || '').slice(0, 6000);
    const anchors = [...body.querySelectorAll('a[href]')].filter((a) => /^https?:/i.test(a.href)).slice(0, 150);
    email.links = anchors.map((a) => ({ href: a.href, text: (a.textContent || '').trim().slice(0, 200) }));
    email.attachments = [...new Set(email.attachments.filter(Boolean))].slice(0, 20);
    return { email, anchors };
  }

  // ------------------------------------------------------------- actions ---

  function disableLink(a, info) {
    a.dataset.vsBlocked = '1';
    a.dataset.vsReal = info.real;
    a.dataset.vsReasons = JSON.stringify(info.reasons.slice(0, 5));
    a.removeAttribute('href');
    a.removeAttribute('data-saferedirecturl');
    a.setAttribute('title', 'Disabled by IOC Triage — dangerous link');
    a.setAttribute('aria-disabled', 'true');
    a.style.cssText += ';text-decoration:line-through !important;color:#b42318 !important;cursor:not-allowed !important;';
  }

  function markSuspicious(a, info) {
    a.dataset.vsWarn = '1';
    a.dataset.vsReal = info.real;
    a.dataset.vsReasons = JSON.stringify(info.reasons.slice(0, 5));
    a.style.cssText += ';outline:2px dashed #f5a524 !important;outline-offset:1px;';
    a.setAttribute('title', 'IOC Triage: suspicious link — you will be asked before it opens');
  }

  // Intercept before the webmail app's own handlers (window capture runs first).
  function onLinkEvent(e) {
    const a = e.target instanceof Element && e.target.closest('a[data-vs-blocked], a[data-vs-warn]');
    if (!a) return;
    e.preventDefault(); e.stopImmediatePropagation();
    if (e.type !== 'click') return;
    const real = a.dataset.vsReal;
    let reasons = [];
    try { reasons = JSON.parse(a.dataset.vsReasons || '[]'); } catch (_) { /* ignore */ }
    const report = { label: 'Report to security', onClick: (close, b) => { UI.send({ type: 'report', kind: 'email', url: real, links: [real] }); b.textContent = 'Reported ✓'; b.disabled = true; } };
    const copy = { label: 'Copy defanged URL', onClick: (close, b) => { navigator.clipboard.writeText(UI.defang(real)).then(() => { b.textContent = 'Copied ✓'; }); } };
    if (a.dataset.vsBlocked) {
      UI.modal({ level: 'block', title: 'This link has been disabled', text: 'IOC Triage blocked this link because it is very likely phishing.', reasons, meta: UI.defang(real),
        actions: [{ label: 'Close', kind: 'primary', onClick: (close) => close() }, report, copy] });
    } else {
      UI.modal({ level: 'warn', title: 'Open this link?', text: 'This link looks suspicious. Only continue if you trust the sender and expected this message.', reasons, meta: UI.defang(real),
        actions: [{ label: 'Don\'t open', kind: 'primary', onClick: (close) => close() }, report,
          { label: 'Open anyway', kind: 'danger', onClick: (close) => { close(); window.open(real, '_blank', 'noopener'); } }] });
    }
  }
  ['click', 'auxclick', 'mousedown', 'mouseup'].forEach((t) => window.addEventListener(t, onLinkEvent, true));
  window.addEventListener('keydown', (e) => { if (e.key === 'Enter') onLinkEvent(e); }, true);

  // ---------------------------------------------------------------- scan ---

  async function scanBody(body) {
    done.add(body);
    const { email, anchors } = extract(body);
    if (!email.links.length && !email.senderEmail && email.text.length < 40) return;
    const r = await UI.send({ type: 'scanEmail', email });
    if (!r || !body.isConnected) return;

    let disabled = 0, warned = 0;
    r.links.forEach((info, i) => {
      const a = anchors[i];
      if (!a || info.allow) return;
      if (info.level === 'block' || (r.level === 'block' && info.score >= 15)) { disableLink(a, info); disabled++; }
      else if (info.level === 'warn' || (r.level === 'block')) { markSuspicious(a, info); warned++; }
    });

    if (r.level !== 'warn' && r.level !== 'block') return;
    const linkNote = disabled ? `${disabled} dangerous link${disabled > 1 ? 's were' : ' was'} disabled.` : warned ? 'Links will ask before opening.' : '';
    const banner = UI.inline({
      level: r.level,
      title: r.level === 'block' ? 'Phishing email — do not interact' : 'This email looks suspicious',
      text: (r.level === 'block' ? 'Do not reply, open attachments or enter any password. ' : 'Check the sender carefully before acting. ') + linkNote,
      reasons: r.reasons,
      actions: [
        { label: 'Report to security', kind: 'primary', onClick: (close, b) => {
          UI.send({ type: 'report', kind: 'email', email: { sender: email.senderEmail, senderName: email.senderName, subject: email.subject, client: CLIENT },
            links: r.links.filter((l) => !l.allow).map((l) => l.real) }).then((res) => { b.textContent = res && res.sentToSoc ? 'Reported to SOC ✓' : 'Logged ✓'; b.disabled = true; });
        } },
        { label: 'Dismiss', kind: 'danger', onClick: (close) => close() }
      ]
    });
    body.parentNode.insertBefore(banner, body);
  }

  let timer = null;
  function schedule() {
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      bodies().forEach((b) => { if (!done.has(b)) scanBody(b); });
    }, 350);
  }
  const mo = new MutationObserver(schedule);
  const boot = () => { mo.observe(document.body, { childList: true, subtree: true }); schedule(); };
  if (document.body) boot(); else document.addEventListener('DOMContentLoaded', boot, { once: true });
})();
