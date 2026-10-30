/*
 * IOC Triage recent activity: turns the raw event log into items a person understands.
 * Merges a block with the bypass that followed it, collapses repeats, explains what happened and
 * why, and names the real domain behind look-alike hosts. Pure functions (popup + tests).
 */
(function (root) {
  'use strict';
  const A = root.VSAnalyzer;

  const SEV = { critical: 4, high: 3, medium: 2, low: 1 };
  const MERGE_MS = 15 * 60e3;     // a bypass within 15 min belongs to the block before it
  const REPEAT_MS = 24 * 3600e3;  // same thing on the same site within a day = one item

  function realDomain(host) {
    if (!host) return '';
    return A ? A.registrableDomain(host) : host.split('.').slice(-2).join('.');
  }

  function describe(ev) {
    const host = ev.host || '';
    const dom = realDomain(host);
    const posing = host && dom && host !== dom && host.length > dom.length + 1 && /\.(com|net|org|microsoft|google|apple)\./i.test(host)
      ? host.slice(0, host.length - dom.length - 1) : '';
    const why = (ev.reasons || [])[0] || '';
    const b = ev.brand || '';
    const mail = ev.email || {};
    switch (ev.type) {
      case 'url_blocked': return { title: b ? `Blocked a fake ${b} site` : 'Blocked a dangerous site', site: dom || host, posing, why };
      case 'page_blocked': return { title: b ? `Blocked a fake ${b} login page` : 'Blocked a fake login page', site: dom || host, posing, why };
      case 'page_warned': return { title: b ? `Warned: page may imitate ${b}` : 'Warned: suspicious page', site: dom || host, posing, why };
      case 'credential_reuse_blocked': return { title: 'Stopped your work password leaking', site: dom || host, posing, why: why || 'Your work password was typed on a site outside your organisation' };
      case 'phishing_email_detected': return { title: 'Flagged a phishing email', site: mail.sender || '', why: mail.subject ? `“${mail.subject}”` + (why ? ' · ' + why : '') : why };
      case 'device_code_warning': return { title: 'Warned about a device-code sign-in', site: dom || host, why };
      case 'user_report_site': return { title: 'You reported a site', site: dom || host, why: ev.note || '' };
      case 'user_report_email': return { title: 'You reported an email', site: mail.sender || '', why: mail.subject ? `“${mail.subject}”` : '' };
      case 'user_trusted_site': return { title: 'You marked a site as trusted', site: dom || host, why: '' };
      case 'user_bypass': return { title: 'You continued past a warning', site: dom || host, posing, why };
      case 'verify_answer': return { title: 'You answered a sign-in check', site: '', why: ev.answer === 'no' ? '“No, not me”' : '“Yes, it was me”' };
      default: return { title: String(ev.type || 'Event').replace(/_/g, ' '), site: dom || host, why };
    }
  }

  /** events: newest first (as stored). Returns grouped items, newest first. */
  function build(events, opts) {
    const max = (opts && opts.max) || 8;
    const list = (events || []).filter((e) => e && e.ts).slice().sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts));
    const items = [];
    const bypassUsed = new Set();
    // Pair each bypass with the block / warning just before it on the same host.
    for (let i = 0; i < list.length; i++) {
      const ev = list[i];
      if (ev.type !== 'user_bypass') continue;
      const t = Date.parse(ev.ts);
      const block = list.find((x) => (x.type === 'url_blocked' || x.type === 'page_blocked' || x.type === 'page_warned') && x.host === ev.host
        && Date.parse(x.ts) <= t && t - Date.parse(x.ts) < MERGE_MS);
      if (block) { block._bypassed = true; bypassUsed.add(ev); }
    }
    for (const ev of list) {
      if (bypassUsed.has(ev)) continue;
      const t = Date.parse(ev.ts);
      const key = ev.type + '|' + (ev.host || (ev.email && ev.email.sender) || '') + '|' + (ev._bypassed ? 'b' : '');
      const prev = items.find((it) => it.key === key && it.firstTs - t < REPEAT_MS);
      if (prev) { prev.count++; prev.firstTs = Math.min(prev.firstTs, t); for (const r of ev.reasons || []) if (!prev.reasons.includes(r)) prev.reasons.push(r); continue; }
      const d = describe(ev);
      items.push(Object.assign(d, {
        key, type: ev.type, severity: ev.severity || 'low', ts: t, firstTs: t, count: 1, bypassed: !!ev._bypassed,
        host: ev.host || '', url: ev.url || '', urlDefanged: ev.urlDefanged || '', reasons: (ev.reasons || []).slice(), score: ev.score,
        canTrust: ['page_warned', 'page_blocked', 'url_blocked'].includes(ev.type) && !!ev.url,
        canInvestigate: !!(ev.url || ev.host || (ev.email && ev.email.sender))
      }));
      if (items.length >= max) break;
    }
    return items;
  }

  function when(ts, now) {
    now = now || Date.now();
    const s = Math.round((now - ts) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return Math.round(s / 60) + ' min ago';
    const d = new Date(ts), n = new Date(now);
    const hm = d.toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
    if (d.toDateString() === n.toDateString()) return s < 6 * 3600 ? Math.round(s / 3600) + ' h ago' : 'Today ' + hm;
    const y = new Date(now - 864e5);
    if (d.toDateString() === y.toDateString()) return 'Yesterday ' + hm;
    return d.toLocaleDateString([], { day: 'numeric', month: 'short' }) + ' ' + hm;
  }

  const api = { build, describe, when, realDomain, SEV };
  root.VSActivity = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
