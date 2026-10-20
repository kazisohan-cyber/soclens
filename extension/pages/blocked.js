(async function () {
  'use strict';
  let d = {};
  try { d = JSON.parse(decodeURIComponent(location.hash.slice(1))); } catch (_) { /* empty */ }
  const $ = (id) => document.getElementById(id);
  const defang = (u) => String(u || '').replace(/^http/i, 'hxxp').replace(/\./g, '[.]');

  $('url').textContent = defang(d.url || '');
  $('score').textContent = d.score != null ? `Risk score ${d.score}/100` : '';
  if (d.brand) $('title').textContent = `Fake ${d.brand} site blocked`;
  if (d.kind === 'page') $('lead').textContent = 'This page is asking for your details while pretending to be something it is not.';
  for (const r of d.reasons || []) { const li = document.createElement('li'); li.textContent = r; $('reasons').appendChild(li); }

  $('back').addEventListener('click', () => {
    // A page-level block sits on top of the phishing page's own history entry, so skip over it.
    const steps = d.kind === 'page' ? 2 : 1;
    if (history.length > steps) history.go(-steps); else location.replace('about:blank');
  });

  $('report').addEventListener('click', async (e) => {
    const b = e.currentTarget;
    b.disabled = true;
    const r = await chrome.runtime.sendMessage({ type: 'report', kind: 'site', url: d.url, note: 'false_positive_from_block_page' });
    b.textContent = r && r.sentToSoc ? 'Sent to your security team ✓' : 'Logged ✓';
  });

  const cfg = await VSConfig.get();
  if (cfg.allowUserBypass && d.url) {
    $('proceed').hidden = false;
    $('proceed').addEventListener('click', async () => {
      if (!confirm('This site is very likely phishing. Your security team will be notified that you continued. Continue?')) return;
      const r = await chrome.runtime.sendMessage({ type: 'bypass', url: d.url, reasons: d.reasons });
      if (r && r.ok) location.replace(d.url);
    });
  }
})();
