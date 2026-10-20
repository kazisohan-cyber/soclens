(async function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const LABEL = { block: 'Dangerous', warn: 'Suspicious', caution: 'Low trust', safe: 'No threats found' };

  $('opts').addEventListener('click', (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); });
  $('analyst').addEventListener('click', () => {
    // Must run inside the click (user gesture); fall back to a tab where the side panel API is missing.
    chrome.windows.getCurrent((w) => {
      const done = () => window.close();
      if (chrome.sidePanel && chrome.sidePanel.open) chrome.sidePanel.open({ windowId: w.id }).then(done, () => chrome.tabs.create({ url: chrome.runtime.getURL('pages/analyst.html') }, done));
      else chrome.tabs.create({ url: chrome.runtime.getURL('pages/analyst.html') }, done);
    });
  });

  const vstate = await chrome.runtime.sendMessage({ type: 'verifyState' });
  if (window.VSVerifyUI && vstate && vstate.pending && vstate.pending.length) {
    $('verifyBox').hidden = false;
    await window.VSVerifyUI.render($('verifyList'), () => { $('verifyBox').hidden = true; });
  }

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const s = await chrome.runtime.sendMessage({ type: 'popupState', tabId: tab ? tab.id : null });
  if (!s) return;

  const v = s.verdict;
  if (v && v.host) {
    const lvl = v.allow ? 'safe' : v.level;
    $('lvl').textContent = v.bypassed ? 'Bypassed' : (v.allow ? 'Trusted' : LABEL[lvl] || lvl);
    $('lvl').className = 'pill lvl-' + lvl;
    $('host').textContent = v.host;
    for (const r of (v.reasons || []).slice(0, 6)) { const li = document.createElement('li'); li.textContent = r; $('reasons').appendChild(li); }
    $('siteActions').hidden = false;
    $('trust').hidden = !s.allowBypass || v.allow || lvl === 'safe';
  } else {
    $('lvl').textContent = 'Idle';
    $('lvl').className = 'pill lvl-safe';
  }

  $('report').addEventListener('click', async (e) => {
    e.currentTarget.disabled = true;
    const r = await chrome.runtime.sendMessage({ type: 'report', kind: 'site', url: s.url });
    e.currentTarget.textContent = r && r.sentToSoc ? 'Reported ✓' : 'Logged on this device ✓';
  });
  $('trust').addEventListener('click', async (e) => {
    if (!confirm(`Always trust ${v.host}? SOCLens will stop checking it.`)) return;
    const r = await chrome.runtime.sendMessage({ type: 'trustSite', url: s.url });
    if (r && r.ok) { e.currentTarget.textContent = 'Trusted ✓'; e.currentTarget.disabled = true; }
  });

  const { analyst = {} } = await chrome.storage.local.get('analyst');
  renderProtection(s, vstate, analyst);
  if (s.mode !== 'managed' && !s.revoked && (s.mode === 'community' || s.communityAvailable)) {
    $('communityActions').hidden = false;
    if (s.mode === 'community') {
      $('toggleShare').textContent = s.reporting === 'off' ? 'Start sharing reports' : 'Stop sharing reports';
      $('toggleShare').addEventListener('click', async (e) => {
        e.currentTarget.disabled = true;
        await chrome.runtime.sendMessage({ type: 'setConsent', reporting: s.reporting === 'off' ? 'full' : 'off' });
        location.reload();
      });
    } else {
      $('toggleShare').hidden = true;
      $('connect').hidden = false;
      $('connect').addEventListener('click', () => chrome.tabs.create({ url: chrome.runtime.getURL('pages/welcome.html') }));
    }
  }
  $('ver').textContent = 'v' + s.version;

  renderActivity(s);
})();

// ------------------------------------------------------------ protection card ---
// Every row says its state in words, shows a colour, and when something is off says how to fix it.
function openAnalystPanel() {
  chrome.windows.getCurrent((w) => {
    const done = () => window.close();
    if (chrome.sidePanel && chrome.sidePanel.open) chrome.sidePanel.open({ windowId: w.id }).then(done, () => chrome.tabs.create({ url: chrome.runtime.getURL('pages/analyst.html') }, done));
    else chrome.tabs.create({ url: chrome.runtime.getURL('pages/analyst.html') }, done);
  });
}

function ago(ts) {
  if (!ts) return '';
  const m = Math.round((Date.now() - ts) / 60e3);
  return m < 1 ? 'just now' : m < 60 ? m + ' min ago' : m < 48 * 60 ? Math.round(m / 60) + ' h ago' : Math.round(m / 1440) + ' days ago';
}

function protectionRows(s, vstate, analyst) {
  const rows = [];
  const H = 3600e3;
  const connected = s.mode === 'managed' || s.mode === 'community';
  rows.push(s.pageScanner === false
    ? { label: 'Phishing site blocking', value: 'Off', state: 'warn', hint: 'Turned off in Settings: fake login pages will not be blocked.', action: ['Settings', () => chrome.runtime.openOptionsPage()] }
    : { label: 'Phishing site blocking', value: 'On', state: 'ok' });
  rows.push(s.webmailScanner === false
    ? { label: 'Email scanner', value: 'Off', state: 'off', hint: 'Gmail / Outlook web emails are not checked.' }
    : { label: 'Email scanner', value: 'On', state: 'ok', hint: 'Gmail and Outlook on the web' });
  if (!s.credentialGuard) rows.push({ label: 'Credential guard', value: 'Off', state: 'off' });
  else if (s.enrolled) rows.push({ label: 'Credential guard', value: 'Active', state: 'ok', hint: s.credLearned ? `Protecting the password you use at ${s.credLearned.host}` : '' });
  else {
    const where = s.loginDomain || 'login.microsoftonline.com';
    rows.push({ label: 'Credential guard', value: 'Not active yet', state: 'warn', issue: 'Credential guard is not active yet',
      hint: `Sign in once at ${where} so SOCLens can stop your work password being typed on fake sites.`,
      action: ['Activate', () => chrome.tabs.create({ url: 'https://' + where + '/' })] });
  }
  if (s.blocklistSize) {
    const stale = s.blocklistAt && Date.now() - s.blocklistAt > 6 * H;
    rows.push({ label: 'Threat feed', value: s.blocklistSize.toLocaleString() + ' sites', state: stale ? 'warn' : 'ok', issue: stale ? 'Threat feed is out of date' : '',
      hint: stale ? `Last updated ${ago(s.blocklistAt)}: check the connection to your SOC console.` : `Updated ${ago(s.blocklistAt)}` });
  } else {
    rows.push({ label: 'Threat feed', value: connected ? 'Waiting' : 'Built-in only', state: connected ? 'warn' : 'off',
      hint: connected ? 'No feed received yet from your console.' : 'Look-alike and fake-login detection run on this device. A SOCLens console adds a live phishing feed.' });
  }
  if (s.revoked) rows.push({ label: 'Connection', value: 'Disconnected', state: 'bad', issue: 'This browser was disconnected by an admin', hint: 'Your admin revoked this browser. Protection on the device still works.' });
  else if (s.mode === 'managed') rows.push({ label: 'Connection', value: 'Your SOC', state: 'ok', hint: s.reporting === 'off' ? 'Reports are not shared' : 'Blocks and reports go to your security team' });
  else if (s.mode === 'community') rows.push({ label: 'Connection', value: 'Community', state: 'ok', hint: s.reporting === 'off' ? 'Protection only, reports not shared' : 'Sharing anonymous reports with the SOCLens community' });
  else rows.push({ label: 'Connection', value: 'This device only', state: 'off', hint: 'Everything runs locally. Nothing is sent anywhere.' });
  if (vstate && vstate.enabled) rows.push({ label: 'Sign-in verification', value: vstate.lastHeartbeat ? 'On' : 'Starting…', state: vstate.lastHeartbeat ? 'ok' : 'warn',
    hint: vstate.lastHeartbeat ? `Your SOC can ask "was this you?" here · checked ${ago(vstate.lastHeartbeat)}` : 'Waiting for the first check-in with your SOC' });
  if (s.queue > 0) {
    const stuck = s.oldestQueued && Date.now() - s.oldestQueued > H;
    rows.push({ label: 'Reports waiting', value: String(s.queue), state: stuck ? 'warn' : 'off', issue: stuck ? 'Reports are not reaching your SOC' : '',
      hint: stuck ? `The oldest has been waiting ${ago(s.oldestQueued).replace(' ago', '')}: the console may be unreachable.` : 'Sending shortly' });
  }
  const keys = Object.values((analyst && analyst.keys) || {}).filter(Boolean).length;
  rows.push({ label: 'Analyst intel', value: (analyst.publicSources === false ? 'Local' : '8 free') + (keys ? ` + ${keys} key${keys > 1 ? 's' : ''}` : ''), state: keys ? 'ok' : 'off',
    hint: keys ? 'Right-click any IP, domain, URL or hash → Investigate' : 'Add free VirusTotal / AbuseIPDB keys for known-bad verdicts',
    action: keys ? null : ['Add keys', openAnalystPanel] });
  return rows;
}

function renderProtection(s, vstate, analyst) {
  const el = (tag, cls, text) => { const x = document.createElement(tag); if (cls) x.className = cls; if (text != null) x.textContent = text; return x; };
  const rows = protectionRows(s, vstate, analyst);
  const box = document.getElementById('prot');
  box.textContent = '';
  for (const r of rows) {
    const d = el('div', 'stat');
    d.append(el('span', '', r.label), el('span', 'v ' + r.state, r.value));
    if (r.hint || r.action) {
      const h = el('div', 'hint', r.hint || '');
      if (r.action) { const b = el('button', '', r.action[0]); b.addEventListener('click', r.action[1]); h.append(b); }
      d.append(h);
    }
    box.append(d);
  }
  const issues = rows.filter((r) => r.issue);
  const bad = rows.some((r) => r.state === 'bad');
  const health = document.getElementById('health');
  health.className = 'health' + (bad ? ' bad' : issues.length ? ' warn' : '');
  const active = rows.filter((r) => r.state === 'ok').length;
  document.getElementById('healthText').textContent = issues.length
    ? (issues.length === 1 ? '1 thing needs attention' : `${issues.length} things need attention`)
    : '✓ You\'re protected';
  document.getElementById('healthSub').textContent = issues.length ? issues.map((r) => r.issue).join(' · ') : `${active} protections active`;
}

// ------------------------------------------------------------ recent activity ---
function renderActivity(s) {
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => { const x = document.createElement(tag); if (cls) x.className = cls; if (text != null) x.textContent = text; return x; };
  const box = $('events');
  const items = window.VSActivity.build(s.events, { max: 6 });
  $('empty').hidden = items.length > 0;
  const shared = s.soc && s.reporting !== 'off';
  for (const it of items) {
    const d = el('details', 'ev sev-' + it.severity);
    const sum = el('summary');
    sum.append(el('span', 'dot'), el('span', 't', it.title + (it.count > 1 ? `  ×${it.count}` : '')), el('span', 'when', window.VSActivity.when(it.ts)));
    const sub = el('div', 'sub');
    if (it.site) sub.append(el('b', '', it.site));
    if (it.posing) sub.append(document.createTextNode(` pretending to be ${it.posing}`));
    if (it.why) sub.append(document.createTextNode((it.site ? ' · ' : '') + it.why));
    sum.append(sub);
    const tags = el('div', 'why');
    if (it.bypassed) tags.append(el('span', 'tag bad', 'You continued anyway'));
    if (shared && /blocked|warned|detected|reuse|report|bypass/.test(it.type)) tags.append(el('span', 'tag', 'Sent to your SOC'));
    if (tags.children.length) sum.append(tags);
    d.append(sum);

    const more = el('div', 'more');
    if (it.reasons.length > 1) { const ul = el('ul'); it.reasons.slice(0, 6).forEach((r) => ul.append(el('li', '', r))); more.append(ul); }
    if (it.urlDefanged || it.url) more.append(el('div', 'mono', it.urlDefanged || it.url));
    if (it.count > 1) more.append(el('div', 'mono', `${it.count} times since ${new Date(it.firstTs).toLocaleString()}`));
    if (it.canInvestigate) {
      const b = el('button', '', 'Investigate');
      b.addEventListener('click', () => {
        chrome.storage.session.set({ analystQuery: { value: it.url || it.host || it.site, t: Date.now() } });
        chrome.windows.getCurrent((w) => {
          const done = () => window.close();
          if (chrome.sidePanel && chrome.sidePanel.open) chrome.sidePanel.open({ windowId: w.id }).then(done, () => chrome.tabs.create({ url: chrome.runtime.getURL('pages/analyst.html') }, done));
          else chrome.tabs.create({ url: chrome.runtime.getURL('pages/analyst.html') }, done);
        });
      });
      more.append(b);
    }
    if (it.canTrust && s.allowBypass) {
      const b = el('button', '', 'Not phishing? Trust this site');
      b.addEventListener('click', async () => {
        if (!confirm(`Always trust ${it.host}? SOCLens will stop checking it${shared ? ' and your SOC will see this decision' : ''}.`)) return;
        const r = await chrome.runtime.sendMessage({ type: 'trustSite', url: it.url });
        b.textContent = r && r.ok ? 'Trusted ✓' : 'Not allowed by your organisation';
        b.disabled = true;
      });
      more.append(b);
    }
    d.append(more);
    box.appendChild(d);
  }
}
