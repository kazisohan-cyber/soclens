/* SOCLens analyst panel: investigate IOCs, ticket notes, email headers, client memory, settings. */
(function () {
  'use strict';
  const I = window.VSIoc, E = window.VSEngine, HD = window.VSHeaders;
  const $ = (id) => document.getElementById(id);
  const send = (msg) => chrome.runtime.sendMessage(msg);
  const MAX_IOCS = 25;
  let settings = null;
  let current = [];          // [{ report, a }] in display order
  let aiText = '';
  let editingId = null;
  let ctxNotes = [];      // remembered accounts / hostnames found in the pasted text

  // Tiny DOM builder: every string becomes text, never HTML (lookup data is untrusted).
  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : v);
    }
    for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    return el;
  }
  const pill = (v, extra) => h('span', { class: 'pill v-' + v, text: (extra || v).toUpperCase() });
  const SRC = E.SOURCE_NAMES;

  // ------------------------------------------------------------------ tabs ---
  function showTab(name) {
    document.querySelectorAll('[role=tab]').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.tab === name)));
    document.querySelectorAll('section.tab').forEach((s) => { s.hidden = s.id !== 'tab-' + name; });
    if (name === 'memory') loadMemory();
  }
  document.querySelectorAll('[role=tab]').forEach((b) => b.addEventListener('click', () => showTab(b.dataset.tab)));
  document.addEventListener('click', (e) => { const g = e.target.closest('[data-goto]'); if (g) showTab(g.dataset.goto); });

  // -------------------------------------------------------------- settings ---
  async function loadSettings() {
    settings = await send({ type: 'analystSettings' });
    const keys = settings.keys || {};
    document.querySelectorAll('[data-key]').forEach((f) => { f.value = keys[f.dataset.key] || ''; });
    $('sPublic').checked = !!settings.publicSources;
    $('sHighlight').checked = !!settings.highlight;
    $('sAi').checked = !!settings.ai;
    $('sSites').value = (settings.highlightSites || []).join('\n');
    $('sName').value = settings.analyst || '';
    const nKeys = Object.values(keys).filter(Boolean).length;
    $('srcCount').textContent = (settings.publicSources ? '8 free sources' : 'local only') + (nKeys ? ` + ${nKeys} key${nKeys > 1 ? 's' : ''}` : '');
    renderWizard();
    aiAvailability().then((s) => { $('aiState').textContent = s; });
  }

  // ------------------------------------------------- key setup (wizard + Settings) ---
  const PROVIDERS = {
    vt: { name: 'VirusTotal', signup: 'https://www.virustotal.com/gui/join-us', unlocks: 'File hash, IP, domain and URL verdicts from 70+ security vendors, with the malware family name.' },
    abuseipdb: { name: 'AbuseIPDB', signup: 'https://www.abuseipdb.com/register', unlocks: 'IP abuse score, number of reports, network type and Tor exits. Best for sign-in and firewall alerts.' },
    abusech: { name: 'abuse.ch', signup: 'https://auth.abuse.ch/', unlocks: 'Known malware URLs, C2 servers and malware samples (URLhaus, ThreatFox, MalwareBazaar).' },
    urlscan: { name: 'urlscan.io', signup: 'https://urlscan.io/user/signup', unlocks: '"Detonate safely": a screenshot of a link without opening it in your browser.' },
    greynoise: { name: 'GreyNoise', signup: 'https://viz.greynoise.io/signup', unlocks: 'Higher daily limit for internet-scanner checks (works without a key too).' }
  };

  /** Paste box + Test button + result line. onOk(key, message) runs after a successful test. */
  function keyRow(provider, input, onOk) {
    const status = h('div', { class: 'keystat' });
    const btn = h('button', { text: onOk ? 'Test & save' : 'Test', onclick: async () => {
      btn.disabled = true;
      status.className = 'keystat';
      status.textContent = 'Testing…';
      const r = await send({ type: 'testKey', provider, key: input.value });
      btn.disabled = false;
      status.className = 'keystat ' + (r && r.ok ? 'ok' : 'bad');
      status.textContent = (r && r.ok ? '✓ ' : '✗ ') + ((r && r.message) || 'Test failed');
      if (r && r.ok && onOk) onOk(input.value.trim(), r.message);
    } });
    return { row: h('div', { class: 'keyrow' }, input, btn), status };
  }

  function renderWizard() {
    const box = $('wizard');
    const keys = settings.keys || {};
    const core = ['vt', 'abuseipdb'];
    if (settings.wizardDone) { box.hidden = true; return; }
    box.hidden = false;
    box.textContent = '';
    const allSet = core.every((p) => keys[p]);
    box.append(h('h3', { text: allSet ? 'All set ✓' : 'Unlock full reputation in 2 minutes (free)' }),
      h('p', { class: 'muted small', style: 'margin:0 0 6px', text: allSet
        ? 'SOCLens now gives known-bad verdicts for IPs, domains, URLs and hashes. More sources (abuse.ch, urlscan) are in Settings.'
        : 'SOCLens already works with 8 free sources. Two free keys add "known bad" verdicts. Keys stay in this browser.' }));
    core.forEach((p, i) => {
      const P = PROVIDERS[p];
      const step = h('div', { class: 'step' }, h('b', { text: `${i + 1}. ${P.name}` }), h('div', { class: 'unlocks', text: P.unlocks }));
      if (keys[p]) step.append(h('div', { class: 'done-line', text: '✓ Connected' }));
      else {
        const input = h('input', { type: 'password', autocomplete: 'off', placeholder: 'Paste your ' + P.name + ' API key' });
        const k = keyRow(p, input, async (key) => {
          await send({ type: 'analystSave', patch: { keys: { [p]: key } } });
          setTimeout(loadSettings, 900);
        });
        step.append(h('div', { class: 'small', style: 'margin-bottom:4px' }, 'Sign up free, then copy the API key from your profile: ',
          h('a', { href: P.signup, target: '_blank', rel: 'noopener', text: 'open ' + P.name })), k.row, k.status);
      }
      box.append(step);
    });
    box.append(h('div', { class: 'row between', style: 'margin-top:6px' },
      h('button', { class: 'link', 'data-goto': 'settings', text: 'More sources' }),
      h('button', { class: allSet ? 'primary' : 'link', text: allSet ? 'Done' : 'Skip for now', onclick: async () => {
        await send({ type: 'analystSave', patch: { wizardDone: true } });
        loadSettings();
      } })));
  }

  // Settings tab: a Test button and an "unlocks" line under every key field.
  document.querySelectorAll('[data-key]').forEach((input) => {
    const p = input.dataset.key;
    const label = input.closest('label');
    const k = keyRow(p, input, null);
    label.after(h('div', { class: 'unlocks muted small', text: PROVIDERS[p].unlocks }), k.row, k.status);
    k.row.prepend(input);
  });
  $('wizardAgain').addEventListener('click', async () => {
    await send({ type: 'analystSave', patch: { wizardDone: false } });
    await loadSettings();
    showTab('investigate');
  });
  $('sSave').addEventListener('click', async () => {
    const keys = {};
    document.querySelectorAll('[data-key]').forEach((f) => { keys[f.dataset.key] = f.value.trim(); });
    await send({ type: 'analystSave', patch: { keys, publicSources: $('sPublic').checked, highlight: $('sHighlight').checked, ai: $('sAi').checked,
      highlightSites: $('sSites').value.split(/\s+/).filter(Boolean), analyst: $('sName').value.trim().slice(0, 60) } });
    $('sState').textContent = 'Saved ✓';
    setTimeout(() => { $('sState').textContent = ''; }, 2500);
    loadSettings();
  });

  // ----------------------------------------------------------- investigate ---
  $('q').addEventListener('input', () => {
    const n = I.unique($('q').value).length;
    const vtNote = n > 4 && settings && settings.keys && settings.keys.vt
      ? ` · VirusTotal free tier checks 4/min, the rest fill in automatically (~${Math.ceil((Math.min(n, MAX_IOCS) - 4) / 4)} min)` : '';
    $('found').textContent = n ? `${n} indicator${n > 1 ? 's' : ''} found${n > MAX_IOCS ? ` (first ${MAX_IOCS} checked)` : ''}${vtNote} · Ctrl+Enter` : 'Ctrl+Enter to investigate';
  });
  $('q').addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) run(); });
  $('go').addEventListener('click', () => run());

  async function run(text) {
    if (text != null) { $('q').value = text; $('q').dispatchEvent(new Event('input')); }
    showTab('investigate');
    let iocs = I.unique($('q').value);
    if (!iocs.length) {
      const c = I.classify($('q').value);
      if (c.type !== 'unknown') iocs = [Object.assign({ raw: c.value }, c)];
    }
    const box = $('results');
    box.textContent = '';
    current = [];
    aiText = '';
    $('overall').hidden = true;
    if (!iocs.length) { box.append(h('p', { class: 'muted', text: 'No IP, domain, URL, hash, email or CVE found in that text.' })); return; }
    iocs = iocs.slice(0, MAX_IOCS);
    $('go').disabled = true;
    const slots = iocs.map((x) => {
      const card = h('div', { class: 'card ioc' }, h('div', { class: 'head' },
        h('span', { class: 'val', text: I.defang(x.value, x.type) }), h('span', { class: 'chip', text: I.LABEL_OF[x.type] }),
        h('span', { class: 'pill v-checking' }, h('span', { class: 'spin' }), ' checking')));
      box.append(card);
      return card;
    });
    let next = 0;
    const results = new Array(iocs.length);
    async function worker() {
      while (next < iocs.length) {
        const i = next++;
        let r;
        try { r = await send({ type: 'investigate', value: iocs[i].value }); } catch (e) { r = { error: String(e.message || e) }; }
        results[i] = r;
        renderCard(slots[i], r, iocs[i]);
      }
    }
    await Promise.all([worker(), worker(), worker(), worker()]);
    $('go').disabled = false;
    current = results.filter((r) => r && r.report);
    try { ctxNotes = (await send({ type: 'memoryContext', text: $('q').value })) || []; } catch (_) { ctxNotes = []; }
    renderOverall();
    renderClientContext();
  }

  function sourceChip(key, s) {
    const name = SRC[key] || key;
    const label = s.status === 'ok' ? name + (s.cached ? ' ✓ (cached)' : s.waited ? ` ✓ (queued ${s.waited}s)` : ' ✓') : s.status === 'notfound' ? name + ': not seen'
      : s.status === 'nokey' ? name + ': add key' : s.status === 'ratelimited' ? name + ': rate limit' : s.status === 'skipped' ? name + ': off' : name + ': ' + (s.error || 'error');
    const cls = 'chip ' + (s.status === 'ok' ? 'ok' : s.status === 'notfound' ? '' : 'off');
    return s.link ? h('a', { class: cls, href: s.link, target: '_blank', rel: 'noopener', title: 'Open in ' + name, text: label }) : h('span', { class: cls, text: label });
  }

  function pivots(report) {
    const v = report.value, g = report.group;
    const dom = I.domainOf(report.type, v);
    const L = [];
    if (g === 'ip') L.push(['AbuseIPDB', 'https://www.abuseipdb.com/check/' + v], ['Shodan', 'https://www.shodan.io/host/' + v], ['Censys', 'https://search.censys.io/hosts/' + v], ['urlscan', 'https://urlscan.io/search/#ip:%22' + v + '%22']);
    if (dom) L.push(['urlscan', 'https://urlscan.io/search/#domain:' + dom], ['crt.sh', 'https://crt.sh/?q=' + encodeURIComponent(dom)], ['WHOIS', 'https://who.is/whois/' + dom]);
    if (g === 'hash') L.push(['MalwareBazaar', 'https://bazaar.abuse.ch/browse.php?search=' + encodeURIComponent(v)], ['Hybrid Analysis', 'https://www.hybrid-analysis.com/search?query=' + v]);
    if (g === 'cve') L.push(['NVD', 'https://nvd.nist.gov/vuln/detail/' + v], ['CISA KEV', 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=' + v], ['GitHub PoCs', 'https://github.com/search?type=repositories&q=' + v]);
    return L;
  }

  function renderCard(card, r, ioc) {
    card.textContent = '';
    if (!r || r.error || !r.report) {
      card.append(h('div', { class: 'head' }, h('span', { class: 'val', text: I.defang(ioc.value, ioc.type) }), pill('unknown', 'error')),
        h('p', { class: 'muted small', text: (r && r.error) || 'Lookup failed' }));
      return;
    }
    const { report, a } = r;
    const conf = report.group === 'cve' ? 'Patch priority' : 'confidence ' + a.confidence;
    card.append(h('div', { class: 'head' }, h('span', { class: 'val', text: I.defang(report.value, report.type) }),
      h('span', { class: 'chip', text: I.LABEL_OF[report.type] }), pill(a.verdict)));
    card.append(h('div', { class: 'muted small', text: conf }));
    card.append(h('p', { class: 'sum', text: a.summary }));
    const ranked = a.reasons.slice().sort((x, y) => ({ bad: 0, good: 1, info: 2 }[x.kind] - { bad: 0, good: 1, info: 2 }[y.kind]));
    const li = (r0) => h('li', { class: r0.kind }, r0.t, r0.src ? h('span', { class: 'src', text: ' · ' + (SRC[r0.src] || r0.src) }) : null);
    card.append(h('ul', { class: 'why' }, ranked.slice(0, 7).map(li)));
    if (ranked.length > 7) card.append(h('details', {}, h('summary', { text: `${ranked.length - 7} more finding(s)` }), h('ul', { class: 'why' }, ranked.slice(7).map(li))));
    if (a.actions.length) card.append(h('details', { open: a.verdict === 'malicious' || a.verdict === 'critical' || a.verdict === 'suspicious' },
      h('summary', { text: 'What to do next' }), h('ol', { class: 'next' }, a.actions.map((x) => h('li', { text: x })))));
    const chips = h('div', { class: 'small', style: 'margin-top:6px' });
    for (const [k, s] of Object.entries(report.sources || {})) chips.append(sourceChip(k, s));
    if (report.local && report.local.analyzer) chips.append(h('span', { class: 'chip ok', text: SRC.local + ' ✓' }));
    card.append(chips);
    const piv = pivots(report);
    if (piv.length) card.append(h('div', { class: 'small' }, h('span', { class: 'muted', text: 'Pivot: ' }), piv.map(([n, u]) => h('a', { class: 'chip', href: u, target: '_blank', rel: 'noopener', text: n }))));
    const det = h('div', { class: 'det' });
    card.append(h('div', { class: 'actions' },
      h('button', { text: 'Copy defanged', onclick: (e) => copyText(I.defang(report.value, report.type), e.target) }),
      h('button', { text: 'Copy', onclick: (e) => copyText(report.value, e.target) }),
      (report.group === 'url' || report.group === 'domain') ? h('button', { text: 'Detonate safely', onclick: (e) => detonate(report.value, det, e.target) }) : null,
      report.group !== 'cve' ? h('button', { text: 'Remember…', onclick: () => prefillMemory(report.value) }) : null), det);
  }

  function renderOverall() {
    if (!current.length) return;
    const ov = E.overall(current.map((x) => ({ a: x.a })));
    $('overall').hidden = false;
    $('ovPill').className = 'pill v-' + ov;
    $('ovPill').textContent = ov.toUpperCase();
    const bad = current.filter((x) => ['malicious', 'suspicious', 'critical', 'high'].includes(x.a.verdict)).length;
    $('ovText').textContent = `${current.length} indicator${current.length > 1 ? 's' : ''}` + (bad ? `, ${bad} need attention` : ', nothing alarming');
    $('ovTime').textContent = new Date().toLocaleTimeString();
    $('copyState').textContent = '';
    aiSummarize();
  }

  function renderClientContext() {
    const box = $('clientCtx');
    box.textContent = '';
    box.hidden = !ctxNotes.length;
    if (!ctxNotes.length) return;
    box.append(h('b', { text: 'Client context from memory' }));
    for (const m of ctxNotes) box.append(h('div', {}, h('span', { class: 'chip' + (m.expired ? ' warn' : ''), text: m.expired ? 'expired' : m.verdict }), ' ', m._desc));
  }

  function noteOpts() {
    const worst = current.slice().sort((x, y) => (E.RANK[y.a.verdict] || 0) - (E.RANK[x.a.verdict] || 0))[0];
    return { context: $('ctx').value.trim(), analyst: settings && settings.analyst, summary: aiText || (worst ? worst.a.summary : ''),
      client: (settings && settings.activeClient) || '', clientContext: ctxNotes.map((m) => m._desc) };
  }
  $('copyNote').addEventListener('click', (e) => {
    const n = E.ticketNote(current, noteOpts());
    copyText(n.text, e.currentTarget, n.html, 'Copied. Paste into the HaloPSA / ticket note (formatting kept).');
  });
  $('copyMd').addEventListener('click', (e) => copyText(E.ticketNote(current, noteOpts()).markdown, e.currentTarget, null, 'Markdown copied.'));
  $('copyIocs').addEventListener('click', (e) => copyText(current.map((x) => `${I.defang(x.report.value, x.report.type)}\t${I.LABEL_OF[x.report.type]}\t${x.a.verdict}`).join('\n'),
    e.currentTarget, null, 'IOC list copied (tab separated).'));

  /**
   * Copy plain text (and optional HTML). The side panel often isn't "focused" for the async Clipboard API,
   * so copy synchronously inside the click first (copy event + execCommand), then fall back to the API,
   * and if both fail show the text selected so Ctrl+C still works. Must be called before any await.
   */
  function copyText(text, btn, html, okMsg) {
    let ok = false;
    const onCopy = (ev) => {
      ev.preventDefault();
      ev.clipboardData.setData('text/plain', text);
      if (html) ev.clipboardData.setData('text/html', html);
      ok = true;
    };
    document.addEventListener('copy', onCopy, true);
    try { document.execCommand('copy'); } catch (_) { /* not allowed */ }
    document.removeEventListener('copy', onCopy, true);
    const done = (success) => {
      if (btn) {
        const old = btn.dataset.label || btn.textContent;
        btn.dataset.label = old;
        btn.textContent = success ? 'Copied ✓' : 'Press Ctrl+C';
        setTimeout(() => { btn.textContent = old; }, 1600);
      }
      if (okMsg || !success) $('copyState').textContent = success ? (okMsg || '') : 'Copy was blocked: the text is selected below, press Ctrl+C.';
      if (!success) showManualCopy(text);
    };
    if (ok) { done(true); return Promise.resolve(true); }
    const p = html && window.ClipboardItem
      ? navigator.clipboard.write([new ClipboardItem({ 'text/html': new Blob([html], { type: 'text/html' }), 'text/plain': new Blob([text], { type: 'text/plain' }) })])
      : navigator.clipboard.writeText(text);
    return p.then(() => { done(true); return true; }, () => { done(false); return false; });
  }

  function showManualCopy(text) {
    let box = $('manualCopy');
    if (!box) {
      box = h('textarea', { id: 'manualCopy', rows: 6, readonly: true, spellcheck: 'false', style: 'margin-top:8px' });
      $('overall').hidden ? $('results').prepend(box) : $('overall').append(box);
    }
    box.value = text;
    box.focus();
    box.select();
  }

  async function detonate(value, box, btn) {
    btn.disabled = true;
    box.textContent = '';
    box.append(h('span', { class: 'spin' }), ' Detonating in urlscan.io (unlisted scan, ~30 s). Your browser never opens the page.');
    const r = await send({ type: 'detonate', value });
    btn.disabled = false;
    box.textContent = '';
    if (!r || r.error) { box.append(h('p', { class: 'muted', text: (r && r.error) || 'Detonation failed' })); return; }
    if (r.status === 'nokey') {
      box.append(h('p', {}, 'Add a free urlscan.io key in ', h('button', { class: 'link', 'data-goto': 'settings', text: 'Settings' }), ' to see a screenshot of the page safely.'));
      if (r.unwrapped) box.append(h('p', { class: 'small' }, 'Real destination after unwrapping: ', h('span', { class: 'mono', text: I.defang(r.unwrapped, 'url') })));
      return;
    }
    if (r.status !== 'ok') { box.append(h('p', {}, (r.error || 'Still processing.') + ' ', r.reportUrl ? h('a', { href: r.reportUrl, target: '_blank', rel: 'noopener', text: 'Open the urlscan report' }) : '')); return; }
    const rows = [['Verdict', r.malicious ? `MALICIOUS (score ${r.score})` : `not flagged (score ${r.score})`], ['Final page', r.finalUrl ? I.defang(r.finalUrl, 'url') : '-'],
      ['Title', r.title || '-'], ['Server', [r.ip, r.country, r.asn].filter(Boolean).join(' · ') || '-'], ['Redirected', r.redirected ? 'yes' : 'no'],
      ['Brands targeted', r.brands.join(', ') || '-'], ['TLS', r.tlsIssuer ? `${r.tlsIssuer}${r.tlsAgeDays != null ? ', cert ' + r.tlsAgeDays + ' days old' : ''}` : '-'], ['Requests', String(r.requests)]];
    box.append(h('table', { class: 'kv' }, rows.map(([k, v]) => h('tr', {}, h('td', { text: k }), h('td', { text: v })))),
      h('img', { src: r.screenshot, alt: 'Screenshot of the scanned page', loading: 'lazy' }),
      h('a', { href: r.reportUrl, target: '_blank', rel: 'noopener', class: 'small', text: 'Full urlscan report' }));
  }

  // ---------------------------------------------------------- on-device AI ---
  function lm() { return self.LanguageModel || (self.ai && self.ai.languageModel) || null; }
  async function aiAvailability() {
    const L = lm();
    if (!L) return 'This browser has no built-in AI model. SOCLens uses its own reasoning instead.';
    try {
      const a = L.availability ? await L.availability() : (await L.capabilities()).available;
      return a === 'available' || a === 'readily' ? 'Built-in AI model ready on this device.'
        : a === 'unavailable' || a === 'no' ? 'This device cannot run the built-in model. SOCLens uses its own reasoning instead.'
          : 'Built-in model can be downloaded by the browser on first use.';
    } catch (_) { return 'Built-in AI not available.'; }
  }
  async function aiSummarize() {
    const box = $('ai');
    box.hidden = true;
    if (!settings || !settings.ai || !current.length) return;
    const L = lm();
    if (!L) return;
    let avail;
    try { avail = L.availability ? await L.availability() : (await L.capabilities()).available; } catch (_) { return; }
    if (avail !== 'available' && avail !== 'readily') return;
    box.hidden = false;
    box.textContent = '';
    box.append(h('span', { class: 'lbl', text: 'On-device AI summary (draft, verify)' }), h('span', { class: 'spin' }));
    const sys = 'You are a senior SOC analyst. Use ONLY the evidence provided. In 2 to 4 short sentences say what the indicators are, '
      + 'the overall assessment, and the single most important next step. Never invent sources, numbers or facts. Plain English.';
    const evidence = current.map((x) => ({ indicator: I.defang(x.report.value, x.report.type), type: I.LABEL_OF[x.report.type], verdict: x.a.verdict,
      confidence: x.a.confidence, findings: x.a.reasons.filter((r) => r.kind !== 'info').slice(0, 6).map((r) => r.t) }));
    try {
      const session = L.availability ? await L.create({ initialPrompts: [{ role: 'system', content: sys }] }) : await L.create({ systemPrompt: sys });
      const out = await Promise.race([session.prompt('Context: ' + ($('ctx').value || 'none') + '\nEvidence: ' + JSON.stringify(evidence)),
        new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 30000))]);
      if (session.destroy) session.destroy();
      aiText = String(out || '').trim().slice(0, 1200);
      box.textContent = '';
      box.append(h('span', { class: 'lbl', text: 'On-device AI summary (draft, verify)' }), aiText);
    } catch (_) { box.hidden = true; }
  }

  // --------------------------------------------------------------- headers ---
  $('hdrGo').addEventListener('click', () => {
    const out = $('hdrOut');
    out.textContent = '';
    const r = HD.analyze($('hdr').value);
    if (!r.ok) { out.append(h('p', { class: 'muted', text: r.error })); return; }
    const s = r.summary;
    const st = (k, v) => h('span', { class: 'chip ' + (v === 'pass' ? 'ok' : /fail/.test(v) ? 'bad' : ''), text: `${k}: ${v || 'n/a'}` });
    const card = h('div', { class: 'card ioc' },
      h('div', { class: 'head' }, h('span', { class: 'val', text: s.subject || '(no subject)' }), pill(r.verdict)),
      h('div', { class: 'auth' }, st('SPF', r.auth.spf), st('DKIM', r.auth.dkim), st('DMARC', r.auth.dmarc), r.auth.compauth ? st('compauth', r.auth.compauth) : null),
      h('table', { class: 'kv' }, [['From', s.from], ['Reply-To', s.replyTo], ['Return-Path', s.returnPath], ['To', s.to], ['Date', s.date],
        ['Originating IP', r.origin], ['Mailer', s.mailer], ['Message-ID', s.messageId]].filter(([, v]) => v).map(([k, v]) => h('tr', {}, h('td', { text: k }), h('td', { text: v })))),
      h('ul', { class: 'why' }, r.reasons.slice().sort((x, y) => ({ bad: 0, good: 1, info: 2 }[x.kind] - { bad: 0, good: 1, info: 2 }[y.kind])).map((x) => h('li', { class: x.kind, text: x.t }))));
    if (r.hops.length) {
      card.append(h('details', {}, h('summary', { text: `Delivery path: ${r.hops.length} hop(s), oldest first` }),
        h('table', { class: 'hops' }, h('tr', {}, ['#', 'From', 'By', 'IP', 'Delay'].map((t) => h('th', { text: t }))),
          r.hops.map((x, i) => h('tr', {}, h('td', { text: String(i + 1) }), h('td', { text: x.from }), h('td', { text: x.by }), h('td', { text: x.ip }),
            h('td', { text: x.delay == null ? '' : x.delay < 120 ? x.delay + 's' : Math.round(x.delay / 60) + 'm' }))))));
    }
    const iocText = r.iocs.map((x) => x.value).join('\n');
    card.append(h('div', { class: 'actions' },
      r.iocs.length ? h('button', { class: 'primary', text: `Investigate ${r.iocs.length} indicator(s)`, onclick: () => { $('ctx').value = $('ctx').value || ('Email: ' + (s.subject || '')).slice(0, 200); run(iocText); } }) : null,
      h('button', { text: 'Copy findings', onclick: (e) => copyText([`Email header analysis: ${r.verdict.toUpperCase()}`, `Subject: ${s.subject}`, `From: ${s.from}`,
        `SPF ${r.auth.spf || 'n/a'} · DKIM ${r.auth.dkim || 'n/a'} · DMARC ${r.auth.dmarc || 'n/a'}`, r.origin ? 'Originating IP: ' + I.defang(r.origin) : '',
        ...r.reasons.filter((x) => x.kind !== 'info').map((x) => '- ' + x.t)].filter(Boolean).join('\n'), e.target) })));
    out.append(card);
  });

  // ---------------------------------------------------------------- memory ---
  const MEM = window.VSMemory;

  function prefillMemory(v) {
    editingId = null;
    $('mKind').value = 'auto';
    $('mIoc').value = v;
    $('mNote').value = '';
    $('mTicket').value = $('ctx').value.trim().slice(0, 80);
    $('mClient').value = (settings && settings.activeClient) || '';
    showTab('memory');
    $('mNote').focus();
  }
  $('mSave').addEventListener('click', async () => {
    const r = await send({ type: 'memorySave', entry: { id: editingId, kind: $('mKind').value, ioc: $('mIoc').value, client: $('mClient').value,
      verdict: $('mVerdict').value, note: $('mNote').value, ticket: $('mTicket').value, ttlDays: $('mTtl').value } });
    if (!r.ok) { $('mState').textContent = r.error; return; }
    editingId = null;
    $('mIoc').value = ''; $('mNote').value = ''; $('mTicket').value = '';
    $('mState').textContent = 'Saved ✓';
    setTimeout(() => { $('mState').textContent = ''; }, 2000);
    loadMemory();
    loadClients();
  });
  $('mFilter').addEventListener('input', () => loadMemory());

  async function loadMemory() {
    const list = await send({ type: 'memoryList' });
    const client = settings && settings.activeClient;
    const f = $('mFilter').value.trim().toLowerCase();
    const box = $('mList');
    box.textContent = '';
    const now = Date.now();
    const scoped = list.filter((m) => MEM.inScope(m, client));
    // Expired notes first: they need a decision (re-confirm or delete).
    const rows = scoped.filter((m) => !f || [m.ioc, m.client, m.note, m.ticket, m.by, m.kind].join(' ').toLowerCase().includes(f))
      .sort((a, b) => MEM.isExpired(b, now) - MEM.isExpired(a, now) || b.updated - a.updated);
    const expired = scoped.filter((m) => MEM.isExpired(m, now)).length;
    box.append(h('p', { class: 'muted small', text: `${scoped.length} note${scoped.length === 1 ? '' : 's'}${client ? ` for ${client} (and all clients)` : ''}`
      + (expired ? ` · ${expired} expired: re-confirm or delete them` : '') }));
    if (!rows.length) box.append(h('p', { class: 'muted small', text: list.length ? 'No match.' : 'No client notes yet. Use “Remember…” on any result, or add one above.' }));
    for (const m of rows.slice(0, 300)) {
      const exp = MEM.isExpired(m, now);
      const days = m.expires ? Math.round((m.expires - now) / MEM.DAY) : null;
      const validity = !m.expires ? 'never expires' : exp ? `expired ${MEM.fmtDate(m.expires)}` : `valid ${days} more day${days === 1 ? '' : 's'}`;
      box.append(h('div', { class: 'card mem' + (exp ? ' expired' : '') },
        h('div', { class: 'row between' }, h('span', {}, h('span', { class: 'chip', text: MEM.KIND_LABEL[m.kind || 'ioc'] }), ' ', h('span', { class: 'ioc-v', text: m.ioc })),
          exp ? h('span', { class: 'chip warn', text: 'EXPIRED' }) : pill(m.verdict === 'note' ? 'unknown' : m.verdict, m.verdict)),
        h('div', { text: (m.client ? m.client + ' · ' : 'All clients · ') + (m.note || '(no note)') }),
        h('div', { class: 'meta', text: [m.by ? 'by ' + m.by : '', m.ticket, 'updated ' + MEM.fmtDate(m.updated), validity].filter(Boolean).join(' · ') }),
        h('div', { class: 'row between small' }, h('span'),
          h('span', {},
            (exp || (days != null && days <= 14)) ? h('button', { class: 'link', text: 'still true: re-confirm', onclick: async () => { await send({ type: 'memoryConfirm', id: m.id }); loadMemory(); } }) : null,
            h('button', { class: 'link', text: 'edit', onclick: () => { editingId = m.id; $('mKind').value = m.kind === 'ioc' ? 'auto' : m.kind; $('mIoc').value = m.ioc; $('mClient').value = m.client;
              $('mVerdict').value = m.verdict; $('mNote').value = m.note; $('mTicket').value = m.ticket || ''; window.scrollTo(0, 0); } }),
            h('button', { class: 'link', text: 'delete', onclick: async () => { if (confirm('Delete this note?')) { await send({ type: 'memoryDelete', id: m.id }); loadMemory(); loadClients(); } } })))));
    }
  }

  // ------------------------------------------------------------ EDR import ---
  // The CSV is parsed here in the panel; only the notes the analyst ticks are stored.
  $('edrFile').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    e.target.value = '';
    const box = $('edrReview');
    box.textContent = '';
    if (!file) return;
    if (file.size > 25 * 1024 * 1024) { box.append(h('p', { class: 'err small', text: 'File is larger than 25 MB. Export a shorter time range.' })); return; }
    const r = window.VSImport.importCsv(await file.text());
    if (r.error) { box.append(h('p', { class: 'small', style: 'color:var(--block)', text: r.error })); return; }
    const guess = (settings && settings.activeClient) || r.sites[0] || '';
    const client = h('input', { type: 'text', value: guess, placeholder: 'Client name for these notes' });
    const checks = {};
    const list = h('div', { class: 'small' });
    for (const [cat, n] of Object.entries(r.counts)) {
      const cb = h('input', { type: 'checkbox', checked: cat !== 'user' });
      checks[cat] = cb;
      list.append(h('label', { class: 'toggle', style: 'margin:4px 0' }, cb, h('span', {}, `${window.VSImport.CATEGORY_LABEL[cat] || cat}: `, h('b', { text: String(n) }))));
    }
    const sample = r.entries.slice(0, 4).map((x) => h('li', { text: `${x.kind === 'ioc' ? '' : x.kind + ' '}${x.ioc}: ${x.note.slice(0, 110)}${x.note.length > 110 ? '…' : ''}` }));
    const status = h('div', { class: 'muted small' });
    const go = h('button', { class: 'primary', text: 'Save to client memory', onclick: async () => {
      const chosen = r.entries.filter((x) => checks[x.category] && checks[x.category].checked);
      if (!chosen.length) { status.textContent = 'Nothing selected.'; return; }
      const name = client.value.trim().slice(0, 60);
      go.disabled = true;
      const res = await send({ type: 'memoryUpsert', entries: chosen.map((x) => Object.assign({}, x, { client: name })), defaults: { client: name, ticket: 'S1 import ' + new Date().toISOString().slice(0, 10) } });
      go.disabled = false;
      if (!res || !res.ok) { status.textContent = (res && res.error) || 'Import failed'; return; }
      status.textContent = `Saved: ${res.added} new, ${res.updated} updated${res.rejected ? `, ${res.rejected} skipped` : ''}.`;
      if (name && (!settings.activeClient || settings.activeClient !== name)) settings = await send({ type: 'analystSave', patch: { activeClient: name } });
      await loadClients();
      loadMemory();
    } });
    box.append(h('div', { style: 'margin-top:8px' },
      h('p', { class: 'small', style: 'margin:0 0 6px' }, h('b', { text: r.label }), ` · ${r.rows} rows${r.skipped ? `, ${r.skipped} without endpoint / hash data ignored` : ''}`),
      h('label', { class: 'f' }, 'Client', client),
      list,
      sample.length ? h('details', {}, h('summary', { text: 'Preview' }), h('ul', { style: 'padding-left:16px;margin:4px 0' }, sample)) : null,
      h('div', { class: 'row between', style: 'margin-top:6px' }, status, go)));
  });

  // ------------------------------------------------------------ active client ---
  async function loadClients() {
    const list = await send({ type: 'memoryList' });
    const names = MEM.clients(list);
    const active = (settings && settings.activeClient) || '';
    if (active && !names.some((n) => n.toLowerCase() === active.toLowerCase())) names.push(active);
    const sel = $('client');
    sel.textContent = '';
    sel.append(h('option', { value: '', text: 'All clients' }));
    for (const n of names) sel.append(h('option', { value: n, text: n }));
    sel.append(h('option', { value: '__new', text: '+ New client…' }));
    sel.value = active;
    const dl = $('clientList');
    dl.textContent = '';
    for (const n of names) dl.append(h('option', { value: n }));
  }
  $('client').addEventListener('change', async () => {
    let v = $('client').value;
    if (v === '__new') {
      v = (prompt('Client name (as you want it on notes and tickets):') || '').trim().slice(0, 60);
      if (!v) { $('client').value = (settings && settings.activeClient) || ''; return; }
    }
    settings = await send({ type: 'analystSave', patch: { activeClient: v } });
    await loadClients();
    loadMemory();
    if (current.length) run(); // verdicts depend on this client's notes
  });

  $('mExport').addEventListener('click', async () => {
    const list = await send({ type: 'memoryList' });
    const a = h('a', { href: URL.createObjectURL(new Blob([JSON.stringify(list, null, 2)], { type: 'application/json' })), download: `soclens-client-memory-${new Date().toISOString().slice(0, 10)}.json` });
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  $('mImportFile').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    let items;
    try { items = JSON.parse(await file.text()); } catch (_) { $('mState').textContent = 'Not a valid JSON file'; return; }
    const r = await send({ type: 'memoryImport', items });
    $('mState').textContent = r.ok ? `Imported: ${r.added} new, ${r.updated} updated` : r.error;
    e.target.value = '';
    loadMemory();
  });

  // ------------------------------------------------- queries from elsewhere ---
  async function takeQuery() {
    const { analystQuery } = await chrome.storage.session.get('analystQuery');
    if (analystQuery && analystQuery.value && Date.now() - analystQuery.t < 60e3) {
      await chrome.storage.session.remove('analystQuery');
      run(analystQuery.value);
    }
  }
  chrome.storage.onChanged.addListener((ch, area) => { if (area === 'session' && ch.analystQuery && ch.analystQuery.newValue) takeQuery(); });

  (async function init() {
    await loadSettings();
    await loadClients();
    const m = location.hash.match(/^#q=(.*)$/);
    if (m) { run(decodeURIComponent(m[1])); history.replaceState(null, '', location.pathname); }
    else takeQuery();
  })();
})();
