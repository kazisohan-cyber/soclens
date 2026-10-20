/*
 * SOCLens analyst engine: turns raw lookups for one indicator into a verdict an L1 can act on
 * (verdict, confidence, the reasons in plain words, what to do next), and writes ticket notes.
 * Pure functions: the service worker builds the report, the panel and tests render it.
 *
 * report = { type, group, value, internal, memory:[...], local:{...}, sources:{ name:{ status, data, link } } }
 * status: ok | notfound | nokey | ratelimited | error | skipped
 */
(function (root) {
  'use strict';

  const SOURCE_NAMES = {
    memory: 'Client memory', local: 'SOCLens local analysis', feed: 'SOCLens phishing feed', abuseipdb: 'AbuseIPDB',
    greynoise: 'GreyNoise', internetdb: 'Shodan InternetDB', ipinfo: 'ipinfo', vt: 'VirusTotal', threatfox: 'ThreatFox',
    urlhaus: 'URLhaus', malwarebazaar: 'MalwareBazaar', rdap: 'RDAP (domain age)', dns: 'DNS', kev: 'CISA KEV',
    epss: 'FIRST EPSS', nvd: 'NVD'
  };

  const ACTIONS = {
    ip: {
      malicious: ['Block the IP at the firewall / EDR network policy', 'Search SIEM (last 30 days) for every host and user that talked to it',
        'If it appears in a sign-in alert: revoke sessions and reset the password for that user'],
      suspicious: ['Search SIEM for other hits on this IP before deciding', 'Check the user / asset context (VPN, travel, known vendor)',
        'Escalate to L2 if it touched a privileged account or a server'],
      benign: ['Likely false positive: close with this note', 'If it fires often, add a client note and propose a suppression / tuning'],
      unknown: ['No reputation either way: decide on context (asset, user, time, volume)', 'Search SIEM for other hits on this IP']
    },
    domain: {
      malicious: ['Block the domain at DNS / web proxy / email gateway', 'Search proxy and DNS logs for users who visited it',
        'Search the mail gateway for messages containing it and purge them', 'If credentials were entered: reset password, revoke sessions, check inbox rules'],
      suspicious: ['Detonate it safely (urlscan) before anyone opens it', 'Search proxy / DNS logs for visits', 'Check how the user received it (email, chat)'],
      benign: ['Likely benign: close with this note', 'Add a client note if this domain is part of the client\'s normal business'],
      unknown: ['Detonate it safely (urlscan) to see the page', 'Search proxy / DNS logs for visits']
    },
    hash: {
      malicious: ['Isolate the host in the EDR', 'Search the fleet (EDR) for the same hash', 'Review the parent process and how the file arrived'],
      suspicious: ['Search the fleet for the hash', 'Submit to a sandbox before deciding', 'Escalate to L2 with the process tree'],
      benign: ['Known good file: close with this note'],
      unknown: ['Never seen publicly: could be new or custom. Sandbox it and check the process tree', 'Search the fleet for the hash']
    },
    email: {
      malicious: ['Purge messages from this sender', 'Block the sender domain at the email gateway', 'Check who replied or clicked'],
      suspicious: ['Check the full email headers (Headers tab)', 'Search the mail gateway for the sender'],
      benign: ['Sender looks normal: decide on content'],
      unknown: ['Check the full email headers (Headers tab)']
    }
  };

  // Infrastructure every analyst recognises on sight; saying "unknown" here wastes their time.
  const KNOWN_IPS = {
    '8.8.8.8': 'Google Public DNS', '8.8.4.4': 'Google Public DNS', '1.1.1.1': 'Cloudflare DNS', '1.0.0.1': 'Cloudflare DNS',
    '9.9.9.9': 'Quad9 DNS', '149.112.112.112': 'Quad9 DNS', '208.67.222.222': 'Cisco OpenDNS', '208.67.220.220': 'Cisco OpenDNS',
    '2001:4860:4860::8888': 'Google Public DNS', '2001:4860:4860::8844': 'Google Public DNS', '2606:4700:4700::1111': 'Cloudflare DNS'
  };
  const KNOWN_HOSTS = [[/(^|\.)dns\.google$/, 'Google Public DNS'], [/(^|\.)1e100\.net$/, 'Google infrastructure'], [/^one\.one\.one\.one$/, 'Cloudflare DNS'],
    [/(^|\.)quad9\.net$/, 'Quad9 DNS'], [/(^|\.)opendns\.com$/, 'Cisco OpenDNS']];
  const FREE_MAIL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com', 'ymail.com', 'aol.com',
    'icloud.com', 'me.com', 'proton.me', 'protonmail.com', 'gmx.com', 'gmx.net', 'mail.com', 'yandex.com', 'yandex.ru', 'mail.ru', 'zoho.com', 'tutanota.com', 'qq.com', '163.com']);

  function n(x) { return typeof x === 'number' && isFinite(x) ? x : Number(x) || 0; }
  // EPSS is a probability; never round 0.99999 up to a flat "100%".
  function epssPct(x) { const p = n(x) * 100; return p >= 99.95 ? '>99.9%' : (Math.round(p * 10) / 10) + '%'; }

  function assess(report) {
    const reasons = [];
    let score = 0;
    let evidenceSources = 0; // sources that returned data (ok or a clean "not found")
    const add = (pts, t, kind, src) => { score += pts; reasons.push({ t, kind: kind || (pts > 0 ? 'bad' : pts < 0 ? 'good' : 'info'), src }); };
    const S = report.sources || {};
    const ok = (k) => S[k] && S[k].status === 'ok' && S[k].data;
    for (const k of Object.keys(S)) if (S[k] && (S[k].status === 'ok' || S[k].status === 'notfound')) evidenceSources++;

    const g = report.group;
    const res = { verdict: 'unknown', confidence: 'low', score: 0, reasons, summary: '', actions: [], facts: [], memoryOverride: null };

    if (g === 'cve') return assessCve(report, res);

    if (report.internal) {
      res.verdict = 'internal';
      res.confidence = 'high';
      add(0, 'Private / internal address: public reputation does not apply', 'info', 'local');
      // For internal assets the client's own notes are the main evidence ("10.20.30.40 = backup server").
      const notes = (report.memory || []);
      for (const m of notes) add(0, m.expired ? `Client note EXPIRED ${new Date(m.expires).toLocaleDateString()}: ${noteText(m)}. Re-confirm it` : `Client note: ${noteText(m)}`,
        m.expired ? 'info' : m.verdict === 'malicious' ? 'bad' : m.verdict === 'benign' ? 'good' : 'info', 'memory');
      const known = notes.find((m) => !m.expired);
      res.actions = known ? ['Compare the alert with the client note: does the activity fit what this asset normally does?', 'If it does not fit, look at the process that made the connection']
        : ['Identify the asset in the CMDB / EDR (hostname, owner)', 'Look at what process made the connection on that host'];
      res.summary = known ? `${report.value} is an internal address known to the client: ${noteText(known)}.`
        : `${report.value} is an internal address. Check the asset and the process, not internet reputation.`;
      memoryFacts(report, res);
      return res;
    }

    if (g === 'ip') {
      const hostnames = [].concat(ok('internetdb') ? S.internetdb.data.hostnames || [] : [], ok('ipinfo') && S.ipinfo.data.hostname ? [S.ipinfo.data.hostname] : []);
      const known = KNOWN_IPS[report.value] || (KNOWN_HOSTS.find(([re]) => hostnames.some((h) => re.test(String(h).toLowerCase()))) || [])[1];
      if (known) add(-35, `Well-known infrastructure: ${known}`, 'good', 'local');
      else if (hostnames.length) add(0, `Reverse DNS: ${hostnames.slice(0, 2).join(', ')}`, 'info', ok('internetdb') ? 'internetdb' : 'ipinfo');
    }
    if (g === 'email') {
      const d = (report.value.split('@')[1] || '').toLowerCase();
      if (FREE_MAIL.has(d)) add(0, `Free webmail address (${d}): anyone can register it, so check it matches the claimed sender`, 'info', 'local');
    }

    // Local analysis (lookalikes, brand impersonation, phishing feed) for domains / URLs / email domains.
    const L = report.local || {};
    if (L.unwrapped && L.unwrapped !== report.value) add(0, `Link wrapper removed: real destination is ${L.unwrapped}`, 'info', 'local');
    if (L.blocklisted) add(60, 'Listed in the SOCLens phishing feed (PhishTank / OpenPhish / URLhaus)', 'bad', 'feed');
    if (L.analyzer) {
      const a = L.analyzer;
      if (a.allow) add(-25, a.brand ? `Official ${a.brand} domain` : 'Allow-listed / well-known legitimate domain', 'good', 'local');
      else {
        if (a.level === 'block') add(45, 'Strong impersonation signals', 'bad', 'local');
        else if (a.level === 'warn') add(25, 'Impersonation signals', 'bad', 'local');
        for (const r of (a.reasons || []).slice(0, 4)) add(0, r, a.level === 'safe' ? 'info' : 'bad', 'local');
      }
    }
    if (ok('rdap')) {
      const d = S.rdap.data.ageDays;
      if (d != null) {
        if (d < 7) add(30, `Domain registered ${d} day(s) ago`, 'bad', 'rdap');
        else if (d < 30) add(18, `Domain registered ${d} days ago (new)`, 'bad', 'rdap');
        else if (d > 730) add(-8, `Domain registered ${Math.floor(d / 365)} years ago`, 'good', 'rdap');
        else add(0, `Domain registered ${d} days ago`, 'info', 'rdap');
      }
    }
    if (ok('dns')) {
      const d = S.dns.data;
      if (d.nx) add(5, 'Domain does not resolve (NXDOMAIN): taken down or not live yet', 'info', 'dns');
      else if (d.a && d.a.length) add(0, `Resolves to ${d.a.slice(0, 3).join(', ')}`, 'info', 'dns');
    }

    // IP reputation
    const torFrom = [];
    if (ok('greynoise')) {
      const d = S.greynoise.data;
      if (d.riot) add(-30, `GreyNoise: known business service (${d.name || 'common service'})`, 'good', 'greynoise');
      else if (d.classification === 'malicious') add(35, `GreyNoise: malicious internet scanner${d.name && d.name !== 'unknown' ? ' (' + d.name + ')' : ''}`, 'bad', 'greynoise');
      else if (d.classification === 'benign') add(-25, `GreyNoise: benign scanner (${d.name || 'research'})`, 'good', 'greynoise');
      else if (d.noise) add(10, 'GreyNoise: mass internet scanner (background noise, rarely targeted)', 'bad', 'greynoise');
    } else if (S.greynoise && S.greynoise.status === 'notfound') add(0, 'GreyNoise: not seen scanning the internet', 'info', 'greynoise');
    if (ok('abuseipdb')) {
      const d = S.abuseipdb.data;
      const sc = n(d.score), rep = n(d.reports);
      if (d.whitelisted) add(-20, 'AbuseIPDB: whitelisted', 'good', 'abuseipdb');
      if (sc >= 75) add(40, `AbuseIPDB: ${sc}% abuse confidence, ${rep} reports`, 'bad', 'abuseipdb');
      else if (sc >= 25) add(20, `AbuseIPDB: ${sc}% abuse confidence, ${rep} reports`, 'bad', 'abuseipdb');
      else if (rep > 0) add(4, `AbuseIPDB: ${rep} old/low-confidence reports (${sc}%)`, 'info', 'abuseipdb');
      else add(-5, 'AbuseIPDB: no abuse reports', 'good', 'abuseipdb');
      if (d.tor) torFrom.push('AbuseIPDB');
      if (d.usage) add(0, `Usage type: ${d.usage}`, 'info', 'abuseipdb');
    }
    if (ok('internetdb')) {
      const d = S.internetdb.data;
      const tags = d.tags || [];
      if (tags.includes('tor')) torFrom.push('Shodan');
      if (tags.includes('c2')) add(40, 'Shodan: command-and-control server', 'bad', 'internetdb');
      if (tags.includes('malware')) add(30, 'Shodan: tagged malware', 'bad', 'internetdb');
      if (tags.includes('vpn') || tags.includes('proxy')) add(5, `Shodan: ${tags.filter((t) => t === 'vpn' || t === 'proxy').join('/')} service`, 'info', 'internetdb');
      if (tags.includes('compromised')) add(25, 'Shodan: likely compromised host', 'bad', 'internetdb');
      if ((d.vulns || []).length) add(3, `Shodan: exposed services with ${d.vulns.length} known CVE(s)`, 'info', 'internetdb');
      if ((d.ports || []).length) add(0, `Open ports: ${d.ports.slice(0, 10).join(', ')}`, 'info', 'internetdb');
    }
    if (ok('ipinfo')) {
      const d = S.ipinfo.data;
      if (d.org) add(0, `Network: ${d.org}${d.country ? ' · ' + [d.city, d.country].filter(Boolean).join(', ') : ''}`, 'info', 'ipinfo');
      if (/hosting|cloud|digitalocean|ovh|hetzner|linode|vultr|amazon|google cloud|microsoft|contabo|leaseweb|m247|choopa/i.test(d.org || '') && !(ok('greynoise') && S.greynoise.data.riot))
        add(4, 'Hosting / datacenter network (not a home or office ISP)', 'info', 'ipinfo');
    }

    if (g === 'ip') {
      const rdns = [].concat(ok('internetdb') ? S.internetdb.data.hostnames || [] : [], ok('ipinfo') && S.ipinfo.data.hostname ? [S.ipinfo.data.hostname] : []);
      if (rdns.some((h) => /(^|[.-])tor-?exit|torexit/i.test(h))) torFrom.push('reverse DNS');
      if (torFrom.length) add(30, `Tor exit node (${[...new Set(torFrom)].join(', ')}): the real source is hidden`, 'bad', 'internetdb');
    }

    // Multi-type sources
    if (ok('vt')) {
      const d = S.vt.data;
      const mal = n(d.malicious), sus = n(d.suspicious), total = mal + sus + n(d.harmless) + n(d.undetected);
      const strong = g === 'hash' ? [10, 3] : [5, 1];
      if (mal >= strong[0]) add(g === 'hash' ? 60 : 40, `VirusTotal: ${mal}/${total} engines flag it${d.label ? ' (' + d.label + ')' : ''}`, 'bad', 'vt');
      else if (mal >= strong[1] || sus >= 3) add(g === 'hash' ? 30 : 15, `VirusTotal: ${mal} malicious, ${sus} suspicious of ${total}`, 'bad', 'vt');
      else if (total > 0) add(g === 'hash' ? -20 : -6, `VirusTotal: clean (0/${total})`, 'good', 'vt');
      if (n(d.reputation) <= -10) add(10, `VirusTotal community reputation ${d.reputation}`, 'bad', 'vt');
      if (d.name || d.typeDesc) add(0, `File: ${[d.name, d.typeDesc].filter(Boolean).join(' · ')}`, 'info', 'vt');
    } else if (S.vt && S.vt.status === 'notfound') add(g === 'hash' ? 5 : 0, 'VirusTotal: never seen', 'info', 'vt');
    if (ok('threatfox')) {
      const d = S.threatfox.data;
      add(50, `ThreatFox: ${d.threatType || 'IOC'} for ${d.malware || 'known malware'} (confidence ${d.confidence || '?'}%)`, 'bad', 'threatfox');
    }
    if (ok('urlhaus')) {
      const d = S.urlhaus.data;
      if (n(d.urlsCount) > 0 || d.threat) add(d.online ? 50 : 30, `URLhaus: ${d.threat || 'malware distribution'}${d.urlsCount ? ' · ' + d.urlsCount + ' URL(s)' : ''}${d.online ? ' · still online' : ''}`, 'bad', 'urlhaus');
      if (d.blacklists && d.blacklists.length) add(15, `Listed on ${d.blacklists.join(', ')}`, 'bad', 'urlhaus');
    }
    if (ok('malwarebazaar')) {
      const d = S.malwarebazaar.data;
      add(60, `MalwareBazaar: ${d.signature || 'known malware sample'}${d.fileType ? ' (' + d.fileType + ')' : ''}`, 'bad', 'malwarebazaar');
    }

    // Client memory: analysts know the client. An exact-indicator note weighs most, a network or country
    // note less. Expired notes are shown but never trusted, and conflicts with strong intel are flagged.
    const W = { ioc: 60, asn: 35, country: 12 }; // a country only lowers suspicion, never clears it alone
    const mems = report.memory || [];
    for (const m of mems.filter((x) => x.expired)) {
      add(0, `Client note EXPIRED ${new Date(m.expires).toLocaleDateString()}: ${noteText(m)}. Re-confirm it before trusting it`, 'info', 'memory');
    }
    const live = mems.filter((x) => !x.expired);
    const top = live.find((x) => (x.kind || 'ioc') === 'ioc') || live[0];
    if (top) {
      const w = W[top.kind || 'ioc'] || 60;
      if (top.verdict !== 'note') res.memoryOverride = top;
      if (top.verdict === 'benign') {
        if (score >= 60) add(0, `Client note says benign (${noteText(top)}) but public intel is strongly malicious: re-check the note`, 'bad', 'memory');
        else add(-w, `Client note: ${noteText(top)}`, 'good', 'memory');
      } else if (top.verdict === 'malicious') add(w, `Client note: ${noteText(top)}`, 'bad', 'memory');
      else add(0, `Client note: ${noteText(top)}`, 'info', 'memory');
    }
    for (const m of live) if (m !== top) add(0, `Client note: ${noteText(m)}`, 'info', 'memory');

    res.score = Math.max(-100, Math.min(100, score));
    res.verdict = res.score >= 55 ? 'malicious' : res.score >= 22 ? 'suspicious' : res.score <= -15 ? 'benign' : 'unknown';
    const bad = reasons.filter((r) => r.kind === 'bad' && r.src !== 'local').length + (L.blocklisted ? 1 : 0);
    const good = reasons.filter((r) => r.kind === 'good').length;
    const strongSignals = res.verdict === 'malicious' ? bad : res.verdict === 'benign' ? good : 0;
    res.confidence = (res.memoryOverride && (res.memoryOverride.kind || 'ioc') === 'ioc') ? 'high'
      : strongSignals >= 2 && evidenceSources >= 2 ? 'high' : (strongSignals >= 1 || evidenceSources >= 3) ? 'medium' : 'low';
    if (res.verdict === 'unknown' && evidenceSources <= 1) res.confidence = 'low';

    res.actions = (ACTIONS[g === 'url' ? 'domain' : g] || ACTIONS.domain)[res.verdict] || [];
    res.summary = summarize(report, res);
    memoryFacts(report, res);
    return res;
  }

  function memoryFacts(report, res) {
    for (const m of report.memory || []) res.facts.push(['Client note', `${noteText(m)} (${m.expired ? 'expired' : m.verdict})`]);
  }

  // Memory entries from lib/memory.js carry _desc ("Client A: Network AS62044: Zscaler (by Arefin · INC-1)").
  function noteText(m) { return m._desc || `${m.client ? m.client + ': ' : ''}${m.note || m.verdict}`; }

  function assessCve(report, res) {
    const S = report.sources || {};
    const kev = S.kev && S.kev.status === 'ok' ? S.kev.data : null;
    const epss = S.epss && S.epss.status === 'ok' ? S.epss.data : null;
    const nvd = S.nvd && S.nvd.status === 'ok' ? S.nvd.data : null;
    const r = res.reasons;
    let pr = 'low';
    if (kev) {
      pr = 'critical';
      r.push({ t: `CISA KEV: exploited in the wild (${kev.vendor} ${kev.product}, added ${kev.dateAdded})`, kind: 'bad', src: 'kev' });
      if (kev.ransomware === 'Known') r.push({ t: 'Used in ransomware campaigns', kind: 'bad', src: 'kev' });
    } else if (S.kev && S.kev.status === 'notfound') r.push({ t: 'Not in CISA KEV (no confirmed exploitation listed)', kind: 'info', src: 'kev' });
    if (epss) {
      const p = Math.round(n(epss.epss) * 1000) / 10;
      r.push({ t: `EPSS: ${epssPct(epss.epss)} chance of exploitation in the next 30 days (top ${Math.max(0.1, Math.round((1 - n(epss.percentile)) * 1000) / 10)}%)`, kind: p >= 10 ? 'bad' : 'info', src: 'epss' });
      if (pr !== 'critical' && n(epss.epss) >= 0.5) pr = 'high';
    }
    if (nvd) {
      if (nvd.score != null) r.push({ t: `CVSS ${nvd.score} ${nvd.severity || ''}${nvd.vector ? ' · ' + nvd.vector : ''}`, kind: n(nvd.score) >= 9 ? 'bad' : 'info', src: 'nvd' });
      if (nvd.description) r.push({ t: nvd.description.slice(0, 280) + (nvd.description.length > 280 ? '…' : ''), kind: 'info', src: 'nvd' });
      if (pr === 'low') pr = n(nvd.score) >= 9 ? 'high' : n(nvd.score) >= 7 ? 'medium' : 'low';
    }
    res.verdict = pr;
    res.confidence = (kev || epss || nvd) ? 'high' : 'low';
    res.actions = pr === 'critical'
      ? ['Treat as an emergency patch: exploited in the wild', kev && kev.requiredAction ? 'CISA required action: ' + kev.requiredAction : 'Apply the vendor fix or mitigation', 'Hunt for exploitation on exposed assets (SIEM / EDR)']
      : pr === 'high' ? ['Patch in the next cycle; prioritise internet-facing assets', 'Check exposure (which assets run this product)']
        : ['Patch with normal priority'];
    res.summary = `${report.value}: ${pr.toUpperCase()} priority. ` + (kev ? 'Exploited in the wild (CISA KEV).' : epss ? `EPSS ${epssPct(epss.epss)}.` : '');
    return res;
  }

  const VERDICT_WORD = { malicious: 'very likely malicious', suspicious: 'suspicious', benign: 'likely benign', unknown: 'unknown (no strong signal)', internal: 'internal' };

  function summarize(report, res) {
    // Client memory explains a verdict best ("this is Client A's VPN"), so it leads the summary.
    const top = (kind) => res.reasons.filter((r) => r.kind === kind && !/^(Open ports|Network|Resolves|Usage type|File:)/.test(r.t))
      .sort((a, b) => (b.src === 'memory') - (a.src === 'memory')).slice(0, 2).map((r) => r.t.replace(/\.$/, ''));
    const why = res.verdict === 'benign' ? top('good') : top('bad');
    let s = `${defangShort(report)} is ${VERDICT_WORD[res.verdict]}`;
    if (why.length) s += ': ' + why.join('; ');
    s += '.';
    if (res.verdict === 'unknown' && !why.length) {
      const net = res.reasons.find((r) => /^(Network|Reverse DNS|Domain registered|Usage type)/.test(r.t));
      s += ' No reputation source has reported it' + (net ? ` (${net.t.replace(/^Network: /, '')})` : '') + '. Decide on context.';
    }
    if (res.actions[0]) s += ' Next: ' + res.actions[0].charAt(0).toLowerCase() + res.actions[0].slice(1) + '.';
    return s;
  }

  function defangShort(report) {
    const I = root.VSIoc;
    const v = I ? I.defang(report.value, report.type) : report.value;
    return v.length > 80 ? v.slice(0, 77) + '…' : v;
  }

  // ------------------------------------------------------------ ticket notes ---

  const RANK = { malicious: 5, critical: 5, suspicious: 4, high: 4, internal: 2, medium: 3, unknown: 1, low: 1, benign: 0 };

  function overall(items) {
    const worst = items.reduce((w, it) => (RANK[it.a.verdict] > RANK[w] ? it.a.verdict : w), 'benign');
    return items.length ? worst : 'unknown';
  }

  function checkedList(items) {
    const used = new Set(), skipped = new Set();
    for (const it of items) for (const [k, s] of Object.entries(it.report.sources || {})) {
      const nm = SOURCE_NAMES[k] || k;
      if (s.status === 'ok' || s.status === 'notfound') used.add(nm);
      else if (s.status === 'nokey') skipped.add(nm + ' (no API key)');
      else if (s.status === 'ratelimited') skipped.add(nm + ' (rate limit)');
      else if (s.status === 'error') skipped.add(nm + ' (unavailable)');
    }
    for (const it of items) if (it.report.local && it.report.local.analyzer) used.add(SOURCE_NAMES.local);
    return { used: [...used], skipped: [...skipped].filter((s) => !used.has(s.split(' (')[0])) };
  }

  /** items: [{ report, a: assess(report) }]. Returns { text, markdown, html }. */
  function ticketNote(items, opts) {
    opts = opts || {};
    const I = root.VSIoc;
    const when = new Date().toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
    const ov = overall(items);
    const { used, skipped } = checkedList(items);
    const actions = [];
    for (const it of items) for (const x of it.a.actions.slice(0, 3)) if (!actions.includes(x)) actions.push(x);
    const D = (it) => I ? I.defang(it.report.value, it.report.type) : it.report.value;
    const lab = (it) => (I && I.LABEL_OF[it.report.type]) || it.report.type;
    const reasonsOf = (it) => it.a.reasons.filter((r) => r.kind !== 'info' || /^(Network|Usage type|Domain registered|Client note|Link wrapper|File:|CISA|EPSS|CVSS)/.test(r.t)).slice(0, 6);

    const t = [];
    t.push(`SOCLens investigation · ${when}`);
    t.push(`Overall: ${ov.toUpperCase()} (${items.length} indicator${items.length === 1 ? '' : 's'})`);
    if (opts.client) t.push(`Client: ${opts.client}`);
    if (opts.context) t.push(`Context: ${opts.context}`);
    for (const c of opts.clientContext || []) t.push(`Client context: ${c}`);
    if (opts.summary) t.push(`Summary: ${opts.summary}`);
    t.push('');
    items.forEach((it, i) => {
      t.push(`${i + 1}. ${D(it)} [${lab(it)}]: ${it.a.verdict.toUpperCase()} (confidence ${it.a.confidence})`);
      for (const r of reasonsOf(it)) t.push(`   - ${r.t}`);
    });
    t.push('');
    t.push('Recommended actions:');
    actions.slice(0, 6).forEach((x) => t.push(`- ${x}`));
    t.push('');
    t.push(`Checked: ${used.join(', ') || 'none'}`);
    if (skipped.length) t.push(`Not checked: ${skipped.join(', ')}`);
    t.push(`Analyst: ${opts.analyst || '________'} · Decision: ________`);
    t.push('(Indicators defanged. Generated by SOCLens; verify before closing.)');
    const text = t.join('\n');

    const md = [];
    md.push(`**SOCLens investigation** · ${when}  `);
    md.push(`**Overall: ${ov.toUpperCase()}** (${items.length} indicator${items.length === 1 ? '' : 's'})`);
    if (opts.client) md.push(`\n**Client:** ${opts.client}`);
    if (opts.context) md.push(`\n**Context:** ${opts.context}`);
    for (const c of opts.clientContext || []) md.push(`\n**Client context:** ${c}`);
    if (opts.summary) md.push(`\n**Summary:** ${opts.summary}`);
    md.push('', '| # | Indicator | Type | Verdict | Key findings |', '|---|---|---|---|---|');
    items.forEach((it, i) => md.push(`| ${i + 1} | \`${D(it)}\` | ${lab(it)} | **${it.a.verdict.toUpperCase()}** (${it.a.confidence}) | ${reasonsOf(it).slice(0, 3).map((r) => r.t.replace(/\|/g, '/')).join('<br>')} |`));
    md.push('', '**Recommended actions**', ...actions.slice(0, 6).map((x) => `- ${x}`), '', `_Checked: ${used.join(', ') || 'none'}${skipped.length ? ' · Not checked: ' + skipped.join(', ') : ''}_`);
    const markdown = md.join('\n');

    const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    const color = { malicious: '#b42318', critical: '#b42318', suspicious: '#b54708', high: '#b54708', benign: '#067647', internal: '#475467', unknown: '#475467', medium: '#b54708', low: '#475467' };
    const rows = items.map((it, i) => `<tr><td style="padding:3px 8px;vertical-align:top">${i + 1}</td><td style="padding:3px 8px;vertical-align:top;font-family:Consolas,monospace">${esc(D(it))}</td><td style="padding:3px 8px;vertical-align:top">${esc(lab(it))}</td><td style="padding:3px 8px;vertical-align:top;color:${color[it.a.verdict] || '#475467'}"><b>${esc(it.a.verdict.toUpperCase())}</b> (${esc(it.a.confidence)})</td><td style="padding:3px 8px;vertical-align:top">${reasonsOf(it).map((r) => esc(r.t)).join('<br>')}</td></tr>`).join('');
    const html = `<div style="font-family:Segoe UI,Arial,sans-serif;font-size:13px">`
      + `<p><b>SOCLens investigation</b> · ${esc(when)}<br><b style="color:${color[ov] || '#475467'}">Overall: ${esc(ov.toUpperCase())}</b> (${items.length} indicator${items.length === 1 ? '' : 's'})${opts.client ? '<br><b>Client:</b> ' + esc(opts.client) : ''}${opts.context ? '<br><b>Context:</b> ' + esc(opts.context) : ''}${(opts.clientContext || []).map((c) => '<br><b>Client context:</b> ' + esc(c)).join('')}${opts.summary ? '<br><b>Summary:</b> ' + esc(opts.summary) : ''}</p>`
      + `<table style="border-collapse:collapse" border="1" cellspacing="0"><tr><th style="padding:3px 8px">#</th><th style="padding:3px 8px">Indicator</th><th style="padding:3px 8px">Type</th><th style="padding:3px 8px">Verdict</th><th style="padding:3px 8px">Key findings</th></tr>${rows}</table>`
      + `<p><b>Recommended actions</b></p><ul>${actions.slice(0, 6).map((x) => '<li>' + esc(x) + '</li>').join('')}</ul>`
      + `<p style="color:#475467"><i>Checked: ${esc(used.join(', ') || 'none')}${skipped.length ? ' · Not checked: ' + esc(skipped.join(', ')) : ''}. Indicators defanged. Generated by SOCLens; verify before closing.</i></p></div>`;
    return { text, markdown, html };
  }

  const api = { assess, ticketNote, overall, SOURCE_NAMES, RANK };
  root.VSEngine = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
