/*
 * IOC Triage block list export: turns flagged indicators into lists for firewalls, EDR and intel platforms.
 * Only flagged public indicators go in. The analyst reviews and deploys the list themselves; nothing is pushed.
 * Pure functions.
 */
(function (root) {
  'use strict';
  const FORMATS = [
    { id: 'plain', name: 'Plain list (all types)', ext: 'txt', mime: 'text/plain' },
    { id: 'ips', name: 'Firewall: IP addresses', ext: 'txt', mime: 'text/plain' },
    { id: 'domains', name: 'Firewall / DNS: domains', ext: 'txt', mime: 'text/plain' },
    { id: 'urls', name: 'Web proxy: URLs without scheme', ext: 'txt', mime: 'text/plain' },
    { id: 'hashes', name: 'EDR: SHA-256 hashes', ext: 'txt', mime: 'text/plain' },
    { id: 'defender', name: 'Microsoft Defender: indicators CSV', ext: 'csv', mime: 'text/csv' },
    { id: 'csv', name: 'CSV (all fields)', ext: 'csv', mime: 'text/csv' },
    { id: 'stix', name: 'STIX 2.1 bundle (JSON)', ext: 'json', mime: 'application/json' }
  ];
  const THREAT = new Set(['malicious', 'critical']);
  const WATCH = new Set(['suspicious', 'high']);
  const DAY = 864e5;

  /** items: [{ report, a }]. Skips CVEs, private addresses and anything not flagged. */
  function build(items, opts) {
    opts = opts || {};
    const entries = [];
    let skipped = 0;
    for (const it of items || []) {
      const r = it.report;
      const flagged = THREAT.has(it.a.verdict) || (opts.includeSuspicious && WATCH.has(it.a.verdict));
      if (!flagged || r.group === 'cve' || r.internal) { skipped++; continue; }
      entries.push({ type: r.type, group: r.group, value: r.value, verdict: it.a.verdict, confidence: it.a.confidence,
        reason: (it.a.reasons.find((x) => x.kind === 'bad') || {}).t || it.a.verdict });
    }
    return { entries, skipped };
  }

  // A cell starting with = + - @ runs as a formula when opened in a spreadsheet.
  const cell = (v) => {
    const s = String(v == null ? '' : v);
    const safe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
    return /[",\r\n]/.test(safe) ? '"' + safe.replace(/"/g, '""') + '"' : safe;
  };
  const rows = (table) => table.map((r) => r.map(cell).join(',')).join('\r\n') + '\r\n';
  const uniq = (a) => [...new Set(a)];

  const ofGroup = (entries, g) => uniq(entries.filter((e) => e.group === g).map((e) => e.value));

  // The host of a bad URL, unless it is a well-known site that hosts other people's content too.
  function urlHosts(entries) {
    const I = root.VSIoc, A = root.VSAnalyzer;
    return entries.filter((e) => e.group === 'url').map((e) => I.domainOf('url', e.value)).filter((h) => h && !(A && A.analyzeUrl('https://' + h + '/', {}).allow));
  }

  const DEFENDER_TYPE = { ipv4: 'IpAddress', ipv6: 'IpAddress', domain: 'DomainName', url: 'Url', sha256: 'FileSha256', sha1: 'FileSha1' };

  function defender(entries, opts) {
    const exp = new Date((opts.now || Date.now()) + (opts.days || 90) * DAY).toISOString().replace(/\.\d+Z$/, '.0Z');
    const table = [['indicatorType', 'indicatorValue', 'expirationTime', 'action', 'severity', 'title', 'description', 'recommendedActions']];
    for (const e of entries) {
      const t = DEFENDER_TYPE[e.type];
      if (!t) continue; // Defender takes no MD5 or email indicators
      const hash = e.group === 'hash';
      table.push([t, e.value, exp, hash ? 'BlockAndRemediate' : 'Block', THREAT.has(e.verdict) ? 'High' : 'Medium', `IOC Triage: ${e.verdict} ${e.group}`.slice(0, 100),
        [opts.ticket, e.reason].filter(Boolean).join(': ').slice(0, 300), 'Review the alert and the host that matched']);
    }
    return rows(table);
  }

  const stixQuote = (v) => String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
  function stixPattern(e) {
    const v = stixQuote(e.value);
    switch (e.type) {
      case 'ipv4': return `[ipv4-addr:value = '${v}']`;
      case 'ipv6': return `[ipv6-addr:value = '${v}']`;
      case 'domain': return `[domain-name:value = '${v}']`;
      case 'url': return `[url:value = '${v}']`;
      case 'email': return `[email-addr:value = '${v}']`;
      case 'md5': return `[file:hashes.MD5 = '${v}']`;
      case 'sha1': return `[file:hashes.'SHA-1' = '${v}']`;
      case 'sha256': return `[file:hashes.'SHA-256' = '${v}']`;
      default: return '';
    }
  }

  function stix(entries, opts) {
    const now = new Date(opts.now || Date.now()).toISOString();
    const uuid = () => (root.crypto && root.crypto.randomUUID ? root.crypto.randomUUID() : '00000000-0000-4000-8000-' + String(Math.random()).slice(2, 14).padEnd(12, '0'));
    const objects = entries.map((e) => ({ pattern: stixPattern(e), e })).filter((x) => x.pattern).map(({ pattern, e }) => ({
      type: 'indicator', spec_version: '2.1', id: 'indicator--' + uuid(), created: now, modified: now,
      name: `${e.verdict} ${e.group}: ${root.VSIoc ? root.VSIoc.defang(e.value, e.type) : e.value}`, description: [opts.ticket, e.reason].filter(Boolean).join(': '),
      indicator_types: ['malicious-activity'], pattern, pattern_type: 'stix', valid_from: now,
      confidence: { high: 85, medium: 60, low: 30 }[e.confidence] || 30 }));
    return JSON.stringify({ type: 'bundle', id: 'bundle--' + uuid(), objects }, null, 2) + '\n';
  }

  /** Text of the list in one format. opts: { now, days, ticket, client }. */
  function render(format, entries, opts) {
    opts = opts || {};
    switch (format) {
      case 'ips': return ofGroup(entries, 'ip').join('\n');
      case 'domains': return uniq([...ofGroup(entries, 'domain'), ...urlHosts(entries)]).join('\n');
      case 'urls': return ofGroup(entries, 'url').map((u) => u.replace(/^https?:\/\//i, '')).join('\n');
      case 'hashes': return uniq(entries.filter((e) => e.type === 'sha256').map((e) => e.value.toLowerCase())).join('\n');
      case 'defender': return defender(entries, opts);
      case 'csv': return rows([['type', 'value', 'verdict', 'confidence', 'reason', 'client', 'ticket', 'date'],
        ...entries.map((e) => [e.type, e.value, e.verdict, e.confidence, e.reason, opts.client || '', opts.ticket || '', new Date(opts.now || Date.now()).toISOString().slice(0, 10)])]);
      case 'stix': return stix(entries, opts);
      default: return uniq(entries.map((e) => e.value)).join('\n');
    }
  }

  const api = { FORMATS, build, render };
  root.VSBlocklist = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
