/*
 * IOC Triage client memory (v2): what is normal for each client, written by analysts.
 *
 * Entry: { id, kind, ioc, client, verdict, note, ticket, by, created, updated, expires }
 *   kind     ioc     IP, CIDR, domain (subdomains included), URL, email or hash
 *            asn     a network, e.g. AS62044 (Zscaler): matches every IP in it
 *            country two-letter code, e.g. BD: normal sign-in country for this client
 *            user    account name, e.g. svc-backup: spotted in pasted alert text
 *            host    hostname, e.g. BKP-SRV01: spotted in pasted alert text
 *   client   '' = all clients
 *   verdict  benign | malicious | note
 *   expires  ms timestamp, 0 = never. Expired notes are shown but never trusted.
 *
 * Pure functions: the service worker stores entries; panel, highlighter and tests use these.
 */
(function (root) {
  'use strict';
  const I = root.VSIoc, A = root.VSAnalyzer;
  const DAY = 864e5;
  const KINDS = ['ioc', 'asn', 'country', 'user', 'host'];
  const KIND_LABEL = { ioc: 'Indicator', asn: 'Network (ASN)', country: 'Country', user: 'Account', host: 'Hostname' };
  // Weight of a note in the verdict: an exact indicator says more than "this network / country is normal".
  const WEIGHT = { ioc: 60, asn: 35, country: 12, user: 0, host: 0 };

  /** Turn what the analyst typed into { kind, value }. kind 'auto' guesses from the text. */
  function parseKey(kind, raw) {
    let s = String(raw || '').trim();
    if (!s) throw new Error('Enter what to remember');
    if (!kind || kind === 'auto') {
      const pre = s.match(/^(asn|as|country|user|account|host|hostname)\s*:\s*(.+)$/i);
      if (pre) { kind = { as: 'asn', account: 'user', hostname: 'host' }[pre[1].toLowerCase()] || pre[1].toLowerCase(); s = pre[2].trim(); }
      else if (/^AS\d{1,10}$/i.test(s)) kind = 'asn';
      else kind = 'ioc';
    }
    if (kind === 'asn') {
      const m = s.match(/^(?:AS)?\s*(\d{1,10})$/i);
      if (!m) throw new Error('ASN looks like AS62044');
      return { kind, value: 'AS' + m[1] };
    }
    if (kind === 'country') {
      if (!/^[a-z]{2}$/i.test(s)) throw new Error('Use the two-letter country code, e.g. BD, MY, SG');
      return { kind, value: s.toUpperCase() };
    }
    if (kind === 'user' || kind === 'host') {
      if (/\s/.test(s) || s.length > 120) throw new Error('One account or hostname, without spaces');
      return { kind, value: s.toLowerCase() };
    }
    // ioc: CIDR ranges are allowed as-is, everything else goes through the IOC parser.
    if (/^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$/.test(I.refang(s))) return { kind: 'ioc', value: I.refang(s) };
    const c = I.classify(s);
    if (c.type === 'unknown') throw new Error('Not an IP, CIDR, domain, URL, email or hash. For an account, hostname, ASN or country pick the type.');
    return { kind: 'ioc', value: c.value, type: c.type };
  }

  function normalize(x, now) {
    now = now || Date.now();
    const kind = KINDS.includes(x.kind) ? x.kind : 'ioc';
    return {
      id: String(x.id || ''), kind, ioc: String(x.ioc || '').slice(0, 2048), client: String(x.client || '').trim().slice(0, 60),
      verdict: ['benign', 'malicious', 'note'].includes(x.verdict) ? x.verdict : 'note', note: String(x.note || '').trim().slice(0, 500),
      ticket: String(x.ticket || '').trim().slice(0, 80), by: String(x.by || '').trim().slice(0, 60),
      created: Number(x.created) || now, updated: Number(x.updated) || now, expires: Number(x.expires) || 0
    };
  }

  function isExpired(m, now) { return !!(m.expires && m.expires < (now || Date.now())); }
  function inScope(m, client) { return !client || !m.client || m.client.toLowerCase() === String(client).toLowerCase(); }
  function annotate(m, now) { return Object.assign({}, m, { kind: m.kind || 'ioc', expired: isExpired(m, now), _desc: describe(m) }); }
  const newestFirst = (a, b) => (a.expired - b.expired) || (b.updated || 0) - (a.updated || 0);

  /** Notes about this exact indicator (IP / CIDR / domain incl. subdomains / URL / email / hash). */
  function matchIoc(list, type, value, client, now) {
    const g = I.GROUP[type];
    const dom = I.domainOf(type, value);
    return list.filter((m) => (m.kind || 'ioc') === 'ioc' && inScope(m, client) && (() => {
      if (m.ioc === value) return true;
      if (g === 'ip' && m.ioc.includes('/')) return I.ipInCidr(value, m.ioc);
      if (m.ioc.includes('/') || /^\d+\.\d+\.\d+\.\d+$/.test(m.ioc)) return false;
      const mt = I.classify(m.ioc);
      if (dom && mt.group === 'domain') return A ? A.hostMatches(dom, mt.value) : dom === mt.value || dom.endsWith('.' + mt.value);
      return false;
    })()).map((m) => annotate(m, now)).sort(newestFirst);
  }

  /** Notes about the network or country an IP belongs to (needs ipinfo / AbuseIPDB data). */
  function matchNetwork(list, net, client, now) {
    const asn = net && net.asn ? 'AS' + String(net.asn).replace(/^AS/i, '') : '';
    const cc = net && net.country ? String(net.country).toUpperCase() : '';
    return list.filter((m) => inScope(m, client) && ((m.kind === 'asn' && asn && m.ioc === asn) || (m.kind === 'country' && cc && m.ioc === cc)))
      .map((m) => annotate(m, now)).sort(newestFirst);
  }

  /** Accounts / hostnames from memory that appear in pasted alert text. */
  function matchContext(list, text, client, now) {
    const t = String(text || '');
    if (!t) return [];
    return list.filter((m) => (m.kind === 'user' || m.kind === 'host') && inScope(m, client) && m.ioc &&
      new RegExp('(^|[^\\w.-])' + m.ioc.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?![\\w-])', 'i').test(t))
      .map((m) => annotate(m, now)).sort(newestFirst);
  }

  function clients(list) {
    const seen = new Map();
    for (const m of list) if (m.client && !seen.has(m.client.toLowerCase())) seen.set(m.client.toLowerCase(), m.client);
    return [...seen.values()].sort((a, b) => a.localeCompare(b));
  }

  function fmtDate(ts) { return new Date(ts).toLocaleDateString([], { day: 'numeric', month: 'short', year: 'numeric' }); }

  /** "Client A: Fortinet VPN egress (by Sam · INC-4711 · 12 Oct 2026)" */
  function describe(m) {
    const who = [m.by ? 'by ' + m.by : '', m.ticket || '', m.updated ? fmtDate(m.updated) : ''].filter(Boolean).join(' · ');
    const what = m.kind && m.kind !== 'ioc' ? `${KIND_LABEL[m.kind]} ${m.ioc}: ` : '';
    return `${m.client ? m.client + ': ' : ''}${what}${m.note || m.verdict}${who ? ' (' + who + ')' : ''}`;
  }

  /** Extract ASN number and country from investigation results. */
  function networkOf(sources) {
    const ii = sources && sources.ipinfo && sources.ipinfo.status === 'ok' ? sources.ipinfo.data : null;
    const ab = sources && sources.abuseipdb && sources.abuseipdb.status === 'ok' ? sources.abuseipdb.data : null;
    const asn = ii && (String(ii.org || '').match(/^AS(\d+)/i) || [])[1];
    return { asn: asn || '', country: (ii && ii.country) || (ab && ab.country) || '' };
  }

  const api = { KINDS, KIND_LABEL, WEIGHT, DAY, parseKey, normalize, isExpired, inScope, matchIoc, matchNetwork, matchContext, clients, describe, networkOf, fmtDate };
  root.VSMemory = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
