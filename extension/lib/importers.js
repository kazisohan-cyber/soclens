/*
 * SOCLens importers: turn EDR exports into client-memory notes, on the device.
 *
 * SentinelOne
 *   threats    Threats > Export (CSV): "Threat Details", "Analyst Verdict", "Hash", "Endpoints", "Site"...
 *              -> file hashes the client already triaged (false positive = benign, true positive = malicious),
 *                 plus a note on endpoints that had a true positive
 *   datalake   Singularity Data Lake / Activity export: data.agent.computer_name, data.agent.external_ip...
 *   endpoints  Endpoints (Sentinels) export: "Endpoint Name", "External IP", "Last Logged In User"...
 *              -> hostnames, the agent's egress IP, its internal IPs and the last logged-in user
 *
 * Nothing leaves the browser. Pure functions: the panel parses and previews, the service worker stores.
 */
(function (root) {
  'use strict';

  /** RFC 4180 CSV: quotes, "" escapes, commas and newlines inside quotes, CRLF. Returns array of rows. */
  function parseCsv(text) {
    const rows = [];
    let row = [], field = '', i = 0, q = false;
    text = String(text || '').replace(/^﻿/, '');
    while (i < text.length) {
      const c = text[i];
      if (q) {
        if (c === '"') { if (text[i + 1] === '"') { field += '"'; i += 2; continue; } q = false; i++; continue; }
        field += c; i++; continue;
      }
      if (c === '"' && field === '') { q = true; i++; continue; }
      if (c === ',') { row.push(field); field = ''; i++; continue; }
      if (c === '\r') { i++; continue; }
      if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; i++; continue; }
      field += c; i++;
    }
    if (field !== '' || row.length) { row.push(field); rows.push(row); }
    return rows.filter((r) => r.some((x) => x !== ''));
  }

  /** Rows -> objects keyed by header. Values are trimmed and lose the leading ' that S1 adds to stop CSV injection. */
  function toObjects(rows) {
    const head = (rows[0] || []).map((h) => h.trim());
    return rows.slice(1).map((r) => {
      const o = {};
      head.forEach((h, j) => { o[h] = String(r[j] == null ? '' : r[j]).trim().replace(/^'/, ''); });
      return o;
    });
  }

  function pick(o, names) {
    for (const n of names) if (o[n] != null && o[n] !== '') return o[n];
    return '';
  }

  const COL = {
    host: ['Endpoint Name', 'Endpoint', 'Computer Name', 'data.agent.computer_name', 'data.computer_name', 'agentComputerName'],
    extIp: ['External IP', 'External Ip', 'data.agent.external_ip', 'externalIp'],
    ifaces: ['data.agent.network_interfaces', 'Network Interfaces'],
    ipList: ['IP Addresses', 'Last Reported IP', 'Internal IP'],
    user: ['Last Logged In User', 'data.agent.last_logged_in_user_name', 'lastLoggedInUserName'],
    domain: ['Domain', 'data.agent.domain'],
    os: ['OS', 'OS Name', 'OS Version', 'data.agent.os_name'],
    site: ['Site', 'Site Name', 'data.site_name', 'site_name'],
    group: ['Group', 'Group Name', 'data.agent.group.name', 'data.group_name', 'group_name'],
    seen: ['Last Active', 'Last Seen', 'time', 'created_at', 'Time']
  };

  /** Which export is this? */
  function detect(headers) {
    const h = new Set(headers.map((x) => x.trim()));
    if (h.has('Threat Details') && h.has('Hash')) return 'threats';
    if (h.has('data.agent.computer_name')) return 'datalake';
    if (COL.host.some((c) => h.has(c)) && (COL.extIp.some((c) => h.has(c)) || COL.user.some((c) => h.has(c)) || COL.os.some((c) => h.has(c)))) return 'endpoints';
    return null;
  }

  const KIND_TEXT = { threats: 'SentinelOne threats export', datalake: 'SentinelOne Data Lake export', endpoints: 'SentinelOne endpoints export' };

  function shortPath(p) {
    const parts = String(p || '').replace(/^\\Device\\HarddiskVolume\d+/i, '').split(/[\\/]/).filter(Boolean);
    return parts.length > 3 ? '…\\' + parts.slice(-3).join('\\') : parts.join('\\');
  }

  function shortDate(s) {
    const t = Date.parse(s);
    return isNaN(t) ? String(s || '').slice(0, 12) : new Date(t).toISOString().slice(0, 10);
  }

  /** LAN / non-routable addresses only (RFC 1918, loopback, link-local, CGNAT): anything else is an egress IP. */
  function isPrivateIp(ip) {
    const o = String(ip).split('.').map(Number);
    return o[0] === 10 || o[0] === 127 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168)
      || (o[0] === 169 && o[1] === 254) || (o[0] === 100 && o[1] >= 64 && o[1] <= 127);
  }
  const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

  // ------------------------------------------------------------------ threats ---
  function fromThreats(objs, opts) {
    const byHash = new Map();
    const tpHosts = new Map();
    let skipped = 0;
    for (const o of objs) {
      const hash = (o.Hash || '').toLowerCase();
      if (!/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/.test(hash)) { skipped++; continue; }
      const verdict = /false positive/i.test(o['Analyst Verdict']) || /benign/i.test(o.Status) ? 'fp'
        : /true positive/i.test(o['Analyst Verdict']) ? 'tp' : 'open';
      const e = byHash.get(hash) || { hash, fp: 0, tp: 0, open: 0, names: new Set(), cls: new Set(), engines: new Set(), hosts: new Set(), last: '', path: '', site: '' };
      e[verdict]++;
      if (o['Threat Details']) e.names.add(o['Threat Details']);
      if (o.Classification) e.cls.add(o.Classification);
      String(o['Detecting Engine'] || '').replace(/[[\]']/g, '').split(',').map((x) => x.trim()).filter(Boolean).forEach((x) => e.engines.add(x));
      if (o.Endpoints) e.hosts.add(o.Endpoints);
      const when = o['Identifying Time (UTC)'] || o['Reported Time (UTC)'] || '';
      if (!e.last || Date.parse(when) > Date.parse(e.last)) e.last = when;
      e.path = e.path || o.Path || '';
      e.site = e.site || o.Site || '';
      byHash.set(hash, e);
      if (verdict === 'tp' && o.Endpoints) {
        const h = tpHosts.get(o.Endpoints) || { host: o.Endpoints, threats: new Set(), last: '', site: o.Site || '' };
        h.threats.add(o['Threat Details'] || hash.slice(0, 12));
        if (!h.last || Date.parse(when) > Date.parse(h.last)) h.last = when;
        tpHosts.set(o.Endpoints, h);
      }
    }
    const entries = [];
    for (const e of byHash.values()) {
      const n = e.fp + e.tp + e.open;
      const verdict = e.tp && !e.fp ? 'malicious' : e.fp && !e.tp && !e.open ? 'benign' : 'note';
      const what = e.tp && e.fp ? `mixed analyst verdicts (${e.tp} true positive, ${e.fp} false positive)`
        : e.tp ? `true positive${n > 1 ? ' ×' + n : ''}` : e.fp ? `false positive${n > 1 ? ' ×' + n : ''}` : `not triaged yet${n > 1 ? ' ×' + n : ''}`;
      const names = [...e.names].slice(0, 2).join(', ') + (e.names.size > 2 ? ` +${e.names.size - 2}` : '');
      const note = `SentinelOne ${what}: ${names}` + (e.cls.size ? ` (${[...e.cls].join('/')}${e.engines.size ? ', ' + [...e.engines].join(', ') : ''})` : '')
        + ` · ${e.hosts.size} endpoint${e.hosts.size === 1 ? '' : 's'} · last ${shortDate(e.last)}` + (e.path ? ` · ${shortPath(e.path)}` : '');
      entries.push({ kind: 'ioc', ioc: e.hash, verdict, note, client: opts.client || e.site, category: verdict === 'benign' ? 'hashBenign' : verdict === 'malicious' ? 'hashMalicious' : 'hashOther' });
    }
    for (const h of tpHosts.values()) {
      entries.push({ kind: 'host', ioc: h.host.toLowerCase(), verdict: 'note', client: opts.client || h.site, category: 'host',
        note: `SentinelOne true positive on this endpoint: ${[...h.threats].slice(0, 3).join(', ')} (last ${shortDate(h.last)})` });
    }
    return { entries, skipped };
  }

  // ------------------------------------------------------- agents (endpoints / Data Lake) ---
  function fromAgents(objs, opts) {
    const agents = new Map();
    let skipped = 0;
    for (const o of objs) {
      const host = pick(o, COL.host);
      if (!host) { skipped++; continue; }
      const a = agents.get(host.toLowerCase()) || { host, ext: '', internal: new Set(), user: '', domain: '', os: '', site: '', group: '', seen: '' };
      const seen = pick(o, COL.seen);
      const newer = !a.seen || (Date.parse(seen) || 0) >= (Date.parse(a.seen) || 0);
      const set = (k, v) => { if (v && (newer || !a[k])) a[k] = v; };
      set('ext', pick(o, COL.extIp)); set('user', pick(o, COL.user)); set('domain', pick(o, COL.domain));
      set('os', pick(o, COL.os)); set('site', pick(o, COL.site)); set('group', pick(o, COL.group));
      if (newer && seen) a.seen = seen;
      const ifaces = pick(o, COL.ifaces);
      if (ifaces) {
        try { for (const n of JSON.parse(ifaces)) for (const ip of n.inet4 || []) if (IPV4.test(ip)) a.internal.add(ip); } catch (_) { /* not JSON */ }
      }
      for (const ip of String(pick(o, COL.ipList)).split(/[\s,;]+/)) if (IPV4.test(ip) && isPrivateIp(ip)) a.internal.add(ip);
      agents.set(host.toLowerCase(), a);
    }
    const entries = [];
    for (const a of agents.values()) {
      const client = opts.client || a.site;
      const facts = [a.os, a.domain ? 'domain ' + a.domain : '', a.group ? 'group ' + a.group : '', a.user ? 'last user ' + a.user : '',
        a.ext ? 'egress ' + a.ext : '', a.internal.size ? 'LAN ' + [...a.internal].join(', ') : ''].filter(Boolean).join(' · ');
      entries.push({ kind: 'host', ioc: a.host.toLowerCase(), verdict: 'note', client, category: 'host', note: `SentinelOne agent · ${facts}` });
      if (a.ext && IPV4.test(a.ext) && !isPrivateIp(a.ext)) {
        entries.push({ kind: 'ioc', ioc: a.ext, verdict: 'note', client, category: 'egress', note: `Egress IP of ${a.host} (SentinelOne agent${a.user ? ', last user ' + a.user : ''})` });
      }
      for (const ip of a.internal) {
        entries.push({ kind: 'ioc', ioc: ip, verdict: 'note', client, category: 'lan', ttlDays: 30, note: `Internal IP of ${a.host}${a.user ? ' (last user ' + a.user + ')' : ''}` });
      }
      if (a.user && !/^(system|n\/a|-)$/i.test(a.user)) {
        entries.push({ kind: 'user', ioc: a.user.toLowerCase(), verdict: 'note', client, category: 'user', note: `Last logged-in user on ${a.host}` });
      }
    }
    return { entries, skipped };
  }

  /** Parse an export. Returns { type, label, client, entries, counts, skipped, rows } or { error }. */
  function importCsv(text, opts) {
    opts = opts || {};
    const rows = parseCsv(text);
    if (rows.length < 2) return { error: 'The file has no data rows.' };
    const type = detect(rows[0]);
    if (!type) return { error: 'Not a recognised export. Supported: SentinelOne Threats, Endpoints and Data Lake / Activity CSV exports.' };
    const objs = toObjects(rows);
    const out = type === 'threats' ? fromThreats(objs, opts) : fromAgents(objs, opts);
    // One note per (client, kind, value): the last one wins.
    const uniq = new Map();
    for (const e of out.entries) uniq.set([e.client, e.kind, e.ioc].join('|'), e);
    const entries = [...uniq.values()];
    const counts = {};
    for (const e of entries) counts[e.category] = (counts[e.category] || 0) + 1;
    const sites = [...new Set(entries.map((e) => e.client).filter(Boolean))];
    return { type, label: KIND_TEXT[type], rows: objs.length, skipped: out.skipped, entries, counts, sites };
  }

  const CATEGORY_LABEL = {
    hashBenign: 'File hashes marked false positive (benign)', hashMalicious: 'File hashes confirmed malicious', hashOther: 'File hashes not triaged / mixed',
    host: 'Endpoints (hostname, OS, last user, IPs)', egress: 'Egress IPs of endpoints', lan: 'Internal IP → hostname (valid 30 days)', user: 'Last logged-in users'
  };

  const api = { parseCsv, toObjects, detect, importCsv, CATEGORY_LABEL };
  root.VSImport = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
