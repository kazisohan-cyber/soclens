/*
 * SOCLens threat-intel: parse URL / domain feeds and match URLs against them.
 * Pure functions (no chrome.*) so the service worker and the test page share them.
 * Feeds are configured by the admin (licensed sources); nothing is bundled.
 */
(function (root) {
  'use strict';

  const HOST_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/;

  /** Canonical form used for exact URL matching: host (no www) + path (no trailing /) + query. */
  function normUrl(u) {
    try {
      const x = new URL(String(u).trim());
      if (!/^https?:$/.test(x.protocol)) return null;
      return x.hostname.toLowerCase().replace(/^www\./, '') + x.pathname.replace(/\/+$/, '') + x.search;
    } catch (_) { return null; }
  }

  /**
   * format: 'urls' (one URL per line), 'domains' (one domain per line, hosts-file style ok),
   * 'csv' (first http(s) URL found on each line). Comment lines (#, //, !) are skipped.
   */
  function parseFeed(text, format, limit) {
    const urls = [], hosts = [];
    const max = limit || 200000;
    for (let line of String(text || '').split(/\r?\n/)) {
      if (urls.length + hosts.length >= max) break;
      line = line.trim();
      if (!line || line[0] === '#' || line[0] === '!' || line.startsWith('//')) continue;
      if (format === 'csv') {
        const m = line.match(/https?:\/\/[^\s",']+/i);
        if (!m) continue;
        line = m[0];
      }
      if (format === 'domains' || !/^https?:\/\//i.test(line)) {
        const h = line.replace(/^(0\.0\.0\.0|127\.0\.0\.1)\s+/, '').split(/[\s/]/)[0].toLowerCase().replace(/^\*\./, '').replace(/\.$/, '');
        if (HOST_RE.test(h)) hosts.push(h);
        continue;
      }
      const n = normUrl(line);
      if (n) urls.push(n);
    }
    return { urls, hosts };
  }

  /** sources: { name: { urls: [], hosts: [] } } -> lookup index */
  function buildIndex(sources) {
    const urls = new Map(), hosts = new Map();
    for (const [name, s] of Object.entries(sources || {})) {
      for (const u of s.urls || []) if (!urls.has(u)) urls.set(u, name);
      for (const h of s.hosts || []) if (!hosts.has(h)) hosts.set(h, name);
    }
    return { urls, hosts, size: urls.size + hosts.size };
  }

  /** Returns { source, kind: 'url'|'host' } or null. */
  function match(idx, href) {
    if (!idx || !idx.size) return null;
    const n = normUrl(href);
    if (!n) return null;
    if (idx.urls.has(n)) return { source: idx.urls.get(n), kind: 'url' };
    const noQuery = n.split('?')[0];
    if (noQuery !== n && idx.urls.has(noQuery)) return { source: idx.urls.get(noQuery), kind: 'url' };
    let host;
    try { host = new URL(href).hostname.toLowerCase().replace(/\.$/, ''); } catch (_) { return null; }
    const labels = host.split('.');
    for (let i = 0; i < labels.length - 1; i++) {
      const h = labels.slice(i).join('.');
      if (idx.hosts.has(h)) return { source: idx.hosts.get(h), kind: 'host' };
    }
    return null;
  }

  const api = { normUrl, parseFeed, buildIndex, match };
  root.VSIntel = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
