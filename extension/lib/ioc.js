/*
 * SOCLens IOC toolkit: find indicators in text (fanged or defanged), refang/defang them,
 * classify a single value, and tell private from public IPs.
 * Pure functions (no chrome.*): shared by the service worker, the analyst panel, the page
 * highlighter and the test page.
 */
(function (root) {
  'use strict';

  // Defang tokens analysts use: [.] (.) {.} [dot] (dot) and hxxp / [:]
  const DOT = '(?:\\.|\\[\\.\\]|\\(\\.\\)|\\{\\.\\}|\\[dot\\]|\\(dot\\))';
  const LABEL = '[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?';
  const TLD = '(?:[a-z]{2,24}|xn--[a-z0-9-]{2,59})';
  const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)';

  const RE = {
    url: new RegExp('(?:https?|hxxps?|fxp|ftp)(?::\\/\\/|\\[:\\]\\/\\/|\\[:\\/\\/\\])[^\\s"\'<>`]+', 'gi'),
    email: new RegExp('[a-z0-9._%+-]+(?:@|\\[@\\]|\\(@\\)|\\[at\\])(?:' + LABEL + DOT + ')+' + TLD + '(?![a-z0-9-])', 'gi'),
    ipv4: new RegExp('(?<![\\d.])' + OCTET + '(?:' + DOT + OCTET + '){3}(?:\\/(?:3[0-2]|[12]?\\d))?(?![\\d]|\\.\\d)', 'g'),
    ipv6: /(?<![0-9a-f:])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])/gi,
    sha256: /(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])/gi,
    sha1: /(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])/gi,
    md5: /(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])/gi,
    cve: /\bCVE-\d{4}-\d{4,7}\b/gi,
    domain: new RegExp('(?<![a-z0-9@._-])(?:' + LABEL + DOT + ')+' + TLD + '(?![a-z0-9-]|' + DOT + '[a-z0-9])', 'gi')
  };
  const ORDER = ['url', 'email', 'ipv4', 'ipv6', 'sha256', 'sha1', 'md5', 'cve', 'domain'];

  // In "strict" mode (auto-highlighting pages) these look like file names or code, not domains.
  const FILE_LIKE = new Set(['js', 'ts', 'css', 'html', 'htm', 'php', 'asp', 'aspx', 'jsp', 'json', 'xml', 'yml', 'yaml',
    'txt', 'log', 'csv', 'md', 'py', 'rb', 'pl', 'sh', 'ps', 'ps1', 'psm1', 'bat', 'cmd', 'vbs', 'exe', 'dll', 'sys', 'msi',
    'bin', 'dat', 'tmp', 'ini', 'cfg', 'conf', 'lnk', 'jpg', 'jpeg', 'png', 'gif', 'svg', 'ico', 'bmp', 'webp', 'pdf', 'doc',
    'docx', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'rtf', 'odt', 'zip', 'rar', '7z', 'gz', 'tar', 'tgz', 'iso', 'img', 'vhd',
    'vhdx', 'mov', 'mp3', 'mp4', 'avi', 'wav', 'java', 'class', 'jar', 'cs', 'go', 'rs', 'cpp', 'hpp', 'lua', 'sql', 'db',
    'sqlite', 'bak', 'old', 'eml', 'msg', 'pst', 'ost', 'evtx', 'pcap', 'pcapng', 'local', 'internal', 'lan', 'corp', 'home',
    'localdomain', 'arpa', 'example', 'invalid', 'test', 'name', 'map', 'min', 'prototype', 'length', 'value', 'id', 'to']);
  // ...unless the "file name" is clearly a host (www., several labels, common SaaS words).
  const COMMON_TLD = new Set(['com', 'net', 'org', 'io', 'co', 'ai', 'app', 'dev', 'info', 'biz', 'xyz', 'top', 'online',
    'site', 'shop', 'store', 'club', 'live', 'click', 'link', 'cloud', 'tech', 'pro', 'me', 'us', 'uk', 'my', 'sg', 'au',
    'in', 'id', 'hk', 'jp', 'de', 'fr', 'ru', 'cn', 'br', 'nl', 'eu', 'gov', 'edu', 'mil', 'int', 'sbs', 'icu', 'cfd',
    'buzz', 'work', 'support', 'help', 'services', 'digital', 'email', 'run', 'page', 'website', 'space', 'fun', 'cc', 'tk',
    'ml', 'ga', 'cf', 'gq', 'ws', 'tv', 'gg', 'ly', 'su', 'kr', 'tw', 'th', 'vn', 'ph', 'nz', 'ca', 'mx', 'es', 'it',
    'pl', 'ch', 'se', 'no', 'fi', 'dk', 'be', 'at', 'cz', 'tr', 'ir', 'ua', 'za', 'ng', 'ke', 'ae', 'sa', 'pk', 'bd']);

  function refang(s) {
    return String(s == null ? '' : s).trim()
      .replace(/^hxxp/i, 'http').replace(/^fxp/i, 'ftp')
      .replace(/\[:\]\/\//g, '://').replace(/\[:\/\/\]/g, '://')
      .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.')
      .replace(/\[@\]|\(@\)|\[at\]/gi, '@')
      .replace(/\[:\]/g, ':');
  }

  function defang(value, type) {
    const v = String(value || '');
    if (!v) return v;
    type = type || classify(v).type;
    if (type === 'url') {
      return v.replace(/^http/i, 'hxxp').replace(/^ftp/i, 'fxp').replace(/^(\w+:\/\/)([^/?#]+)/, (m, s, h) => s.replace('://', '[://]') + h.replace(/\./g, '[.]'));
    }
    if (type === 'domain' || type === 'ipv4') return v.replace(/\./g, '[.]');
    if (type === 'ipv6') return v.replace(/:/g, '[:]');
    if (type === 'email') return v.replace('@', '[@]').replace(/\.(?=[^@]*$)/g, '[.]');
    return v;
  }

  function trimUrl(u) {
    // Trailing punctuation from prose / markdown, and unbalanced closing brackets.
    let s = u.replace(/[.,;:!?'"»”’]+$/, '');
    for (const [o, c] of [['(', ')'], ['[', ']'], ['{', '}']]) {
      while (s.endsWith(c) && (s.split(o).length < s.split(c).length)) s = s.slice(0, -1);
    }
    return s.replace(/[.,;:!?]+$/, '');
  }

  function validIpv6(s) {
    if (!s.includes('::') && s.split(':').length !== 8) return false;
    if (/^\d{1,2}:\d{2}(:\d{2})?$/.test(s)) return false;            // clock time
    if (/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(s)) return false;       // MAC address
    if (!/[0-9a-f]/i.test(s.replace(/:/g, '')) && s !== '::') return false;
    try { return new URL('http://[' + s + ']/').hostname.length > 2; } catch (_) { return false; }
  }

  function tldOf(domain) { const p = domain.split('.'); return p[p.length - 1]; }

  function plausibleDomain(d, strict) {
    const labels = d.split('.');
    if (labels.length < 2 || d.length > 253) return false;
    const tld = tldOf(d);
    if (/^\d+$/.test(tld)) return false;
    if (!strict) return true;
    if (FILE_LIKE.has(tld) && !(labels.length >= 3 && (labels[0] === 'www' || COMMON_TLD.has(labels[labels.length - 2])))) return false;
    // Unknown long TLDs in prose (e.g. "object.property") only when it otherwise looks like a host.
    if (!COMMON_TLD.has(tld) && tld.length > 2 && !tld.startsWith('xn--') && labels.length < 3) return false;
    if (labels.every((l) => /^[a-z]+$/i.test(l)) && labels.length === 2 && labels[0].length <= 2 && !COMMON_TLD.has(tld)) return false;
    return true;
  }

  function isPrivateIp(ip) {
    ip = String(ip || '').split('/')[0];
    if (ip.includes(':')) {
      const s = ip.toLowerCase();
      return s === '::1' || s === '::' || /^f[cd]/.test(s) || /^fe[89ab]/.test(s) || s.startsWith('::ffff:10.') || s.startsWith('::ffff:192.168.');
    }
    const o = ip.split('.').map(Number);
    if (o.length !== 4 || o.some((n) => isNaN(n))) return false;
    return o[0] === 10 || o[0] === 127 || o[0] === 0 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168)
      || (o[0] === 169 && o[1] === 254) || (o[0] === 100 && o[1] >= 64 && o[1] <= 127) || o[0] >= 224
      || (o[0] === 192 && o[1] === 0 && o[2] === 2) || (o[0] === 198 && o[1] === 51 && o[2] === 100) || (o[0] === 203 && o[1] === 0 && o[2] === 113)
      || (o[0] === 198 && (o[1] === 18 || o[1] === 19));
  }

  const GROUP = { url: 'url', domain: 'domain', ipv4: 'ip', ipv6: 'ip', email: 'email', md5: 'hash', sha1: 'hash', sha256: 'hash', cve: 'cve' };
  const LABEL_OF = { url: 'URL', domain: 'Domain', ipv4: 'IPv4', ipv6: 'IPv6', email: 'Email', md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', cve: 'CVE' };

  function normalize(type, raw) {
    let v = refang(raw);
    if (type === 'url') v = trimUrl(v);
    if (type === 'ipv4') v = v.split('/')[0];
    if (type === 'domain' || type === 'email') v = v.toLowerCase().replace(/\.$/, '');
    if (type === 'md5' || type === 'sha1' || type === 'sha256' || type === 'ipv6') v = v.toLowerCase();
    if (type === 'cve') v = v.toUpperCase();
    return v;
  }

  /**
   * Find IOCs in text. Returns [{ type, group, value, raw, start, end }] in text order,
   * non-overlapping, earlier ORDER types win (a URL hides the domain inside it).
   * opts.strict: page highlighting mode (fewer false positives).
   */
  function extract(text, opts) {
    const strict = !!(opts && opts.strict);
    const max = (opts && opts.max) || 500;
    text = String(text || '');
    const taken = [];
    const out = [];
    const overlaps = (s, e) => taken.some(([a, b]) => s < b && e > a);
    for (const type of ORDER) {
      const re = RE[type];
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(text)) && out.length < max) {
        let raw = m[0];
        if (type === 'url') raw = trimUrl(raw);
        const start = m.index, end = m.index + raw.length;
        if (!raw || overlaps(start, end)) continue;
        const value = normalize(type, raw);
        if (type === 'ipv6' && !validIpv6(value)) continue;
        if (type === 'domain' && !plausibleDomain(value, strict)) continue;
        if (strict && (type === 'md5' || type === 'sha1' || type === 'sha256') && (/^\d+$/.test(value) || /^[a-f]+$/.test(value))) continue;
        if (type === 'url') { try { new URL(value); } catch (_) { continue; } }
        taken.push([start, end]);
        out.push({ type, group: GROUP[type], value, raw, start, end });
      }
    }
    return out.sort((a, b) => a.start - b.start);
  }

  /** Unique IOCs (by value) from free text, in first-seen order. */
  function unique(text, opts) {
    const seen = new Set();
    return extract(text, opts).filter((x) => !seen.has(x.type + '|' + x.value) && seen.add(x.type + '|' + x.value));
  }

  /** Classify a single typed / pasted value. Returns { type, group, value } (type 'unknown' if none). */
  function classify(input) {
    const s = refang(input);
    if (!s) return { type: 'unknown', group: 'unknown', value: '' };
    const all = extract(s, { strict: false });
    const whole = all.find((x) => x.start === 0 && x.end >= s.replace(/[.,;]+$/, '').length);
    if (whole) return { type: whole.type, group: whole.group, value: whole.value };
    if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(s)) return { type: 'domain', group: 'domain', value: s.toLowerCase() };
    return { type: 'unknown', group: 'unknown', value: s };
  }

  /** Registrable-ish domain of a URL / email / domain (for domain-level lookups). */
  function domainOf(type, value) {
    if (type === 'url') { try { return new URL(value).hostname.toLowerCase(); } catch (_) { return ''; } }
    if (type === 'email') return value.split('@')[1] || '';
    if (type === 'domain') return value;
    return '';
  }

  function ipInCidr(ip, cidr) {
    if (!ip || !cidr || ip.includes(':') || cidr.includes(':')) return ip === cidr;
    const [net, bitsS] = cidr.split('/');
    const bits = bitsS == null ? 32 : Number(bitsS);
    const toInt = (a) => a.split('.').reduce((n, o) => (n << 8) + Number(o), 0) >>> 0;
    if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip) || !/^\d+\.\d+\.\d+\.\d+$/.test(net) || !(bits >= 0 && bits <= 32)) return false;
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (toInt(ip) & mask) === (toInt(net) & mask);
  }

  const api = { extract, unique, classify, refang, defang, isPrivateIp, domainOf, ipInCidr, GROUP, LABEL_OF };
  root.VSIoc = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
