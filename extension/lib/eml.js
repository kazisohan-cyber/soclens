/*
 * IOC Triage phishing triage: reads a reported .eml file on the device. Nothing is sent and the email is never
 * rendered: HTML goes through an inert DOMParser document only to read its links, so scripts do not run and
 * remote images do not load. Everything in the file is attacker-controlled and is treated as data.
 * Uses VSHeaders, VSIoc and VSAnalyzer.
 */
(function (root) {
  'use strict';
  const MAX_PARTS = 200;
  const MAX_DEPTH = 8;
  const MAX_URLS = 100;
  const RISKY = new Set(['exe', 'scr', 'com', 'bat', 'cmd', 'pif', 'msi', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'hta', 'ps1', 'lnk', 'iso', 'img', 'vhd', 'vhdx', 'one', 'jar', 'cpl', 'dll', 'reg',
    'html', 'htm', 'shtml', 'xhtml', 'svg', 'docm', 'dotm', 'xlsm', 'xltm', 'xlam', 'pptm', 'ppam']);
  const DOC = /\.(pdf|docx?|xlsx?|pptx?|txt|rtf|csv|jpe?g|png|gif)\.[a-z0-9]{1,5}$/i;

  const latin1 = (bytes) => { let s = ''; for (let i = 0; i < bytes.length; i += 32768) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 32768)); return s; };
  const toBytes = (s) => { const b = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i) & 255; return b; };

  function decodeCharset(bytes, charset) {
    for (const cs of [charset, 'utf-8', 'latin1']) {
      if (!cs) continue;
      try { return new TextDecoder(cs).decode(bytes); } catch (_) { /* unknown charset */ }
    }
    return latin1(bytes);
  }

  function fromBase64(s) {
    const clean = s.replace(/[^A-Za-z0-9+/]/g, '');
    // atob accepts missing padding; one leftover character can never be valid.
    try { return toBytes(atob(clean.length % 4 === 1 ? clean.slice(0, -1) : clean)); } catch (_) { return new Uint8Array(0); }
  }
  function fromQuotedPrintable(s) {
    return toBytes(s.replace(/=\r?\n/g, '').replace(/=([0-9a-f]{2})/gi, (_, h) => String.fromCharCode(parseInt(h, 16))));
  }

  /** RFC 2047: =?utf-8?B?...?= in subjects, names and file names. */
  function decodeWords(v) {
    return String(v || '').replace(/(\?=)\s+(=\?)/g, '$1$2').replace(/=\?([^?\s]+)\?([bq])\?([^?]*)\?=/gi, (all, cs, enc, data) => {
      const bytes = /b/i.test(enc) ? fromBase64(data) : fromQuotedPrintable(data.replace(/_/g, ' '));
      return decodeCharset(bytes, cs);
    });
  }

  function splitHead(s) {
    const m = s.match(/\r?\n\r?\n/);
    return m ? [s.slice(0, m.index), s.slice(m.index + m[0].length)] : [s, ''];
  }
  function headerMap(head) {
    const out = {};
    for (const line of head.replace(/\r\n/g, '\n').replace(/\n[ \t]+/g, ' ').split('\n')) {
      const m = line.match(/^([!-9;-~]+):\s*(.*)$/);
      if (m && !(m[1].toLowerCase() in out)) out[m[1].toLowerCase()] = m[2].trim();
    }
    return out;
  }
  /** "text/plain; charset=utf-8" to { value, params }. RFC 2231 file names (filename*=) are decoded. */
  function headerParams(v) {
    const parts = String(v || '').match(/(?:[^;"]|"[^"]*")+/g) || [''];
    const params = {};
    for (const p of parts.slice(1)) {
      const i = p.indexOf('=');
      if (i < 0) continue;
      let k = p.slice(0, i).trim().toLowerCase();
      let val = p.slice(i + 1).trim().replace(/^"|"$/g, '');
      if (k.endsWith('*')) {
        k = k.slice(0, -1);
        const m = val.match(/^([^']*)'[^']*'(.*)$/);
        try { val = m ? decodeURIComponent(m[2]) : decodeURIComponent(val); } catch (_) { /* keep raw */ }
      }
      params[k] = val;
    }
    return { value: parts[0].trim().toLowerCase(), params };
  }

  function walk(raw, depth, out) {
    if (out.length >= MAX_PARTS) return;
    const [head, body] = splitHead(raw);
    const h = headerMap(head);
    const ct = headerParams(h['content-type'] || 'text/plain');
    const cd = headerParams(h['content-disposition'] || '');
    if (ct.value.startsWith('multipart/') && ct.params.boundary && depth < MAX_DEPTH) {
      const mark = '--' + ct.params.boundary;
      const chunks = ('\n' + body).split(new RegExp('\\r?\\n' + mark.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '(?:--)?[ \\t]*(?=\\r?\\n|$)'));
      for (const c of chunks.slice(1)) {
        const part = c.replace(/^\r?\n/, '');
        if (part.trim()) walk(part, depth + 1, out);
      }
      return;
    }
    const enc = (h['content-transfer-encoding'] || '').trim().toLowerCase();
    const bytes = enc === 'base64' ? fromBase64(body) : enc === 'quoted-printable' ? fromQuotedPrintable(body) : toBytes(body);
    out.push({ type: ct.value, charset: ct.params.charset, disposition: cd.value, inline: cd.value === 'inline', contentId: !!h['content-id'],
      filename: decodeWords(cd.params.filename || ct.params.name || ''), bytes });
  }

  /** Splits a raw message into its header block and decoded parts. */
  function parse(bytes) {
    const raw = latin1(bytes);
    const [head] = splitHead(raw);
    const parts = [];
    walk(raw, 0, parts);
    return { headers: head, parts };
  }

  async function sha256(bytes) {
    const d = await crypto.subtle.digest('SHA-256', bytes);
    return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
  }

  function attachmentFlags(name, bytes) {
    const flags = [];
    const low = name.toLowerCase();
    const ext = (low.match(/\.([a-z0-9]{1,6})$/) || [])[1] || '';
    if (DOC.test(low) && RISKY.has(ext)) flags.push('Double extension hides the real file type');
    else if (RISKY.has(ext)) flags.push(/^(html?|shtml|xhtml|svg)$/.test(ext) ? 'HTML or SVG file: often a fake login page opened from disk' : /m$|ppam|xlam/.test(ext) ? 'Office file that can run macros' : `Runs or mounts on open (.${ext})`);
    if (bytes[0] === 0x4d && bytes[1] === 0x5a && !/^(exe|dll|scr|com|cpl|msi)$/.test(ext)) flags.push('Windows program disguised with another extension');
    return flags;
  }

  function hrefsFromHtml(html) {
    if (!root.DOMParser) return [];
    const doc = new root.DOMParser().parseFromString(html, 'text/html');
    return [...doc.querySelectorAll('a[href], area[href]')].map((a) => ({ href: a.getAttribute('href') || '', text: (a.textContent || '').trim().slice(0, 200) }));
  }

  function linkFacts(url, text) {
    const A = root.VSAnalyzer, I = root.VSIoc;
    const real = A ? A.unwrapUrl(url) : url;
    const host = (I && I.domainOf('url', real)) || '';
    const v = A && host ? A.analyzeUrl(real, {}) : null;
    const shown = I && text ? I.classify(text.replace(/\s+/g, '')) : { type: 'unknown' };
    const shownHost = shown.group === 'url' || shown.group === 'domain' ? I.domainOf(shown.type, shown.value) : '';
    const mismatch = !!(shownHost && host && A && A.registrableDomain(shownHost) !== A.registrableDomain(host));
    return { url, real, text, host, mismatch, level: v ? v.level : 'safe', reasons: v && !v.allow && v.level !== 'safe' ? v.reasons.slice(0, 2) : [] };
  }

  /** The whole triage. bytes: Uint8Array of the .eml file. */
  async function analyze(bytes) {
    const I = root.VSIoc, HD = root.VSHeaders;
    const { headers, parts } = parse(bytes);
    const head = HD.analyze(decodeWords(headers));
    if (!head.ok) return { ok: false, error: 'This does not look like an email file. Save the message as .eml and try again.' };
    const found = new Map();
    const addLink = (href, text) => {
      const u = String(href || '').trim();
      if (!/^https?:\/\//i.test(u) || found.has(u) || found.size >= MAX_URLS) return;
      found.set(u, linkFacts(u, text));
    };
    const attachments = [];
    for (const p of parts) {
      const isBody = !p.filename && p.disposition !== 'attachment' && /^text\/(plain|html)$/.test(p.type);
      if (isBody) {
        const text = decodeCharset(p.bytes, p.charset);
        if (p.type === 'text/html') hrefsFromHtml(text).forEach((a) => addLink(a.href, a.text));
        else if (I) I.extract(text).filter((x) => x.group === 'url').forEach((x) => addLink(x.value, ''));
        continue;
      }
      if (p.inline && p.contentId && p.type.startsWith('image/')) continue; // signature logos and the like
      const name = p.filename || '(no file name)';
      attachments.push({ name, type: p.type, size: p.bytes.length, sha256: await sha256(p.bytes), flags: attachmentFlags(name, p.bytes) });
    }
    const urls = [...found.values()];
    const reasons = [];
    for (const a of attachments) for (const f of a.flags) reasons.push({ kind: 'bad', t: `${a.name}: ${f}` });
    const mism = urls.filter((u) => u.mismatch);
    if (mism.length) reasons.push({ kind: 'bad', t: `Link text shows ${mism[0].text} but goes to ${mism[0].host}${mism.length > 1 ? ` (and ${mism.length - 1} more)` : ''}` });
    const risky = urls.filter((u) => u.level === 'warn' || u.level === 'block');
    for (const u of risky.slice(0, 3)) reasons.push({ kind: 'bad', t: `Link to ${u.host}: ${u.reasons.join('; ') || 'suspicious'}` });

    const signals = reasons.length > 0;
    const strong = urls.some((u) => u.level === 'block') || attachments.some((a) => a.flags.length) && head.verdict !== 'benign';
    const verdict = head.verdict === 'malicious' || strong || (signals && head.verdict === 'suspicious') ? 'malicious' : signals ? 'suspicious' : head.verdict;

    const iocs = [];
    const push = (value) => { if (value && !iocs.includes(value)) iocs.push(value); };
    attachments.forEach((a) => push(a.sha256));
    urls.slice().sort((x, y) => (y.level === 'block') - (x.level === 'block')).slice(0, 12).forEach((u) => push(u.real));
    head.iocs.forEach((x) => push(x.value));
    return { ok: true, verdict, reasons, head, attachments, urls, iocs, subject: head.summary.subject };
  }

  /** A short answer for the person who reported the email. */
  function replyTemplate(verdict, opts) {
    opts = opts || {};
    const subject = opts.subject ? ` ("${opts.subject}")` : '';
    const sign = `\n\nThanks for reporting it,\n${opts.analyst || '[Name]'}`;
    if (verdict === 'malicious') return `Hi [Name],\n\nThe email you reported${subject} is a phishing attempt. Please do not click its links or open its attachments, and delete it.\n\nIf you already clicked a link, entered a password or opened an attachment, tell us straight away and change that password. Reporting early is the right thing to do, so you will not be in any trouble.${sign}`;
    if (verdict === 'suspicious') return `Hi [Name],\n\nThe email you reported${subject} looks suspicious and we are still checking it. Please do not click its links or open its attachments until you hear from us.\n\nIf you already did, tell us straight away.${sign}`;
    return `Hi [Name],\n\nWe checked the email you reported${subject} and found no signs of phishing. It looks safe to treat as normal mail. If anything about it still seems wrong, for example an unexpected request for money or a password, confirm with the sender by phone.${sign}`;
  }

  /** Plain-text findings for the ticket. */
  function findings(r) {
    const I = root.VSIoc;
    const a = r.head.auth;
    const t = [`Reported email: ${r.verdict.toUpperCase()}`, `Subject: ${r.subject || '(none)'}`, `From: ${r.head.summary.from}`, `SPF ${a.spf || 'n/a'} · DKIM ${a.dkim || 'n/a'} · DMARC ${a.dmarc || 'n/a'}`];
    if (r.head.origin) t.push(`Originating IP: ${I.defang(r.head.origin)}`);
    for (const x of r.head.reasons.concat(r.reasons)) if (x.kind === 'bad') t.push(`- ${x.t}`);
    if (r.attachments.length) { t.push('', 'Attachments:'); r.attachments.forEach((x) => t.push(`- ${x.name} (${x.size} bytes) SHA-256 ${x.sha256}`)); }
    if (r.urls.length) { t.push('', 'Links:'); r.urls.slice(0, 20).forEach((u) => t.push(`- ${I.defang(u.real, 'url')}`)); }
    t.push('', '(Links defanged. Checked on the device by IOC Triage; verify before acting.)');
    return t.join('\n');
  }

  const api = { parse, analyze, decodeWords, replyTemplate, findings };
  root.VSEml = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
