/*
 * IOC Triage analyzer — pure, dependency-free URL / domain / email heuristics.
 * Loaded by the service worker (importScripts), content scripts, and the test page.
 * No network, no chrome.* calls: everything here is deterministic and testable.
 */
(function (root) {
  'use strict';

  // ---------------------------------------------------------------- data ---

  // Multi-label public suffixes we care about (APAC heavy) + hosting platforms
  // where every subdomain is a different owner. Not a full PSL — kept small on purpose.
  const MULTI_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
    'com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg',
    'co.id', 'or.id', 'go.id', 'ac.id', 'web.id', 'my.id',
    'com.bd', 'net.bd', 'org.bd', 'gov.bd', 'edu.bd', 'ac.bd',
    'co.th', 'or.th', 'go.th', 'ac.th', 'in.th',
    'com.tw', 'org.tw', 'gov.tw', 'edu.tw', 'net.tw',
    'com.hk', 'org.hk', 'gov.hk', 'edu.hk', 'net.hk',
    'co.in', 'net.in', 'org.in', 'gov.in', 'ac.in', 'firm.in',
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
    'co.kr', 'or.kr', 'go.kr', 'com.cn', 'net.cn', 'org.cn', 'gov.cn',
    'com.ph', 'net.ph', 'gov.ph', 'com.vn', 'net.vn', 'gov.vn',
    'co.nz', 'org.nz', 'com.pk', 'net.pk', 'gov.pk', 'com.lk', 'com.np',
    'com.br', 'co.za', 'com.mx', 'com.tr', 'com.ng', 'com.sa', 'com.eg', 'co.ae'
  ]);

  // Free / instant hosting — every subdomain is someone else. Abused heavily for phishing.
  const FREE_HOSTING = [
    'pages.dev', 'workers.dev', 'r2.dev', 'trycloudflare.com',
    'web.app', 'firebaseapp.com', 'appspot.com',
    'netlify.app', 'vercel.app', 'onrender.com', 'herokuapp.com', 'fly.dev', 'railway.app',
    'glitch.me', 'repl.co', 'replit.app', 'replit.dev', 'codesandbox.io', 'csb.app', 'stackblitz.io',
    'ngrok.io', 'ngrok-free.app', 'ngrok.app', 'loca.lt', 'serveo.net',
    'github.io', 'gitlab.io', 'framer.app', 'framer.website', 'webflow.io', 'carrd.co',
    '000webhostapp.com', 'wixsite.com', 'weebly.com', 'square.site', 'godaddysites.com',
    'myshopify.com', 'blogspot.com', 'wordpress.com', 'azurewebsites.net', 'azurestaticapps.net',
    'web.core.windows.net', 'cloudfront.net', 's3.amazonaws.com', 'amplifyapp.com',
    'surge.sh', 'tiiny.site', 'yolasite.com', 'jimdosite.com', 'mystrikingly.com', 'ipfs.io',
    'dweb.link', 'w3s.link', 'fleek.co', 'on.fleek.co'
  ];

  const SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
    'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc', 'bl.ink', 's.id', 'lnkd.in', 'qrco.de'
  ]);

  const RISKY_TLDS = new Set([
    'zip', 'mov', 'xyz', 'top', 'click', 'country', 'gq', 'tk', 'ml', 'cf', 'ga', 'rest',
    'cam', 'icu', 'sbs', 'cfd', 'lol', 'quest', 'buzz', 'monster', 'bond', 'cyou', 'beauty',
    'hair', 'skin', 'makeup', 'autos', 'boats', 'yachts', 'mom', 'live', 'shop', 'online',
    'site', 'website', 'store', 'fun', 'space', 'pw', 'cc', 'ws', 'win', 'bid', 'loan',
    'work', 'party', 'review', 'date', 'racing', 'download', 'stream', 'gdn', 'kim', 'men'
  ]);

  // Brands commonly impersonated. `labels` = registrable labels used for lookalike checks,
  // `keywords` = tokens that signal the brand in a hostname / page, `domains` = legit domains.
  const BRANDS = [
    { name: 'Microsoft', labels: ['microsoft', 'microsoftonline', 'office365', 'outlook', 'onedrive', 'sharepoint'],
      keywords: ['microsoft', 'microsoftonline', 'office365', 'microsoft365', 'outlook', 'onedrive', 'sharepoint', 'hotmail', 'msonline', 'azuread', 'entra'],
      pageTerms: ['microsoft', 'office 365', 'office365', 'microsoft 365', 'outlook', 'onedrive', 'sharepoint', 'sign in to your account'],
      domains: ['microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'office365.com', 'outlook.com', 'sharepoint.com',
        'onedrive.com', 'onedrive.live.com', 'microsoft365.com', 'cloud.microsoft', 'azure.com', 'windows.net', 'msauth.net', 'msftauth.net',
        'aka.ms', 'bing.com', 'skype.com', 'msn.com', 'xbox.com', 'hotmail.com', 'onenote.com', 'msidentity.com', 'microsoftonline-p.com',
        'sharepointonline.com', 'office.net', 'microsoft.net', 'windowsazure.com', 'azureedge.net', 'live.net', 'msecnd.net', 'gfx.ms'] },
    { name: 'Google', labels: ['google', 'gmail', 'youtube'],
      keywords: ['google', 'gmail', 'gdrive', 'googledrive', 'googledocs'],
      pageTerms: ['google', 'gmail', 'google drive', 'google docs'],
      domains: ['google.com', 'gmail.com', 'youtube.com', 'googleusercontent.com', 'gstatic.com', 'googleapis.com', 'google.com.my',
        'google.com.sg', 'google.co.id', 'google.com.bd', 'google.co.th', 'google.com.tw', 'google.com.hk', 'google.co.in', 'withgoogle.com', 'goo.gl', 'g.co', 'youtu.be', 'google.co.uk'] },
    { name: 'Apple', labels: ['apple', 'icloud', 'appleid'],
      keywords: ['apple', 'icloud', 'appleid', 'itunes'],
      pageTerms: ['apple id', 'icloud', 'apple account'],
      domains: ['apple.com', 'icloud.com', 'me.com', 'mzstatic.com', 'apple.news'] },
    { name: 'PayPal', labels: ['paypal'], keywords: ['paypal'], pageTerms: ['paypal'],
      domains: ['paypal.com', 'paypalobjects.com', 'paypal.me'] },
    { name: 'Amazon', labels: ['amazon', 'aws'], keywords: ['amazon', 'awsconsole'], pageTerms: ['amazon', 'aws management console'],
      domains: ['amazon.com', 'amazon.co.uk', 'amazon.sg', 'amazon.in', 'amazon.co.jp', 'amazon.com.au', 'aws.amazon.com', 'amazonaws.com', 'awsstatic.com', 'media-amazon.com'] },
    { name: 'DocuSign', labels: ['docusign'], keywords: ['docusign'], pageTerms: ['docusign'],
      domains: ['docusign.com', 'docusign.net'] },
    { name: 'Dropbox', labels: ['dropbox'], keywords: ['dropbox'], pageTerms: ['dropbox'],
      domains: ['dropbox.com', 'dropboxusercontent.com', 'db.tt'] },
    { name: 'Adobe', labels: ['adobe'], keywords: ['adobe', 'adobesign', 'acrobat'], pageTerms: ['adobe', 'adobe sign', 'adobe acrobat'],
      domains: ['adobe.com', 'adobesign.com', 'adobelogin.com', 'acrobat.com', 'echosign.com', 'adobe.io'] },
    { name: 'DHL', labels: ['dhl'], keywords: ['dhl'], pageTerms: ['dhl express'],
      domains: ['dhl.com', 'dhl.de', 'dhl.com.my', 'dhl.com.sg', 'dhl.co.id'] },
    { name: 'FedEx', labels: ['fedex'], keywords: ['fedex'], pageTerms: ['fedex'], domains: ['fedex.com'] },
    { name: 'LinkedIn', labels: ['linkedin'], keywords: ['linkedin'], pageTerms: ['linkedin'], domains: ['linkedin.com', 'licdn.com', 'lnkd.in'] },
    { name: 'Facebook', labels: ['facebook', 'meta', 'instagram', 'whatsapp'], keywords: ['facebook', 'instagram', 'whatsapp', 'metabusiness'],
      pageTerms: ['facebook', 'instagram', 'whatsapp', 'meta business'],
      domains: ['facebook.com', 'fb.com', 'meta.com', 'instagram.com', 'whatsapp.com', 'whatsapp.net', 'fbcdn.net', 'messenger.com', 'cdninstagram.com'] },
    { name: 'Netflix', labels: ['netflix'], keywords: ['netflix'], pageTerms: ['netflix'], domains: ['netflix.com', 'nflxext.com'] },
    { name: 'Okta', labels: ['okta'], keywords: ['okta'], pageTerms: ['okta'], domains: ['okta.com', 'oktacdn.com', 'okta-emea.com', 'oktapreview.com'] },
    { name: 'Zoom', labels: ['zoom'], keywords: ['zoomus'], pageTerms: ['zoom meeting'], domains: ['zoom.us', 'zoom.com', 'zoomgov.com'] },
    { name: 'Wise', labels: ['wise', 'transferwise'], keywords: ['transferwise'], pageTerms: ['wise account'], domains: ['wise.com', 'transferwise.com'] },
    { name: 'Maybank', labels: ['maybank', 'maybank2u'], keywords: ['maybank', 'maybank2u'], pageTerms: ['maybank', 'maybank2u'],
      domains: ['maybank.com', 'maybank2u.com.my', 'maybank.com.sg', 'maybank.co.id', 'maybank2e.com'] },
    { name: 'CIMB', labels: ['cimb', 'cimbclicks'], keywords: ['cimb', 'cimbclicks', 'octo'], pageTerms: ['cimb clicks', 'cimb octo', 'cimb bank'],
      domains: ['cimb.com', 'cimbclicks.com.my', 'cimb.com.my', 'cimb.com.sg', 'cimbniaga.co.id', 'cimbthai.com'] },
    { name: 'DBS', labels: ['dbs', 'posb'], keywords: ['dbs', 'posb', 'paylah'], pageTerms: ['dbs ibanking', 'digibank', 'posb'],
      domains: ['dbs.com', 'dbs.com.sg', 'dbs.com.hk', 'dbs.com.tw', 'dbs.id', 'posb.com.sg'] },
    { name: 'OCBC', labels: ['ocbc'], keywords: ['ocbc'], pageTerms: ['ocbc'], domains: ['ocbc.com', 'ocbc.com.my', 'ocbc.id'] },
    { name: 'UOB', labels: ['uob', 'uobgroup'], keywords: ['uob', 'uobgroup'], pageTerms: ['uob infinity', 'uob personal internet banking'],
      domains: ['uob.com.sg', 'uobgroup.com', 'uob.com.my', 'uob.co.id', 'uob.co.th', 'uob.com'] },
    { name: 'bKash', labels: ['bkash'], keywords: ['bkash'], pageTerms: ['bkash'], domains: ['bkash.com'] },
    { name: 'Binance', labels: ['binance'], keywords: ['binance'], pageTerms: ['binance'], domains: ['binance.com', 'binance.us'] },
    { name: 'Coinbase', labels: ['coinbase'], keywords: ['coinbase'], pageTerms: ['coinbase'], domains: ['coinbase.com'] },
    { name: 'Steam', labels: ['steampowered', 'steamcommunity'], keywords: ['steampowered', 'steamcommunity'], pageTerms: ['steam community'],
      domains: ['steampowered.com', 'steamcommunity.com', 'steamstatic.com'] }
  ];

  // Confusable characters -> Latin skeleton.
  const HOMOGLYPHS = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ԛ': 'q', 'ѕ': 's', 'ԝ': 'w',
    'һ': 'h', 'ӏ': 'l', 'ԁ': 'd', 'ɡ': 'g', 'ν': 'v', 'ο': 'o', 'α': 'a', 'ε': 'e', 'τ': 't', 'ι': 'i', 'κ': 'k', 'ρ': 'p',
    'υ': 'u', 'ω': 'w', 'ℓ': 'l', 'ı': 'i', 'ɩ': 'i', 'ǀ': 'l', 'ꞁ': 'l', 'ꮃ': 'w', 'ᴠ': 'v', 'ѵ': 'v', 'ɑ': 'a', 'ɒ': 'a',
    'Ь': 'b', 'ь': 'b', 'п': 'n', 'т': 't', 'м': 'm', 'к': 'k', 'в': 'b', 'н': 'h', 'г': 'r', 'ԍ': 'g', 'ɢ': 'g', 'ʀ': 'r'
  };

  // Look-alike ASCII sequences used in typosquats (applied after lowercasing).
  const ASCII_CONFUSABLES = [['rn', 'm'], ['vv', 'w'], ['cl', 'd'], ['0', 'o'], ['1', 'l'], ['3', 'e'], ['4', 'a'], ['5', 's'], ['7', 't'], ['8', 'b'], ['@', 'a'], ['$', 's']];

  const PHISH_PHRASES = [
    // English
    /verify (your|the) (account|identity|email|mailbox)/i, /confirm (your|the) (identity|account|password|details)/i,
    /(account|mailbox|access) (will be|has been|is) (suspended|disabled|locked|terminated|deactivated|closed|restricted)/i,
    /unusual (sign[- ]?in|login|activity)/i, /password (will )?expires?/i, /(mailbox|storage) (is )?(full|almost full|quota)/i,
    /within (24|48|12) hours/i, /(immediately|urgent(ly)?|action required|final (notice|warning))/i,
    /update (your )?(payment|billing|bank) (details|information|method)/i, /payment (failed|declined|was unsuccessful)/i,
    /(shared|sent) (a|an) (document|file|invoice|pdf) with you/i, /(view|review|sign) (the )?(document|invoice|agreement)/i,
    /re-?validate|re-?activate (your )?account/i, /you have (\d+ )?(pending|undelivered|held) (messages|emails|deliveries|packages)/i,
    /(wire|bank) transfer|gift cards?/i, /tax refund|refund (is )?pending/i,
    // Malay / Indonesian
    /akaun anda (akan )?(disekat|digantung|ditutup)/i, /sahkan (akaun|identiti)/i, /verifikasi akun/i, /akun anda (akan )?(diblokir|ditangguhkan)/i,
    // Bengali
    /আপনার অ্যাকাউন্ট (বন্ধ|স্থগিত)/, /যাচাই করুন/, /জরুরি/
  ];

  const DANGEROUS_ATTACHMENT = /\.(html?|shtml|svg|hta|iso|img|vhdx?|lnk|js|jse|vbs|vbe|wsf|scr|exe|msi|one|xll|cab|zip|rar|7z)\b/i;

  // ------------------------------------------------------------- helpers ---

  function punycodeDecode(input) {
    // RFC 3492 decoder for a single label (without the "xn--" prefix).
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128;
    const output = [];
    let n = initialN, i = 0, bias = initialBias;
    let basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (let j = 0; j < basic; j++) {
      if (input.charCodeAt(j) >= 0x80) throw new Error('not-basic');
      output.push(input.charCodeAt(j));
    }
    const adapt = (delta, numPoints, firstTime) => {
      let k = 0;
      delta = firstTime ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / numPoints);
      for (; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
      return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
    };
    const digit = (cp) => (cp - 48 < 10 ? cp - 22 : cp - 65 < 26 ? cp - 65 : cp - 97 < 26 ? cp - 97 : base);
    for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      const oldi = i;
      for (let w = 1, k = base; ; k += base) {
        if (idx >= input.length) throw new Error('bad-input');
        const d = digit(input.charCodeAt(idx++));
        if (d >= base) throw new Error('bad-input');
        i += d * w;
        const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (d < t) break;
        w *= base - t;
      }
      const out = output.length + 1;
      bias = adapt(i - oldi, out, oldi === 0);
      n += Math.floor(i / out);
      i %= out;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  }

  function decodeHost(host) {
    return host.split('.').map((l) => {
      if (!l.startsWith('xn--')) return l;
      try { return punycodeDecode(l.slice(4)); } catch (_) { return l; }
    }).join('.');
  }

  function skeleton(s) {
    let out = '';
    for (const ch of s.normalize('NFKD')) {
      if (/\p{M}/u.test(ch)) continue; // drop combining marks (é -> e)
      out += HOMOGLYPHS[ch] || ch;
    }
    out = out.toLowerCase();
    for (const [from, to] of ASCII_CONFUSABLES) out = out.split(from).join(to);
    return out.replace(/[-_]/g, '');
  }

  function levenshtein(a, b) {
    if (a === b) return 0;
    if (Math.abs(a.length - b.length) > 2) return 3;
    let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
    for (let i = 1; i <= a.length; i++) {
      const cur = [i];
      for (let j = 1; j <= b.length; j++) {
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      }
      prev = cur;
    }
    return prev[b.length];
  }

  function isIp(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[') || /^[0-9a-f:]+$/i.test(host) && host.includes(':');
  }

  /** localhost, loopback, RFC 1918 private, link-local and IPv6 unique-local / link-local addresses. */
  function isLocalHost(host) {
    const h = String(host || '').toLowerCase().replace(/^\[|\]$/g, '');
    if (h === 'localhost' || h.endsWith('.localhost')) return true;
    const o = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (o) {
      const [a, b] = [Number(o[1]), Number(o[2])];
      return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
    }
    return h === '::1' || /^f[cd][0-9a-f]{2}:/.test(h) || /^fe[89ab][0-9a-f]:/.test(h);
  }

  function registrableDomain(host) {
    host = (host || '').toLowerCase().replace(/\.$/, '');
    if (!host || isIp(host)) return host;
    const parts = host.split('.');
    if (parts.length <= 2) return host;
    // Hosting platforms behave like public suffixes: owner is one label below them.
    for (const h of FREE_HOSTING) {
      if (host === h) return host;
      if (host.endsWith('.' + h)) {
        const rest = host.slice(0, -(h.length + 1)).split('.');
        return rest[rest.length - 1] + '.' + h;
      }
    }
    const last2 = parts.slice(-2).join('.');
    if (MULTI_SUFFIXES.has(last2)) return parts.slice(-3).join('.');
    return last2;
  }

  function hostMatches(host, domain) {
    host = (host || '').toLowerCase();
    domain = (domain || '').toLowerCase().replace(/^\*\./, '').replace(/^\./, '');
    return !!domain && (host === domain || host.endsWith('.' + domain));
  }

  function hostInList(host, list) {
    if (list instanceof Set) {
      // O(labels) lookup for big lists (threat feeds): try the host, then each parent domain.
      for (let h = (host || '').toLowerCase(); h;) {
        if (list.has(h)) return true;
        const i = h.indexOf('.');
        if (i < 0) break;
        h = h.slice(i + 1);
      }
      return false;
    }
    return (list || []).some((d) => hostMatches(host, d));
  }

  function freeHostingOf(host) {
    return FREE_HOSTING.find((h) => hostMatches(host, h)) || null;
  }

  function allBrands(extra) {
    return (extra && extra.length) ? BRANDS.concat(extra.map(normalizeBrand)) : BRANDS;
  }

  function normalizeBrand(b) {
    const domains = (b.domains || []).map((d) => String(d).toLowerCase());
    const labels = b.labels || domains.map((d) => registrableDomain(d).split('.')[0]);
    const name = b.name || labels[0] || 'Custom';
    return {
      name, domains, labels: labels.map((l) => l.toLowerCase()),
      keywords: (b.keywords || labels).map((k) => k.toLowerCase()),
      pageTerms: (b.pageTerms || [name]).map((t) => t.toLowerCase())
    };
  }

  function isBrandLegit(host, brand) {
    return hostInList(host, brand.domains);
  }

  /** Unwrap well-known redirect / safe-link wrappers to reach the real destination. */
  function unwrapUrl(href) {
    let url;
    try { url = new URL(href); } catch (_) { return href; }
    for (let depth = 0; depth < 4; depth++) {
      const h = url.hostname.toLowerCase();
      const p = url.searchParams;
      let next = null;
      if ((/(^|\.)google\.[a-z.]+$/.test(h) && url.pathname === '/url') && (p.get('q') || p.get('url'))) next = p.get('q') || p.get('url');
      else if (h.endsWith('safelinks.protection.outlook.com') && p.get('url')) next = p.get('url');
      else if (h === 'l.facebook.com' && p.get('u')) next = p.get('u');
      else if (h === 'www.linkedin.com' && url.pathname.startsWith('/redir/redirect') && p.get('url')) next = p.get('url');
      else if (h.endsWith('urldefense.com') && url.pathname.startsWith('/v3/__')) {
        const m = url.pathname.match(/^\/v3\/__(.+?)__;/);
        if (m) next = m[1];
      } else if (h === 'urldefense.proofpoint.com' && p.get('u')) {
        next = p.get('u').replace(/-/g, '%').replace(/_/g, '/');
        try { next = decodeURIComponent(next); } catch (_) { /* keep raw */ }
      } else if (h.endsWith('mimecastprotect.com') || h.endsWith('protect-us.mimecast.com')) {
        // Mimecast hides the target server-side; nothing to unwrap.
      }
      if (!next) break;
      try { url = new URL(next); } catch (_) { break; }
    }
    return url.href;
  }

  function defang(u) {
    return String(u || '').replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
  }

  function scriptsOf(label) {
    const s = new Set();
    for (const ch of label) {
      if (/[0-9-]/.test(ch)) continue;
      if (/\p{Script=Latin}/u.test(ch)) s.add('latin');
      else if (/\p{Script=Cyrillic}/u.test(ch)) s.add('cyrillic');
      else if (/\p{Script=Greek}/u.test(ch)) s.add('greek');
      else s.add('other');
    }
    return s;
  }

  // ------------------------------------------------------- URL analysis ---

  /**
   * Score a URL. Returns { score, level, reasons[], host, domain, brand, allow }.
   * `cfg`: { allowedDomains, blockedDomains, corporateDomains, extraBrands, warnThreshold, blockThreshold }
   */
  function analyzeUrl(href, cfg) {
    cfg = cfg || {};
    const res = { url: href, score: 0, level: 'safe', reasons: [], host: '', domain: '', brand: null, allow: false };
    let url;
    try { url = new URL(href); } catch (_) { return res; }
    if (!/^https?:$/.test(url.protocol)) return res;

    const host = url.hostname.toLowerCase().replace(/\.$/, '');
    const domain = registrableDomain(host);
    res.host = host; res.domain = domain;
    const add = (pts, why) => { res.score += pts; res.reasons.push(why); };

    if (hostInList(host, cfg.blockedSet || cfg.blockedDomains)) {
      add(100, 'Domain is on your organisation\'s block list');
      return finish(res, cfg);
    }
    if (hostInList(host, cfg.allowedDomains) || hostInList(host, cfg.corporateDomains)) {
      res.allow = true; return finish(res, cfg);
    }

    // Your own computer and private networks (OAuth loopback callbacks, dev servers, router / NAS admin
    // pages) are not phishing sites: raw IP, odd port and plain HTTP are normal there.
    if (isLocalHost(host)) { res.allow = true; res.local = true; return finish(res, cfg); }

    const brands = allBrands(cfg.extraBrands);
    const legitBrand = brands.find((b) => isBrandLegit(host, b));
    if (legitBrand) { res.allow = true; res.brand = legitBrand.name; return finish(res, cfg); }

    // Credentials in authority (http://login.microsoft.com@evil.tld/)
    if (url.username || url.password) add(35, 'URL hides the real host behind an "@" (credential trick)');

    if (isIp(host)) add(30, 'Site is a raw IP address, not a domain name');

    const decoded = decodeHost(host);
    const labels = host.split('.');
    const tld = labels[labels.length - 1];
    const regLabel = domain.split('.')[0];
    const decodedRegLabel = decodeHost(regLabel);

    if (decoded !== host) {
      add(20, 'Internationalised (punycode) domain: ' + decoded);
      for (const l of decoded.split('.')) {
        const sc = scriptsOf(l);
        if (sc.size > 1 && sc.has('latin')) { add(25, 'Domain mixes alphabets (homoglyph trick)'); break; }
      }
    }

    // Brand lookalike on the registrable label (paypa1.com, rnicrosoft.com, gооgle.com)
    const skel = skeleton(decodedRegLabel);
    for (const b of brands) {
      for (const bl of b.labels) {
        if (bl.length < 4) continue;
        const exact = skel === bl && decodedRegLabel !== bl;
        const near = bl.length >= 6 && skel !== bl && levenshtein(skel, bl) === 1;
        if (exact || near) {
          add(60, `Domain imitates ${b.name} ("${decodedRegLabel}" looks like "${bl}")`);
          res.brand = b.name; break;
        }
      }
      if (res.brand) break;
    }

    const fh = freeHostingOf(host);

    // Brand name as the owner label: paypal.de is usually the brand's own ccTLD,
    // but paypal.netlify.app / paypal.xyz is not.
    if (!res.brand) {
      const own = brands.find((b) => b.labels.includes(decodedRegLabel));
      if (own) {
        if (fh || RISKY_TLDS.has(tld)) add(45, `${own.name} name on ${fh ? 'free hosting' : 'an unusual domain'} the brand does not use`);
        res.brand = own.name;
      }
    }

    // Brand keyword used in a hostname the brand does not own (microsoft-login.verify-acc.com)
    if (!res.brand) {
      const tokens = decoded.toLowerCase().split(/[.\-_]/).filter(Boolean);
      const tokenSkels = tokens.map(skeleton);
      for (const b of brands) {
        const hit = b.keywords.find((k) => k.length >= 4 && (tokens.includes(k) || tokenSkels.includes(k) ||
          tokens.some((t) => t.length > k.length + 2 && t.startsWith(k) && /(login|secure|verify|account|support|update|signin|auth|help|service|portal|online|web|mail)/.test(t.slice(k.length)))));
        if (hit) {
          add(40, `Uses the ${b.name} name on a domain ${b.name} does not own`);
          if (fh) add(15, `${b.name} name on free hosting — brands never host logins there`);
          res.brand = b.name; break;
        }
      }
    }

    // A real brand domain used as a prefix: login.microsoftonline.com.verify-account.top
    const embedded = brands.find((b) => b.domains.some((d) => d.includes('.') &&
      (host.startsWith(d + '.') || host.includes('.' + d + '.') || host.includes(d.replace(/\./g, '-') + '.'))));
    if (embedded) { add(30, `Starts with a real ${embedded.name} address to look genuine`); res.brand = res.brand || embedded.name; }

    if (RISKY_TLDS.has(tld)) add(15, `High-abuse top-level domain ".${tld}"`);
    if (fh) add(15, `Hosted on free/instant hosting (${fh})`);

    if (SHORTENERS.has(host)) add(10, 'Link shortener hides the real destination');

    const subCount = labels.length - domain.split('.').length;
    if (subCount >= 4) add(15, 'Unusually deep subdomain chain');
    else if (subCount === 3) add(5, 'Deep subdomain chain');
    if (host.length > 55) add(10, 'Very long hostname');
    if ((host.match(/-/g) || []).length >= 4) add(10, 'Many hyphens in hostname');
    if (/\d{5,}/.test(regLabel)) add(5, 'Random-looking number in domain');
    if (url.port && !['80', '443'].includes(url.port)) add(10, `Non-standard port :${url.port}`);
    if (href.length > 250) add(5, 'Very long URL');
    if (/(login|signin|sign-in|verify|account|secure|update|wallet|password|banking|webscr|auth)/i.test(url.pathname + url.search) && (fh || RISKY_TLDS.has(tld) || isIp(host))) {
      add(15, 'Login / verification path on a low-trust host');
    }
    if (/[?&#](email|e|user|login|u)=[^&]*(@|%40)/i.test(url.search + url.hash)) add(10, 'Your email address is pre-filled in the link (targeted lure)');
    if (url.protocol === 'http:' && res.score > 0) add(5, 'No HTTPS');

    return finish(res, cfg);
  }

  // ------------------------------------------------------ page analysis ---

  /**
   * Combine URL verdict with signals collected from the rendered page.
   * signals: { hasPassword, brandStrong[] (title, logo alts, favicon, site name), bodyText, formActions[], isHttp, ageDays }
   */
  // Brand words that real sites use all the time: SSO buttons, authenticator apps, embedded services.
  const BENIGN_MENTIONS = /\b(?:sign|log)\s?(?:in|up|on)\s+(?:with|using|via|through)\s+(?!your\b)[a-z0-9]+(?:\s+[a-z0-9]+)?|\bcontinue\s+with\s+(?!your\b)[a-z0-9]+(?:\s+[a-z0-9]+)?|\bconnect\s+(?:with|to)\s+[a-z0-9]+|\b[a-z]+\s+authenticator\b|\brecaptcha\b|\bgoogle\s+(?:analytics|play|tag\s+manager|maps|fonts|workspace\s+marketplace)\b|\bapp\s+store\b|\bmicrosoft\s+(?:store|edge)\b|\bpowered\s+by\s+[a-z]+\b/g;
  function stripBenignMentions(s) { return s.replace(BENIGN_MENTIONS, ' '); }

  function analyzePage(urlVerdict, signals, cfg) {
    cfg = cfg || {};
    const res = Object.assign({}, urlVerdict, { reasons: urlVerdict.reasons.slice() });
    if (res.allow || !signals) return finish(res, cfg);
    const add = (pts, why) => { res.score += pts; res.reasons.push(why); };
    const host = res.host;
    const brands = allBrands(cfg.extraBrands);

    if (signals.hasPassword) {
      // Strong = title / logo / favicon / site name. Weak = body text only (it may just mention the brand).
      const strong = (signals.brandStrong || []).join(' \n ').toLowerCase();
      const weak = stripBenignMentions(String(signals.bodyText || '').toLowerCase());
      const strongClaim = brands.find((b) => b.pageTerms.some((t) => strong.includes(t)) && !isBrandLegit(host, b));
      const weakClaim = !strongClaim && brands.find((b) => b.pageTerms.some((t) => weak.includes(t)) && !isBrandLegit(host, b));
      const foreign = (signals.formActions || []).map((a) => { try { return new URL(a).hostname; } catch (_) { return null; } })
        .filter((h) => h && registrableDomain(h) !== res.domain);
      // A brand named only in body text is normal on real sites ("Google Authenticator", "works with Microsoft Teams").
      // It only counts when something else about the site is already off.
      const otherRisk = res.score >= 15 || signals.isHttp || foreign.length > 0 || (typeof signals.ageDays === 'number' && signals.ageDays < 90);
      if (strongClaim) {
        add(70, `Login page imitates ${strongClaim.name} (logo / title) on a non-${strongClaim.name} site`);
        res.brand = res.brand || strongClaim.name;
      } else if (weakClaim && otherRisk) {
        add(30, `Asks for a password while mentioning ${weakClaim.name}`);
        res.brand = res.brand || weakClaim.name;
      } else if (res.score >= 15) {
        add(15, 'Asks for a password on a low-trust site');
      }
      if (signals.isHttp) add(20, 'Password form without HTTPS');
      if (foreign.length) add(15, 'Form sends data to another domain: ' + registrableDomain(foreign[0]));
    }
    if (typeof signals.ageDays === 'number') {
      if (signals.ageDays < 7) add(40, `Domain registered only ${signals.ageDays} day(s) ago`);
      else if (signals.ageDays < 30) add(25, `Domain registered ${signals.ageDays} days ago`);
      else if (signals.ageDays < 90) add(10, `Young domain (${signals.ageDays} days old)`);
    }
    return finish(res, cfg);
  }

  // ----------------------------------------------------- email analysis ---

  /**
   * email: { senderName, senderEmail, subject, text, links: [{ href, text }], attachments: [names] }
   * Returns { score, level, reasons[], links: [{ href, real, verdict, mismatch }] }
   */
  function analyzeEmail(email, cfg) {
    cfg = cfg || {};
    const res = { score: 0, level: 'safe', reasons: [], links: [] };
    const add = (pts, why) => { res.score += pts; res.reasons.push(why); };
    const brands = allBrands(cfg.extraBrands);

    const senderEmail = (email.senderEmail || '').toLowerCase();
    const senderDomain = senderEmail.split('@')[1] || '';
    const senderName = (email.senderName || '').toLowerCase();
    const trustedSender = senderDomain && (hostInList(senderDomain, cfg.corporateDomains) || hostInList(senderDomain, cfg.allowedDomains));

    if (senderDomain && !trustedSender) {
      const sv = analyzeUrl('https://' + senderDomain + '/', cfg);
      if (!sv.allow && sv.brand) add(45, `Sender domain imitates ${sv.brand} (${senderDomain})`);
      const named = brands.find((b) => b.pageTerms.concat(b.keywords).some((t) => t.length >= 4 && senderName.includes(t)));
      if (named && !isBrandLegit(senderDomain, named)) add(35, `Sender name says "${email.senderName}" but mail comes from ${senderDomain}`);
      if (freeHostingOf(senderDomain) || /^(gmail|outlook|hotmail|yahoo|proton|protonmail|gmx|mail|yandex|aol|icloud)\./.test(senderDomain)) {
        if (named) add(15, 'Brand message sent from a free mailbox');
      }
    }

    const body = (email.subject || '') + '\n' + (email.text || '');
    let phraseHits = 0;
    for (const re of PHISH_PHRASES) if (re.test(body)) phraseHits++;
    if (phraseHits) add(Math.min(phraseHits * 8, 30), `Pressure / lure language (${phraseHits} pattern${phraseHits > 1 ? 's' : ''})`);

    const atts = (email.attachments || []).filter((a) => DANGEROUS_ATTACHMENT.test(a));
    if (atts.length) add(25, 'Risky attachment type: ' + atts.slice(0, 3).join(', '));

    let worstLink = 0;
    const seen = new Set();
    for (const l of (email.links || [])) {
      if (!l.href || !/^https?:/i.test(l.href)) continue;
      const real = unwrapUrl(l.href);
      const v = analyzeUrl(real, cfg);
      let mismatch = false;
      const shown = (l.text || '').trim().match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]|$)/i);
      if (shown && v.domain) {
        const shownDomain = registrableDomain(shown[1].toLowerCase());
        if (shownDomain !== v.domain && !v.allow) {
          mismatch = true;
          v.score += 40; v.reasons.push(`Link text shows ${shownDomain} but really goes to ${v.domain}`);
          finish(v, cfg);
        }
      }
      res.links.push({ href: l.href, real, verdict: v, mismatch });
      if (!seen.has(v.domain) && !v.allow) {
        seen.add(v.domain);
        worstLink = Math.max(worstLink, v.score);
      }
    }
    if (worstLink) {
      const worst = res.links.reduce((a, b) => (b.verdict.score > (a ? a.verdict.score : -1) ? b : a), null);
      add(Math.round(worstLink * 0.8), 'Dangerous link: ' + (worst.verdict.reasons[0] || worst.verdict.domain));
    }
    return finish(res, cfg);
  }

  function finish(res, cfg) {
    const warn = (cfg && cfg.warnThreshold) || 40;
    const block = (cfg && cfg.blockThreshold) || 70;
    res.score = Math.min(100, res.score);
    res.level = res.allow ? 'safe' : res.score >= block ? 'block' : res.score >= warn ? 'warn' : res.score >= 15 ? 'caution' : 'safe';
    return res;
  }

  const api = {
    analyzeUrl, analyzePage, analyzeEmail, unwrapUrl, defang, registrableDomain, hostMatches, hostInList,
    decodeHost, skeleton, levenshtein, punycodeDecode, BRANDS, FREE_HOSTING
  };
  root.VSAnalyzer = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
