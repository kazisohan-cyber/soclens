/*
 * SOCLens intel sources (service worker). Looks one indicator up in many places at once, with a
 * per-source cache, and hands the result to VSEngine.assess().
 *
 * No key needed:  GreyNoise community, Shodan InternetDB, ipinfo, RDAP, DNS (Cloudflare DoH),
 *                 CISA KEV, FIRST EPSS, NVD, SOCLens local analysis + client memory.
 * Free API key:   VirusTotal, AbuseIPDB, abuse.ch (URLhaus, ThreatFox, MalwareBazaar), urlscan.io.
 * Keys stay in this browser (storage.local) and requests go straight from the browser to the source.
 * Only the indicator itself is sent, never page content.
 */
(function (root) {
  'use strict';
  const I = root.VSIoc, E = root.VSEngine, A = root.VSAnalyzer, M = root.VSMemory;

  const DEFAULTS = {
    keys: { vt: '', abuseipdb: '', greynoise: '', abusech: '', urlscan: '' },
    publicSources: true,      // the no-key sources above
    highlight: true,          // mark IOCs on analyst sites
    highlightSites: ['securonix.net', 'securonix.com', 'halopsa.com', 'haloitsm.com', 'haloservicedesk.com',
      'sentinelone.net', 'security.microsoft.com', 'portal.azure.com', 'app.slack.com', 'teams.microsoft.com'],
    ai: true,                 // on-device AI summary when the browser offers it
    analyst: '',              // name printed on ticket notes
    wizardDone: false,        // key setup guide dismissed
    activeClient: ''          // client the analyst is working on ('' = all clients)
  };

  async function settings() {
    const { analyst = {} } = await chrome.storage.local.get('analyst');
    return Object.assign({}, DEFAULTS, analyst, { keys: Object.assign({}, DEFAULTS.keys, analyst.keys || {}) });
  }
  async function saveSettings(patch) {
    const cur = await settings();
    const keys = Object.assign({}, cur.keys, (patch && patch.keys) || {});  // merge before cur is overwritten
    const next = Object.assign(cur, patch || {}, { keys });
    if (next.highlightSites) next.highlightSites = root.VSConfig ? root.VSConfig.cleanList(next.highlightSites) : next.highlightSites;
    await chrome.storage.local.set({ analyst: next });
    return next;
  }

  // ------------------------------------------------------------------ cache ---

  const H = 3600e3;
  async function cached(key, ttlOk, fn) {
    const k = 'ic:' + key;
    const hit = (await chrome.storage.local.get(k))[k];
    if (hit && Date.now() < hit.exp) return Object.assign({}, hit.v, { cached: true });
    const v = await fn();
    const ttl = v.status === 'ok' ? ttlOk : v.status === 'notfound' ? Math.min(ttlOk, 2 * H) : 0;
    if (ttl) await chrome.storage.local.set({ [k]: { v, exp: Date.now() + ttl } });
    return v;
  }
  async function sweepCache() {
    const all = await chrome.storage.local.get(null);
    const dead = Object.keys(all).filter((k) => (k.startsWith('ic:') || k.startsWith('ia:')) && !(all[k] && all[k].exp > Date.now()));
    if (dead.length) await chrome.storage.local.remove(dead);
    return dead.length;
  }

  async function http(url, opts) {
    opts = opts || {};
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), opts.timeout || 9000);
    try {
      const r = await fetch(url, { method: opts.method || 'GET', headers: opts.headers || {}, body: opts.body, credentials: 'omit', signal: ctl.signal, cache: 'no-store' });
      let json = null;
      const text = await r.text();
      try { json = text ? JSON.parse(text) : null; } catch (_) { json = null; }
      return { status: r.status, json, text };
    } catch (e) {
      return { status: 0, json: null, error: e.name === 'AbortError' ? 'timeout' : 'network error' };
    } finally { clearTimeout(timer); }
  }

  function fail(r, link) {
    if (r.status === 429) return { status: 'ratelimited', link };
    if (r.status === 401 || r.status === 403) return { status: 'error', error: 'API key rejected', link };
    return { status: 'error', error: r.error || ('HTTP ' + r.status), link };
  }

  // VirusTotal free tier: 4 lookups / minute. Instead of failing the 5th lookup, queue it: requests take
  // slots in order and run as soon as the minute window allows (up to VT_MAX_WAIT).
  const vtCalls = [];
  const VT_MAX_WAIT = 150e3;
  let vtChain = Promise.resolve();
  function vtWaitMs() {
    const now = Date.now();
    while (vtCalls.length && now - vtCalls[0] > 60e3) vtCalls.shift();
    return vtCalls.length >= 4 ? 60e3 - (now - vtCalls[0]) + 300 : 0;
  }
  // A long setTimeout alone lets Chrome stop the service worker; touching an extension API keeps it alive.
  async function sleepAlive(ms) {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      await new Promise((r) => setTimeout(r, Math.min(20e3, end - Date.now())));
      try { await chrome.runtime.getPlatformInfo(); } catch (_) { /* not in an extension (tests) */ }
    }
  }
  /** Resolves with the seconds waited, or -1 when the queue is too long. */
  function vtSlot() {
    const start = Date.now();
    const p = vtChain.then(async () => {
      for (;;) {
        const w = vtWaitMs();
        if (!w) { vtCalls.push(Date.now()); return Math.round((Date.now() - start) / 1000); }
        if (Date.now() + w - start > VT_MAX_WAIT) return -1;
        await sleepAlive(w);
      }
    });
    vtChain = p.catch(() => {});
    return p;
  }

  // ---------------------------------------------------------------- sources ---

  const src = {
    async greynoise(ip, s) {
      const link = 'https://viz.greynoise.io/ip/' + ip;
      return cached('gn:' + ip, 6 * H, async () => {
        const r = await http('https://api.greynoise.io/v3/community/' + ip, { headers: s.keys.greynoise ? { key: s.keys.greynoise } : {} });
        if (r.status === 200 && r.json) return { status: 'ok', data: { noise: !!r.json.noise, riot: !!r.json.riot, classification: r.json.classification || '', name: r.json.name || '', lastSeen: r.json.last_seen || '' }, link };
        if (r.status === 404) return { status: 'notfound', data: { message: (r.json && r.json.message) || 'Not observed' }, link };
        return fail(r, link);
      });
    },
    async internetdb(ip) {
      const link = 'https://www.shodan.io/host/' + ip;
      return cached('idb:' + ip, 12 * H, async () => {
        const r = await http('https://internetdb.shodan.io/' + ip);
        if (r.status === 200 && r.json) return { status: 'ok', data: { ports: r.json.ports || [], tags: r.json.tags || [], vulns: r.json.vulns || [], hostnames: r.json.hostnames || [] }, link };
        if (r.status === 404) return { status: 'notfound', link };
        return fail(r, link);
      });
    },
    async ipinfo(ip) {
      const link = 'https://ipinfo.io/' + ip;
      return cached('ipi:' + ip, 24 * H, async () => {
        const r = await http('https://ipinfo.io/' + ip + '/json');
        if (r.status === 200 && r.json && !r.json.bogon) return { status: 'ok', data: { org: r.json.org || '', country: r.json.country || '', city: r.json.city || '', hostname: r.json.hostname || '', anycast: !!r.json.anycast }, link };
        return fail(r, link);
      });
    },
    async abuseipdb(ip, s) {
      const link = 'https://www.abuseipdb.com/check/' + ip;
      if (!s.keys.abuseipdb) return { status: 'nokey', link };
      return cached('aip:' + ip, 6 * H, async () => {
        const r = await http('https://api.abuseipdb.com/api/v2/check?maxAgeInDays=90&ipAddress=' + encodeURIComponent(ip), { headers: { Key: s.keys.abuseipdb, Accept: 'application/json' } });
        const d = r.json && r.json.data;
        if (r.status === 200 && d) return { status: 'ok', data: { score: d.abuseConfidenceScore, reports: d.totalReports, usage: d.usageType || '', isp: d.isp || '', country: d.countryCode || '', tor: !!d.isTor, whitelisted: !!d.isWhitelisted, lastReported: d.lastReportedAt || '', domain: d.domain || '' }, link };
        return fail(r, link);
      });
    },
    async vt(type, value, s) {
      const group = I.GROUP[type];
      const path = group === 'ip' ? 'ip_addresses/' + value : group === 'hash' ? 'files/' + value
        : type === 'url' ? 'urls/' + btoa(unescape(encodeURIComponent(value))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') : 'domains/' + value;
      const gui = group === 'ip' ? 'ip-address/' + value : group === 'hash' ? 'file/' + value : type === 'url' ? 'search/' + encodeURIComponent(value) : 'domain/' + value;
      const link = 'https://www.virustotal.com/gui/' + gui;
      if (!s.keys.vt) return { status: 'nokey', link };
      const k = 'vt:' + type + ':' + value;
      const hit = (await chrome.storage.local.get('ic:' + k))['ic:' + k];
      let waited = 0;
      if (!(hit && Date.now() < hit.exp)) {
        waited = await vtSlot();
        if (waited < 0) return { status: 'ratelimited', error: 'VirusTotal free limit (4/min): too many queued, try again in a minute', link };
      }
      const res = await cached(k, 6 * H, async () => {
        const r = await http('https://www.virustotal.com/api/v3/' + path, { headers: { 'x-apikey': s.keys.vt } });
        const at = r.json && r.json.data && r.json.data.attributes;
        if (r.status === 200 && at) {
          const st = at.last_analysis_stats || {};
          return { status: 'ok', link, data: {
            malicious: st.malicious || 0, suspicious: st.suspicious || 0, harmless: st.harmless || 0, undetected: st.undetected || 0,
            reputation: at.reputation || 0, label: (at.popular_threat_classification && at.popular_threat_classification.suggested_threat_label) || '',
            name: at.meaningful_name || '', typeDesc: at.type_description || '', created: at.creation_date || 0,
            firstSeen: at.first_submission_date || 0, asOwner: at.as_owner || '', country: at.country || '' } };
        }
        if (r.status === 404) return { status: 'notfound', link };
        return fail(r, link);
      });
      return waited > 2 ? Object.assign({}, res, { waited }) : res;
    },
    async threatfox(value, s) {
      const link = 'https://threatfox.abuse.ch/browse.php?search=ioc%3A' + encodeURIComponent(value);
      if (!s.keys.abusech) return { status: 'nokey', link };
      return cached('tf:' + value, 6 * H, async () => {
        const r = await http('https://threatfox-api.abuse.ch/api/v1/', { method: 'POST', headers: { 'Auth-Key': s.keys.abusech, 'Content-Type': 'application/json' }, body: JSON.stringify({ query: 'search_ioc', search_term: value, exact_match: true }) });
        if (r.status === 200 && r.json && r.json.query_status === 'ok' && Array.isArray(r.json.data) && r.json.data.length) {
          const d = r.json.data[0];
          return { status: 'ok', link, data: { malware: d.malware_printable || d.malware || '', threatType: d.threat_type_desc || d.threat_type || '', confidence: d.confidence_level, firstSeen: d.first_seen || '', count: r.json.data.length } };
        }
        if (r.status === 200) return { status: 'notfound', link };
        return fail(r, link);
      });
    },
    async urlhaus(type, value, s) {
      const isUrl = type === 'url';
      const link = 'https://urlhaus.abuse.ch/browse.php?search=' + encodeURIComponent(value);
      if (!s.keys.abusech) return { status: 'nokey', link };
      return cached('uh:' + value, 6 * H, async () => {
        const r = await http('https://urlhaus-api.abuse.ch/v1/' + (isUrl ? 'url/' : 'host/'), { method: 'POST',
          headers: { 'Auth-Key': s.keys.abusech, 'Content-Type': 'application/x-www-form-urlencoded' }, body: (isUrl ? 'url=' : 'host=') + encodeURIComponent(value) });
        const j = r.json;
        if (r.status === 200 && j && j.query_status === 'ok') {
          const bl = Object.entries(j.blacklists || {}).filter(([, v]) => v && v !== 'not listed').map(([k]) => k.replace('_', ' ').toUpperCase());
          const urls = j.urls || [];
          return { status: 'ok', link, data: { urlsCount: isUrl ? 1 : (j.url_count || urls.length), online: isUrl ? j.url_status === 'online' : urls.some((u) => u.url_status === 'online'),
            threat: isUrl ? j.threat : (urls[0] && urls[0].threat) || '', tags: (isUrl ? j.tags : urls[0] && urls[0].tags) || [], blacklists: bl } };
        }
        if (r.status === 200) return { status: 'notfound', link };
        return fail(r, link);
      });
    },
    async malwarebazaar(hash, s) {
      const link = 'https://bazaar.abuse.ch/browse.php?search=' + (hash.length === 64 ? 'sha256' : hash.length === 40 ? 'sha1' : 'md5') + '%3A' + hash;
      if (!s.keys.abusech) return { status: 'nokey', link };
      return cached('mb:' + hash, 12 * H, async () => {
        const r = await http('https://mb-api.abuse.ch/api/v1/', { method: 'POST', headers: { 'Auth-Key': s.keys.abusech, 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'query=get_info&hash=' + hash });
        if (r.status === 200 && r.json && r.json.query_status === 'ok' && r.json.data && r.json.data[0]) {
          const d = r.json.data[0];
          return { status: 'ok', link, data: { signature: d.signature || '', fileType: d.file_type || '', firstSeen: d.first_seen || '', tags: d.tags || [], name: d.file_name || '' } };
        }
        if (r.status === 200) return { status: 'notfound', link };
        return fail(r, link);
      });
    },
    async rdap(domain) {
      const link = 'https://rdap.org/domain/' + domain;
      const age = typeof root.domainAgeDays === 'function' ? await root.domainAgeDays(A.registrableDomain(domain)) : null;
      return age == null ? { status: 'notfound', link } : { status: 'ok', data: { ageDays: age }, link };
    },
    async dns(domain) {
      const link = 'https://dns.google/query?name=' + domain;
      return cached('dns:' + domain, H, async () => {
        const r = await http('https://cloudflare-dns.com/dns-query?type=A&name=' + encodeURIComponent(domain), { headers: { accept: 'application/dns-json' } });
        if (r.status === 200 && r.json) return { status: 'ok', link, data: { nx: r.json.Status === 3, a: (r.json.Answer || []).filter((x) => x.type === 1).map((x) => x.data) } };
        return fail(r, link);
      });
    },
    async kev(cve) {
      const link = 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=' + cve;
      let { kevCatalog } = await chrome.storage.local.get('kevCatalog');
      if (!kevCatalog || Date.now() - kevCatalog.t > 24 * H) {
        const r = await http('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', { timeout: 20000 });
        if (r.status === 200 && r.json && Array.isArray(r.json.vulnerabilities)) {
          const map = {};
          for (const v of r.json.vulnerabilities) map[v.cveID] = { vendor: v.vendorProject, product: v.product, name: v.vulnerabilityName, dateAdded: v.dateAdded, dueDate: v.dueDate, ransomware: v.knownRansomwareCampaignUse, requiredAction: v.requiredAction };
          kevCatalog = { t: Date.now(), map };
          await chrome.storage.local.set({ kevCatalog });
        } else if (!kevCatalog) return fail(r, link);
      }
      const hit = kevCatalog.map[cve];
      return hit ? { status: 'ok', data: hit, link } : { status: 'notfound', link };
    },
    async epss(cve) {
      const link = 'https://www.first.org/epss/';
      return cached('epss:' + cve, 24 * H, async () => {
        const r = await http('https://api.first.org/data/v1/epss?cve=' + cve);
        const d = r.json && r.json.data && r.json.data[0];
        if (r.status === 200 && d) return { status: 'ok', data: { epss: Number(d.epss), percentile: Number(d.percentile), date: d.date }, link };
        if (r.status === 200) return { status: 'notfound', link };
        return fail(r, link);
      });
    },
    async nvd(cve) {
      const link = 'https://nvd.nist.gov/vuln/detail/' + cve;
      return cached('nvd:' + cve, 24 * H, async () => {
        const r = await http('https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=' + cve, { timeout: 15000 });
        const v = r.json && r.json.vulnerabilities && r.json.vulnerabilities[0] && r.json.vulnerabilities[0].cve;
        if (r.status === 200 && v) {
          const m = v.metrics || {};
          const c = (m.cvssMetricV40 || m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2 || [])[0];
          const cd = c && c.cvssData;
          return { status: 'ok', link, data: { score: cd ? cd.baseScore : null, severity: cd ? (cd.baseSeverity || c.baseSeverity || '') : '', vector: cd ? cd.vectorString : '',
            published: v.published, description: ((v.descriptions || []).find((d) => d.lang === 'en') || {}).value || '' } };
        }
        if (r.status === 200) return { status: 'notfound', link };
        return fail(r, link);
      });
    }
  };

  // ----------------------------------------------------------- client memory ---
  // Matching rules live in lib/memory.js (pure); this part only stores entries.

  async function memoryList() { return ((await chrome.storage.local.get('memory')).memory || []).map((m) => M.normalize(m)); }

  function memoryMatches(list, type, value, client) { return M.matchIoc(list, type, value, client); }

  async function memorySave(entry) {
    const list = await memoryList();
    const key = M.parseKey(entry.kind || 'auto', entry.ioc);
    const now = Date.now();
    const id = entry.id || crypto.randomUUID();
    const days = entry.ttlDays === 0 || entry.ttlDays === '0' ? 0 : Number(entry.ttlDays) || 90;
    const s = await settings();
    const item = M.normalize({ id, kind: key.kind, ioc: key.value, client: entry.client, verdict: entry.verdict, note: entry.note, ticket: entry.ticket,
      by: entry.by || s.analyst || '', created: now, updated: now, expires: days ? now + days * M.DAY : 0 }, now);
    const i = list.findIndex((m) => m.id === id);
    if (i >= 0) { item.created = list[i].created; list[i] = item; } else list.unshift(item);
    await chrome.storage.local.set({ memory: list.slice(0, 5000) });
    return item;
  }

  /** "Still true": extend a note by its original validity (90 days if it had none) and stamp who confirmed it. */
  async function memoryConfirm(id) {
    const list = await memoryList();
    const m = list.find((x) => x.id === id);
    if (!m) return { ok: false };
    const s = await settings();
    const now = Date.now();
    const span = m.expires && m.expires > m.updated ? m.expires - m.updated : 90 * M.DAY;
    Object.assign(m, { updated: now, expires: now + span, by: s.analyst || m.by });
    await chrome.storage.local.set({ memory: list });
    return { ok: true, item: m };
  }

  async function memoryDelete(id) {
    const list = await memoryList();
    await chrome.storage.local.set({ memory: list.filter((m) => m.id !== id) });
    return { ok: true };
  }

  async function memoryImport(items) {
    if (!Array.isArray(items)) throw new Error('Expected a JSON array exported from SOCLens');
    const list = await memoryList();
    const byId = new Map(list.map((m) => [m.id, m]));
    let added = 0, updated = 0;
    for (const x of items) {
      if (!x || !x.ioc || !x.id) continue;
      const clean = M.normalize(x);
      const cur = byId.get(clean.id);
      if (!cur) { byId.set(clean.id, clean); added++; } else if (clean.updated > (cur.updated || 0)) { byId.set(clean.id, clean); updated++; }
    }
    await chrome.storage.local.set({ memory: [...byId.values()].sort((a, b) => b.updated - a.updated).slice(0, 5000) });
    return { added, updated };
  }

  /** Accounts / hostnames remembered for the active client that appear in pasted text. */
  async function memoryContext(text) {
    const s = await settings();
    return M.matchContext(await memoryList(), text, s.activeClient);
  }

  // ------------------------------------------------------------- investigate ---

  async function investigate(input, cfg) {
    const c = I.classify(input);
    if (c.type === 'unknown') return { error: 'Not an IP, domain, URL, email, hash or CVE' };
    const s = await settings();
    const type = c.type, value = c.value, g = c.group;
    const report = { type, group: g, value, internal: false, memory: [], local: {}, sources: {}, at: Date.now() };
    const memList = await memoryList();
    report.client = s.activeClient || '';
    report.memory = memoryMatches(memList, type, value, s.activeClient);
    const pub = (fn) => (s.publicSources ? fn() : Promise.resolve({ status: 'skipped' }));
    const jobs = {};

    if (g === 'ip') {
      report.internal = I.isPrivateIp(value);
      if (!report.internal) {
        jobs.greynoise = pub(() => src.greynoise(value, s));
        jobs.internetdb = pub(() => src.internetdb(value));
        jobs.ipinfo = pub(() => src.ipinfo(value));
        jobs.abuseipdb = src.abuseipdb(value, s);
        jobs.vt = src.vt(type, value, s);
        jobs.threatfox = src.threatfox(value, s);
      }
    } else if (g === 'domain' || g === 'url' || g === 'email') {
      let url = type === 'url' ? value : null;
      if (url) {
        const real = A.unwrapUrl(url);
        if (real !== url) report.local.unwrapped = real;
        url = real;
      }
      const dom = type === 'url' ? I.domainOf('url', url) : I.domainOf(type, value);
      report.local.domain = dom;
      if (dom && !I.isPrivateIp(dom)) {
        report.local.analyzer = A.analyzeUrl(url || ('https://' + dom + '/'), cfg || {});
        report.local.blocklisted = !!(cfg && cfg.blockedSet && A.hostInList(dom, cfg.blockedSet));
        jobs.rdap = pub(() => src.rdap(dom));
        jobs.dns = pub(() => src.dns(dom));
        jobs.vt = type === 'url' ? src.vt('url', url, s) : src.vt('domain', dom, s);
        jobs.urlhaus = type === 'url' ? src.urlhaus('url', url, s) : src.urlhaus('domain', dom, s);
        jobs.threatfox = src.threatfox(type === 'url' ? url : dom, s);
      }
    } else if (g === 'hash') {
      jobs.vt = src.vt(type, value, s);
      jobs.malwarebazaar = src.malwarebazaar(value, s);
      jobs.threatfox = src.threatfox(value, s);
    } else if (g === 'cve') {
      jobs.kev = pub(() => src.kev(value));
      jobs.epss = pub(() => src.epss(value));
      jobs.nvd = pub(() => src.nvd(value));
    }
    const names = Object.keys(jobs);
    const results = await Promise.all(names.map((k) => jobs[k].catch((e) => ({ status: 'error', error: String(e && e.message || e) }))));
    names.forEach((k, i) => { report.sources[k] = results[i]; });
    if (g === 'ip' && !report.internal) {
      const net = M.networkOf(report.sources);
      report.memory = report.memory.concat(M.matchNetwork(memList, net, s.activeClient));
    }
    const a = E.assess(report);
    // Remember the last verdict so page highlighting can colour this IOC without a new lookup.
    await chrome.storage.local.set({ ['ia:' + value]: { verdict: a.verdict, confidence: a.confidence, exp: Date.now() + 24 * H } });
    return { report, a };
  }

  // -------------------------------------------------------------- detonation ---

  async function detonate(input) {
    const s = await settings();
    const c = I.classify(input);
    let url = c.type === 'url' ? A.unwrapUrl(c.value) : c.group === 'domain' ? 'https://' + c.value + '/' : '';
    if (!url) return { error: 'Detonation needs a URL or domain' };
    if (!s.keys.urlscan) return { status: 'nokey', url, unwrapped: url !== c.value ? url : '' };
    const sub = await http('https://urlscan.io/api/v1/scan/', { method: 'POST', headers: { 'API-Key': s.keys.urlscan, 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, visibility: 'unlisted', tags: ['soclens'] }), timeout: 15000 });
    if (sub.status !== 200 || !sub.json || !sub.json.uuid) {
      return { status: 'error', error: (sub.json && (sub.json.message || sub.json.description)) || sub.error || ('HTTP ' + sub.status), url };
    }
    const uuid = sub.json.uuid;
    const reportUrl = 'https://urlscan.io/result/' + uuid + '/';
    for (let i = 0; i < 25; i++) {
      await new Promise((r) => setTimeout(r, i ? 4000 : 10000));
      const r = await http('https://urlscan.io/api/v1/result/' + uuid + '/', { timeout: 15000 });
      if (r.status === 200 && r.json) {
        const j = r.json, p = j.page || {}, v = (j.verdicts && j.verdicts.overall) || {};
        const reqs = (j.data && j.data.requests) || [];
        const chain = [];
        const first = reqs[0] && reqs[0].response && reqs[0].response.response;
        if (reqs[0] && reqs[0].request && reqs[0].request.redirectResponse) chain.push(reqs[0].request.redirectResponse.url);
        return {
          status: 'ok', uuid, reportUrl, url, screenshot: 'https://urlscan.io/screenshots/' + uuid + '.png',
          finalUrl: p.url || '', domain: p.domain || '', ip: p.ip || '', country: p.country || '', server: p.server || '', title: p.title || '',
          asn: p.asnname || '', tlsIssuer: p.tlsIssuer || '', tlsAgeDays: p.tlsAgeDays, malicious: !!v.malicious, score: v.score || 0,
          brands: (v.brands || []).map((b) => (b && b.name) || b).filter(Boolean), categories: v.categories || [], requests: reqs.length,
          status_code: first ? first.status : null, redirected: !!(p.url && p.url !== url), chain
        };
      }
      if (r.status !== 404) return { status: 'error', error: 'HTTP ' + r.status, uuid, reportUrl, url };
    }
    return { status: 'pending', uuid, reportUrl, url };
  }

  // ---------------------------------------------------------------- key test ---

  /** One cheap call to check a key before saving it. Returns { ok, message }. */
  async function testKey(provider, key) {
    key = String(key || '').trim();
    if (!key) return { ok: false, message: 'Paste a key first' };
    let r;
    const verdict = (okText) => {
      if (r.status === 200 || (provider === 'greynoise' && r.status === 404)) return { ok: true, message: okText };
      if (r.status === 401 || r.status === 403) return { ok: false, message: 'Key rejected: check you copied the whole key' };
      if (r.status === 429) return { ok: true, message: 'Key works, but its quota is used up for now' };
      return { ok: false, message: r.error ? `Could not reach the service (${r.error})` : `Unexpected answer (HTTP ${r.status})` };
    };
    if (provider === 'vt') {
      vtCalls.push(Date.now()); // counts against the 4/min budget
      r = await http('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8', { headers: { 'x-apikey': key } });
      return verdict('VirusTotal connected: hash, IP, domain and URL verdicts from 70+ engines are on');
    }
    if (provider === 'abuseipdb') {
      r = await http('https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8', { headers: { Key: key, Accept: 'application/json' } });
      return verdict('AbuseIPDB connected: IP abuse score, report count and Tor detection are on');
    }
    if (provider === 'abusech') {
      r = await http('https://urlhaus-api.abuse.ch/v1/host/', { method: 'POST', headers: { 'Auth-Key': key, 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'host=example.com' });
      return verdict('abuse.ch connected: URLhaus, ThreatFox (C2) and MalwareBazaar are on');
    }
    if (provider === 'urlscan') {
      r = await http('https://urlscan.io/user/quotas/', { headers: { 'API-Key': key } });
      const res = verdict('urlscan.io connected: "Detonate safely" is on');
      const day = r.json && r.json.limits && r.json.limits.unlisted && r.json.limits.unlisted.day;
      if (res.ok && day && day.remaining != null) res.message += ` (${day.remaining} scans left today)`;
      return res;
    }
    if (provider === 'greynoise') {
      r = await http('https://api.greynoise.io/v3/community/8.8.8.8', { headers: { key } });
      return verdict('GreyNoise key works: higher daily limit');
    }
    return { ok: false, message: 'Unknown provider' };
  }

  /** Cheap, no-network status for many IOCs (page highlighting): memory, phishing feed, last verdict. */
  async function quickLook(values, cfg) {
    const mem = await memoryList();
    const client = (await settings()).activeClient;
    const keys = values.map((v) => 'ia:' + v.value);
    const last = keys.length ? await chrome.storage.local.get(keys) : {};
    return values.map((v) => {
      const m = memoryMatches(mem, v.type, v.value, client).filter((x) => !x.expired)[0];
      const dom = I.domainOf(v.type, v.value);
      const feed = !!(dom && cfg && cfg.blockedSet && A.hostInList(dom, cfg.blockedSet));
      const l = last['ia:' + v.value];
      const lastV = l && l.exp > Date.now() ? l.verdict : '';
      const internal = v.group === 'ip' && I.isPrivateIp(v.value);
      const state = m ? (m.verdict === 'note' ? 'known' : m.verdict) : feed ? 'malicious' : lastV || (internal ? 'internal' : '');
      return { value: v.value, state, note: m ? m._desc : feed ? 'In SOCLens phishing feed' : '' };
    });
  }

  root.VSSources = { DEFAULTS, settings, saveSettings, investigate, detonate, quickLook, testKey, memoryList, memorySave, memoryConfirm, memoryDelete, memoryImport, memoryMatches, memoryContext, sweepCache, src };
})(typeof globalThis !== 'undefined' ? globalThis : this);
