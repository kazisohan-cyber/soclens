/*
 * SOCLens service worker: navigation guard, page verdicts, credential guard,
 * email verdicts, event log + SOC reporting, remote blocklist sync, domain-age lookups.
 */
importScripts('lib/analyzer.js', 'lib/config.js', 'lib/ioc.js', 'lib/memory.js', 'lib/engine.js', 'lib/sources.js');
const A = self.VSAnalyzer;
const VERSION = chrome.runtime.getManifest().version;
const BYPASS_MINUTES = 60;
const MAX_EVENTS = 200;
const MAX_QUEUE = 500;
const PBKDF2_ITER = 100000;

// ------------------------------------------------------------- config ---

let cfgPromise = null;
function cfg() { return (cfgPromise = cfgPromise || VSConfig.get()); }
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'managed' || ['settings', 'userAllowed', 'remoteBlock', 'remotePolicy', 'enrollment', 'consent'].some((k) => k in changes)) cfgPromise = null;
});

async function installId() {
  let { installId } = await chrome.storage.local.get('installId');
  if (!installId) { installId = crypto.randomUUID(); await chrome.storage.local.set({ installId }); }
  return installId;
}

// ------------------------------------------------------- tab verdicts ---

async function setVerdict(tabId, v) {
  await chrome.storage.session.set({ ['tab:' + tabId]: v });
  const color = v.level === 'block' ? '#c62828' : v.level === 'warn' ? '#ef6c00' : '#2e7d32';
  const text = v.level === 'block' || v.level === 'warn' ? '!' : '';
  try {
    await chrome.action.setBadgeBackgroundColor({ tabId, color });
    await chrome.action.setBadgeText({ tabId, text });
    await chrome.action.setTitle({ tabId, title: `SOCLens — ${labelOf(v.level)}${v.score ? ' (' + v.score + ')' : ''}` });
  } catch (_) { /* tab gone */ }
}
async function getVerdict(tabId) { return (await chrome.storage.session.get('tab:' + tabId))['tab:' + tabId] || null; }
chrome.tabs.onRemoved.addListener((tabId) => chrome.storage.session.remove('tab:' + tabId));

function labelOf(level) {
  return { block: 'Dangerous', warn: 'Suspicious', caution: 'Low trust', safe: 'No threats found' }[level] || level;
}

async function isBypassed(host) {
  const { bypass = {} } = await chrome.storage.session.get('bypass');
  return (bypass[host] || 0) > Date.now();
}

function blockPageUrl(v, kind) {
  const data = { url: v.url, host: v.host, score: v.score, reasons: v.reasons.slice(0, 8), brand: v.brand, kind };
  return chrome.runtime.getURL('pages/blocked.html') + '#' + encodeURIComponent(JSON.stringify(data));
}

// ---------------------------------------------------- navigation guard ---

chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0 || d.tabId < 0 || !/^https?:/i.test(d.url)) return;
  const c = await cfg();
  const v = A.analyzeUrl(d.url, c);
  if (!v.allow && await isBypassed(v.host)) { v.bypassed = true; v.level = 'warn'; }
  await setVerdict(d.tabId, v);
  if (v.level === 'block') {
    chrome.tabs.update(d.tabId, { url: blockPageUrl(v, 'url') });
    logEvent({ type: 'url_blocked', severity: 'high', url: d.url, host: v.host, score: v.score, reasons: v.reasons, brand: v.brand });
  }
});

// ------------------------------------------------------- domain age ---

async function domainAgeDays(domain) {
  if (!domain || !domain.includes('.') || A.FREE_HOSTING.some((h) => domain.endsWith('.' + h)) || /^[\d.]+$/.test(domain)) return null;
  const { rdap = {} } = await chrome.storage.local.get('rdap');
  const hit = rdap[domain];
  if (hit && Date.now() - hit.t < 7 * 864e5) return hit.created ? Math.floor((Date.now() - hit.created) / 864e5) : null;
  let created = null;
  try {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 3500);
    const r = await fetch('https://rdap.org/domain/' + encodeURIComponent(domain), { signal: ctl.signal, credentials: 'omit' });
    clearTimeout(timer);
    if (r.ok) {
      const j = await r.json();
      const ev = (j.events || []).find((e) => e.eventAction === 'registration');
      if (ev && ev.eventDate) created = Date.parse(ev.eventDate) || null;
    }
  } catch (_) { /* offline or unsupported TLD */ }
  rdap[domain] = { created, t: Date.now() };
  const keys = Object.keys(rdap);
  if (keys.length > 500) keys.sort((a, b) => rdap[a].t - rdap[b].t).slice(0, keys.length - 500).forEach((k) => delete rdap[k]);
  await chrome.storage.local.set({ rdap });
  return created ? Math.floor((Date.now() - created) / 864e5) : null;
}

// ----------------------------------------------------- credential guard ---

async function pbkdf2(value, saltB64) {
  const salt = Uint8Array.from(atob(saltB64), (ch) => ch.charCodeAt(0));
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(value), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' }, key, 256);
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

function trustedForCreds(host, c) {
  return A.hostInList(host, c.corporateDomains) || A.hostInList(host, c.corporateLoginDomains) || A.hostInList(host, c.allowedDomains);
}

async function credContext(host) {
  const c = await cfg();
  const { creds = [] } = await chrome.storage.local.get('creds');
  return {
    enabled: c.credentialGuard,
    enrollHere: c.credentialGuard && (A.hostInList(host, c.corporateLoginDomains) || A.hostInList(host, c.corporateDomains)),
    trusted: trustedForCreds(host, c),
    lens: [...new Set(creds.map((x) => x.len))]
  };
}

async function credEnroll(host, value) {
  const c = await cfg();
  if (!c.credentialGuard || typeof value !== 'string' || value.length < 8) return false;
  if (!(A.hostInList(host, c.corporateLoginDomains) || A.hostInList(host, c.corporateDomains))) return false;
  const { creds = [] } = await chrome.storage.local.get('creds');
  for (const x of creds) if (x.len === value.length && await pbkdf2(value, x.salt) === x.hash) { x.ts = Date.now(); await chrome.storage.local.set({ creds }); return true; }
  const salt = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  creds.unshift({ salt, hash: await pbkdf2(value, salt), len: value.length, ts: Date.now(), host });
  await chrome.storage.local.set({ creds: creds.slice(0, 3) }); // keep current + 2 previous passwords
  return true;
}

async function credCheck(host, url, value) {
  const c = await cfg();
  if (!c.credentialGuard || typeof value !== 'string' || trustedForCreds(host, c)) return { match: false };
  const { creds = [] } = await chrome.storage.local.get('creds');
  for (const x of creds) {
    if (x.len === value.length && await pbkdf2(value, x.salt) === x.hash) {
      logEvent({ type: 'credential_reuse_blocked', severity: 'critical', url, host,
        reasons: ['Corporate password typed on a site outside the organisation'] });
      return { match: true };
    }
  }
  return { match: false };
}

// ------------------------------------------------------- events + SOC ---

async function logEvent(ev) {
  const c = await cfg();
  const full = Object.assign({
    id: crypto.randomUUID(), ts: new Date().toISOString(), version: VERSION,
    tenantId: c.tenantId || null, userId: c.userId || null, installId: await installId(), ua: navigator.userAgent
  }, ev);
  if (full.url) full.urlDefanged = A.defang(full.url);
  const { events = [], queue = [] } = await chrome.storage.local.get(['events', 'queue']);
  events.unshift(full);
  const upd = { events: events.slice(0, MAX_EVENTS) };
  const send = reportsOn(c);
  if (send) { queue.push(full); upd.queue = queue.slice(-MAX_QUEUE); }
  await chrome.storage.local.set(upd);
  if (send) flush();
  return full;
}

// Events leave the device only when connected and the user agreed to share reports.
function reportsOn(c) { return !!c.apiEndpoint && c.reporting !== 'off'; }

function authHeaders(c) {
  const h = { Authorization: 'Bearer ' + c.apiKey };
  if (c.tenantId) h['X-SOCLens-Tenant'] = c.tenantId;
  return h;
}

// A revoked install token stops all traffic until the user re-installs; never re-enroll silently.
async function checkRevoked(r) {
  if (r.status !== 401) return false;
  const c = await cfg();
  if (c.mode !== 'community') return false;
  let detail = '';
  try { detail = (await r.clone().json()).detail || ''; } catch (_) { /* not JSON */ }
  if (detail === 'install revoked' || detail === 'invalid install token') {
    const { enrollment } = await chrome.storage.local.get('enrollment');
    if (enrollment) await chrome.storage.local.set({ enrollment: Object.assign(enrollment, { revoked: true }), queue: [] });
    return true;
  }
  return false;
}

// ------------------------------------------------- community enrollment ---

const ENROLL_RETRY_MS = 6 * 3600e3;

async function ensureEnrolled() {
  const c = await cfg();
  if (c.mode === 'managed' || !c.consent || !c.communityEndpoint) return;
  const { enrollment, enrollFail = 0 } = await chrome.storage.local.get(['enrollment', 'enrollFail']);
  if (enrollment && (enrollment.token || enrollment.revoked)) return;
  if (Date.now() - enrollFail < ENROLL_RETRY_MS) return;
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const r = await fetch(c.communityEndpoint + '/v1/enroll', {
        method: 'POST', credentials: 'omit', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ installId: await installId(), nickname: c.consent.nickname || '', reporting: c.consent.reporting,
          version: VERSION, browser: browserLabel(), ua: navigator.userAgent })
      });
      if (r.status === 409) { await chrome.storage.local.remove('installId'); continue; } // id taken: new id, retry
      if (!r.ok) break;
      const j = await r.json();
      await chrome.storage.local.set({
        enrollment: { token: j.token, tenantId: j.tenantId, installId: j.installId, at: Date.now() },
        remotePolicy: j.policy || {}, enrollFail: 0
      });
      syncBlocklist();
      return;
    } catch (_) { break; }
  }
  await chrome.storage.local.set({ enrollFail: Date.now() });
}

function browserLabel() {
  const ua = navigator.userAgent;
  const b = /Edg\//.test(ua) ? 'Edge' : /OPR\//.test(ua) ? 'Opera' : /Brave/.test(ua) ? 'Brave' : 'Chrome';
  const os = /Windows/.test(ua) ? 'Windows' : /Mac OS X/.test(ua) ? 'macOS' : /Android/.test(ua) ? 'Android' : /CrOS/.test(ua) ? 'ChromeOS' : /Linux/.test(ua) ? 'Linux' : 'Other';
  return b + '/' + os;
}

async function syncConfig() {
  const c = await cfg();
  if (!c.apiEndpoint) return;
  try {
    const q = c.mode === 'community' ? '?reporting=' + c.reporting : '';
    const r = await fetch(c.apiEndpoint + '/v1/config' + q, { credentials: 'omit', headers: authHeaders(c) });
    if (await checkRevoked(r) || !r.ok) return;
    const j = await r.json();
    await chrome.storage.local.set({ remotePolicy: j.policy || {} });
  } catch (_) { /* keep last policy */ }
}

let flushing = false;
async function flush() {
  if (flushing) return;
  flushing = true;
  try {
    const c = await cfg();
    const { queue = [] } = await chrome.storage.local.get('queue');
    if (!queue.length) return;
    if (!reportsOn(c)) { if (c.mode !== 'managed') await chrome.storage.local.set({ queue: [] }); return; }
    const batch = queue.slice(0, 50);
    const r = await fetch(c.apiEndpoint + '/v1/events', {
      method: 'POST', credentials: 'omit',
      headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders(c)),
      body: JSON.stringify({ events: batch })
    });
    if (await checkRevoked(r)) return;
    if (r.ok) {
      const { queue: now = [] } = await chrome.storage.local.get('queue');
      const sent = new Set(batch.map((e) => e.id));
      await chrome.storage.local.set({ queue: now.filter((e) => !sent.has(e.id)), lastSync: Date.now() });
    }
  } catch (_) { /* retried by alarm */ } finally { flushing = false; }
}

async function syncBlocklist() {
  const c = await cfg();
  if (!c.apiEndpoint) return;
  try {
    const { remoteBlock } = await chrome.storage.local.get('remoteBlock');
    const headers = authHeaders(c);
    // Only reuse the ETag for the same backend, or a switch of tenant could keep a stale list.
    if (remoteBlock && remoteBlock.etag && remoteBlock.src === c.apiEndpoint + '|' + c.tenantId) headers['If-None-Match'] = remoteBlock.etag;
    const r = await fetch(c.apiEndpoint + '/v1/blocklist', { credentials: 'omit', headers });
    if (await checkRevoked(r)) return;
    if (r.status === 304) { await chrome.storage.local.set({ remoteBlock: Object.assign(remoteBlock, { t: Date.now() }) }); return; }
    if (!r.ok) return;
    const j = await r.json();
    const domains = VSConfig.cleanList(j.domains || []);
    await chrome.storage.local.set({ remoteBlock: { domains, t: Date.now(), etag: r.headers.get('ETag') || '', src: c.apiEndpoint + '|' + c.tenantId } });
  } catch (_) { /* keep last good list */ }
}

async function syncAll() {
  await ensureEnrolled();
  await syncConfig();
  await syncBlocklist();
}

function setupAlarms() {
  chrome.alarms.create('flush', { periodInMinutes: 1 });
  chrome.alarms.create('blocklist', { periodInMinutes: 15, delayInMinutes: 0.1 });
  chrome.alarms.create('heartbeat', { periodInMinutes: HEARTBEAT_MIN, delayInMinutes: 0.2 });
  chrome.alarms.create('intelSweep', { periodInMinutes: 360, delayInMinutes: 5 });
  setupAnalyst();
}
chrome.runtime.onInstalled.addListener((d) => {
  setupAlarms();
  // First install: ask for consent before anything is sent (unless an admin configured a backend).
  if (d.reason === 'install') {
    cfg().then((c) => { if (c.mode !== 'managed') chrome.tabs.create({ url: chrome.runtime.getURL('pages/welcome.html') }); });
  }
});
chrome.runtime.onStartup.addListener(setupAlarms);
chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === 'flush') { flush(); flushAuth(); }
  if (a.name === 'blocklist') syncAll();
  if (a.name === 'heartbeat') sweepStaleAuth().then(heartbeat);
  if (a.name === 'intelSweep') VSSources.sweepCache();
});

// ------------------------------------------------- SOC analyst assistant ---
// Right-click "Investigate", side panel, IOC highlighting on analyst sites. Lookups go from this
// browser straight to the intel sources; nothing passes through any SOCLens server.

function setupAnalyst() {
  if (chrome.sidePanel && chrome.sidePanel.setPanelBehavior) chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }).catch(() => {});
  // GreyNoise's community API refuses requests that carry a browser Origin header. Drop it, but only for
  // this extension's own background requests (tabId -1), never for web pages.
  if (chrome.declarativeNetRequest) {
    chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [9101], addRules: [{ id: 9101, priority: 1,
      action: { type: 'modifyHeaders', requestHeaders: [{ header: 'origin', operation: 'remove' }] },
      condition: { requestDomains: ['api.greynoise.io'], tabIds: [-1], resourceTypes: ['xmlhttprequest', 'other'] } }] }).catch(() => {});
  }
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: 'sl-investigate', title: 'SOCLens: Investigate "%s"', contexts: ['selection'] });
    chrome.contextMenus.create({ id: 'sl-investigate-link', title: 'SOCLens: Investigate this link', contexts: ['link'] });
    chrome.contextMenus.create({ id: 'sl-panel', title: 'SOCLens: Open analyst panel', contexts: ['page', 'action'] });
  });
}

// sidePanel.open() must run inside the user gesture, so call it before any await.
function openPanel(tab, query) {
  let opened = Promise.resolve(false);
  try {
    if (chrome.sidePanel && tab) opened = chrome.sidePanel.open(tab.id >= 0 ? { tabId: tab.id } : { windowId: tab.windowId }).then(() => true, () => false);
  } catch (_) { /* no gesture */ }
  if (query) chrome.storage.session.set({ analystQuery: { value: String(query).slice(0, 20000), t: Date.now() } });
  return opened.then((ok) => {
    if (!ok) chrome.tabs.create({ url: chrome.runtime.getURL('pages/analyst.html') + (query ? '#q=' + encodeURIComponent(String(query).slice(0, 4000)) : '') });
    return ok;
  });
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId === 'sl-investigate') openPanel(tab, info.selectionText);
  else if (info.menuItemId === 'sl-investigate-link') openPanel(tab, info.linkUrl);
  else if (info.menuItemId === 'sl-panel') openPanel(tab, null);
});

async function onAnalystSite(url) {
  const s = await VSSources.settings();
  const host = hostOf(url || '');
  return !!host && s.highlight && A.hostInList(host, s.highlightSites);
}

// ----------------------------------------------- SOCLens Verify (v0.3) ---
// Records sign-ins on identity-provider pages only (never other browsing), sends a heartbeat so the
// console knows the browser was online, and shows "Was this you?" prompts for SIEM identity alerts.

const IDP_MS = ['login.microsoftonline.com', 'login.microsoft.com', 'login.live.com', 'device.login.microsoftonline.com'];
const IDP_GOOGLE = ['accounts.google.com'];
const MAIL_CHAT = ['mail.google.com', 'outlook.office.com', 'outlook.office365.com', 'outlook.live.com', 'outlook.cloud.microsoft',
  'teams.microsoft.com', 'teams.live.com', 'teams.cloud.microsoft', 'web.whatsapp.com', 'web.telegram.org', 'app.slack.com',
  'discord.com', 'www.linkedin.com', 'www.facebook.com', 'www.messenger.com'];
const AUTH_STALE_MS = 10 * 60e3;
const HEARTBEAT_MIN = 5;

function idpOf(host, c) {
  if (IDP_MS.includes(host)) return 'microsoft';
  if (IDP_GOOGLE.includes(host)) return 'google';
  if (A.hostMatches(host, 'okta.com') || A.hostMatches(host, 'oktapreview.com')) return 'okta';
  if (A.hostInList(host, c.corporateLoginDomains)) return 'corporate';
  return null;
}

function isDeviceCodePage(u) {
  const p = u.pathname.toLowerCase();
  return (IDP_MS.includes(u.hostname) && (p.includes('/deviceauth') || p.includes('/remoteconnect')))
    || (/(^|\.)microsoft\.com$/.test(u.hostname) && p.startsWith('/devicelogin'))
    || (u.hostname === 'aka.ms' && p.startsWith('/devicelogin'))
    || (/(^|\.)google\.com$/.test(u.hostname) && p.startsWith('/device'));
}

function authDetails(u, idp) {
  const q = u.searchParams;
  const p = u.pathname.toLowerCase();
  const flow = isDeviceCodePage(u) ? 'device_code'
    : (p.includes('consent') || q.get('prompt') === 'consent') ? 'consent' : 'password';
  let tenantHint = q.get('domain_hint') || q.get('hd') || '';
  if (idp === 'microsoft') {
    const seg = u.pathname.split('/')[1] || '';
    if (seg && !['common', 'organizations', 'consumers', 'oauth2', 'login.srf', 'ppsecure'].includes(seg.toLowerCase())) tenantHint = seg;
  }
  const hint = (q.get('login_hint') || q.get('username') || '').toLowerCase();
  return { flow, tenantHint: tenantHint.slice(0, 255), accountHint: hint.includes('@') ? hint.slice(0, 320) : '' };
}

async function tabState(tabId) { return (await chrome.storage.session.get('auth:' + tabId))['auth:' + tabId] || null; }

async function finishAuth(tabId, outcome) {
  const a = await tabState(tabId);
  if (!a) return;
  await chrome.storage.session.remove('auth:' + tabId);
  const c = await cfg();
  if (!c.verifyEnabled) return;
  const ev = {
    id: a.id, ts: new Date(a.ts).toISOString(), type: 'auth_event', idp: a.idp, host: a.host, tenantHint: a.tenantHint,
    accountHint: a.accountHint, flow: a.flow, outcome, referrerHost: a.referrerHost, openerHost: a.openerHost,
    tenantId: c.tenantId || null, userId: c.userId || null, installId: await installId(), version: VERSION, ua: navigator.userAgent
  };
  if (outcome === 'success' && a.accountHint) {
    const { authAccounts = [] } = await chrome.storage.local.get('authAccounts');
    if (!authAccounts.includes(a.accountHint)) await chrome.storage.local.set({ authAccounts: [a.accountHint].concat(authAccounts).slice(0, 10) });
  }
  const { authQueue = [] } = await chrome.storage.local.get('authQueue');
  authQueue.push(ev);
  await chrome.storage.local.set({ authQueue: authQueue.slice(-200) });
  flushAuth();
}

let flushingAuth = false;
async function flushAuth() {
  if (flushingAuth) return;
  flushingAuth = true;
  try {
    const c = await cfg();
    const { authQueue = [] } = await chrome.storage.local.get('authQueue');
    if (!authQueue.length || !c.verifyEnabled || !c.apiEndpoint) return;
    const batch = authQueue.slice(0, 50);
    const r = await fetch(c.apiEndpoint + '/v1/auth-events', {
      method: 'POST', credentials: 'omit', headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders(c)),
      body: JSON.stringify({ events: batch })
    });
    if (r.ok) {
      const { authQueue: now = [] } = await chrome.storage.local.get('authQueue');
      const sent = new Set(batch.map((e) => e.id));
      await chrome.storage.local.set({ authQueue: now.filter((e) => !sent.has(e.id)) });
    }
  } catch (_) { /* retried by alarm */ } finally { flushingAuth = false; }
}

// Top-frame commits: start/refresh a pending sign-in on IdP pages; leaving the IdP back to an app = success.
chrome.webNavigation.onCommitted.addListener(async (d) => {
  if (d.frameId !== 0 || d.tabId < 0 || !/^https?:/i.test(d.url)) return;
  let u;
  try { u = new URL(d.url); } catch (_) { return; }
  const host = u.hostname.toLowerCase();
  const prevKey = 'host:' + d.tabId;
  const prev = (await chrome.storage.session.get(prevKey))[prevKey] || '';
  await chrome.storage.session.set({ [prevKey]: host });
  const c = await cfg();
  const openKey = 'opener:' + d.tabId;
  const opener = (await chrome.storage.session.get(openKey))[openKey] || '';
  // Device-code guard protects everyone (warning stays on the device unless reports are shared).
  if (isDeviceCodePage(u)) await deviceCodeSeen(d.tabId, { host, openerHost: opener, referrerHost: prev });
  if (!c.verifyEnabled) return;
  const idp = idpOf(host, c) || (isDeviceCodePage(u) ? 'microsoft' : null);
  const a = await tabState(d.tabId);
  if (idp) {
    const det = authDetails(u, idp);
    const next = a && Date.now() - a.ts < AUTH_STALE_MS ? a : {
      id: crypto.randomUUID(), idp, host, flow: det.flow, tenantHint: '', accountHint: '',
      referrerHost: prev && !idpOf(prev, c) ? prev : '', openerHost: opener
    };
    next.ts = Date.now();
    next.host = host;
    if (det.flow !== 'password') next.flow = det.flow;
    next.tenantHint = det.tenantHint || next.tenantHint;
    next.accountHint = det.accountHint || next.accountHint;
    await chrome.storage.session.set({ ['auth:' + d.tabId]: next });
  } else if (a) {
    await finishAuth(d.tabId, 'success');
  }
});

chrome.webNavigation.onCreatedNavigationTarget.addListener(async (d) => {
  const src = await chrome.tabs.get(d.sourceTabId).catch(() => null);
  const host = src && src.url ? hostOf(src.url) : '';
  if (host) await chrome.storage.session.set({ ['opener:' + d.tabId]: host });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  finishAuth(tabId, 'unknown');
  chrome.storage.session.remove(['host:' + tabId, 'opener:' + tabId, 'dc:' + tabId]);
});

async function sweepStaleAuth() {
  const all = await chrome.storage.session.get(null);
  for (const [k, v] of Object.entries(all)) {
    if (k.startsWith('auth:') && v && Date.now() - v.ts > AUTH_STALE_MS) await finishAuth(Number(k.slice(5)), 'unknown');
  }
}

// Device-code phishing: the code page opened from a mail or chat link.
async function deviceCodeSeen(tabId, a) {
  const from = [a.openerHost, a.referrerHost].find((h) => h && MAIL_CHAT.some((m) => A.hostMatches(h, m)));
  await chrome.storage.session.set({ ['dc:' + tabId]: { from: from || '', t: Date.now() } });
  if (from && await once('dc:' + tabId + ':' + from, 30)) {
    logEvent({ type: 'device_code_warning', severity: 'high', host: a.host, url: 'https://' + a.host + '/',
      reasons: [`Device-code sign-in page opened from ${from}`, 'Entering a code someone sent you gives them your account'], from });
  }
}

async function heartbeat() {
  const c = await cfg();
  if (!c.verifyEnabled || !c.apiEndpoint) return;
  try {
    const { authAccounts = [] } = await chrome.storage.local.get('authAccounts');
    const r = await fetch(c.apiEndpoint + '/v1/heartbeat', {
      method: 'POST', credentials: 'omit', headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders(c)),
      body: JSON.stringify({ installId: await installId(), userId: c.userId || null, accounts: authAccounts, ts: new Date().toISOString(),
        version: VERSION, browser: browserLabel(), ua: navigator.userAgent })
    });
    if (!r.ok) return;
    const j = await r.json();
    await chrome.storage.local.set({ verifyPending: j.verifyRequests || [], binding: j.binding || null, lastHeartbeat: Date.now() });
    for (const vr of j.verifyRequests || []) await promptVerify(vr);
  } catch (_) { /* offline: next alarm */ }
}

async function promptVerify(vr) {
  const { verifyShown = {} } = await chrome.storage.local.get('verifyShown');
  if (verifyShown[vr.id]) return;
  verifyShown[vr.id] = Date.now();
  for (const k of Object.keys(verifyShown)) if (Date.now() - verifyShown[k] > 864e5) delete verifyShown[k];
  await chrome.storage.local.set({ verifyShown });
  try {
    chrome.notifications.create('verify:' + vr.id, {
      type: 'basic', iconUrl: chrome.runtime.getURL('icons/icon128.png'), title: 'SOCLens: was this you?',
      message: vr.prompt, contextMessage: 'Your security team is asking. Only answer here, never in an email.',
      buttons: [{ title: 'Yes, it was me' }, { title: 'No, not me' }], requireInteraction: true, priority: 2
    });
  } catch (_) { /* notifications unavailable: the popup and verify page still show it */ }
}

async function answerVerify(id, answer) {
  const c = await cfg();
  const { verifyPending = [] } = await chrome.storage.local.get('verifyPending');
  const vr = verifyPending.find((v) => v.id === id);
  if (!vr || !['yes', 'no'].includes(answer) || !c.apiEndpoint) return { ok: false };
  let status = 0;
  try {
    const r = await fetch(c.apiEndpoint + vr.answerUrl, {
      method: 'POST', credentials: 'omit', headers: Object.assign({ 'Content-Type': 'application/json' }, authHeaders(c)),
      body: JSON.stringify({ installId: await installId(), answer, ts: new Date().toISOString() })
    });
    status = r.status;
  } catch (_) {
    logEvent({ type: 'verify_answer', severity: 'low', verifyId: id, answer }); // offline: goes with the next event batch
    status = 202;
  }
  if (status === 200 || status === 202 || status === 409 || status === 404) {
    await chrome.storage.local.set({ verifyPending: verifyPending.filter((v) => v.id !== id) });
    try { chrome.notifications.clear('verify:' + id); } catch (_) { /* gone */ }
  }
  return { ok: status === 200 || status === 202, status };
}

if (chrome.notifications) {
  chrome.notifications.onButtonClicked.addListener((nid, idx) => {
    if (nid.startsWith('verify:')) answerVerify(nid.slice(7), idx === 0 ? 'yes' : 'no');
  });
  chrome.notifications.onClicked.addListener((nid) => {
    if (nid.startsWith('verify:')) chrome.tabs.create({ url: chrome.runtime.getURL('pages/verify.html') });
  });
}

// ---------------------------------------------------------- dedupe ---

async function once(key, minutes) {
  const { seen = {} } = await chrome.storage.session.get('seen');
  const now = Date.now();
  if ((seen[key] || 0) > now) return false;
  seen[key] = now + minutes * 60000;
  await chrome.storage.session.set({ seen });
  return true;
}

// ---------------------------------------------------------- messages ---

const handlers = {
  async pageSignals(msg, sender) {
    const tab = sender.tab;
    if (!tab || sender.frameId !== 0) return null;
    const c = await cfg();
    if (!c.pageScanner) return null;
    const urlV = A.analyzeUrl(sender.url, c);
    if (urlV.allow) { await setVerdict(tab.id, urlV); return { level: 'safe' }; }
    const signals = Object.assign({}, msg.signals);
    if (c.domainAgeLookup && (signals.hasPassword || urlV.score >= 15)) {
      const age = await domainAgeDays(urlV.domain);
      if (age !== null) signals.ageDays = age;
    }
    const v = A.analyzePage(urlV, signals, c);
    const bypassed = await isBypassed(v.host);
    if (bypassed && v.level === 'block') { v.bypassed = true; v.level = 'warn'; }
    await setVerdict(tab.id, v);
    if (v.level === 'block') {
      chrome.tabs.update(tab.id, { url: blockPageUrl(v, 'page') });
      logEvent({ type: 'page_blocked', severity: 'high', url: sender.url, host: v.host, score: v.score, reasons: v.reasons, brand: v.brand });
    } else if (v.level === 'warn' && await once('warn:' + v.host, 60)) {
      logEvent({ type: 'page_warned', severity: 'medium', url: sender.url, host: v.host, score: v.score, reasons: v.reasons, brand: v.brand });
    }
    return { level: v.level, score: v.score, reasons: v.reasons, bypassed: !!v.bypassed, allowBypass: c.allowUserBypass };
  },

  async credContext(msg, sender) { return credContext(hostOf(sender.url)); },
  async credEnroll(msg, sender) { return credEnroll(hostOf(sender.url), msg.value); },
  async credCheck(msg, sender) { return credCheck(hostOf(sender.url), sender.url, msg.value); },

  async scanEmail(msg) {
    const c = await cfg();
    if (!c.webmailScanner) return null;
    const r = A.analyzeEmail(msg.email, c);
    if ((r.level === 'warn' || r.level === 'block') && await once('mail:' + (msg.email.senderEmail || '') + '|' + (msg.email.subject || ''), 720)) {
      logEvent({
        type: 'phishing_email_detected', severity: r.level === 'block' ? 'high' : 'medium', score: r.score, reasons: r.reasons,
        email: { sender: msg.email.senderEmail, senderName: msg.email.senderName, subject: msg.email.subject, client: msg.email.client },
        links: r.links.filter((l) => !l.verdict.allow && l.verdict.score >= 15).slice(0, 10).map((l) => ({ url: A.defang(l.real), score: l.verdict.score }))
      });
    }
    return {
      level: r.level, score: r.score, reasons: r.reasons, allowBypass: c.allowUserBypass,
      links: r.links.map((l) => ({ href: l.href, real: l.real, level: l.verdict.level, score: l.verdict.score, reasons: l.verdict.reasons, allow: l.verdict.allow }))
    };
  },

  async report(msg, sender) {
    const ev = { type: msg.kind === 'email' ? 'user_report_email' : 'user_report_site', severity: 'medium', note: msg.note || '' };
    if (msg.url) { ev.url = msg.url; ev.host = hostOf(msg.url); }
    if (msg.email) ev.email = msg.email;
    if (msg.links) ev.links = msg.links.slice(0, 20).map(A.defang);
    await logEvent(ev);
    return { ok: true, sentToSoc: reportsOn(await cfg()) };
  },

  async bypass(msg) {
    const c = await cfg();
    if (!c.allowUserBypass) return { ok: false };
    const host = hostOf(msg.url);
    const { bypass = {} } = await chrome.storage.session.get('bypass');
    bypass[host] = Date.now() + BYPASS_MINUTES * 60000;
    await chrome.storage.session.set({ bypass });
    logEvent({ type: 'user_bypass', severity: 'medium', url: msg.url, host, reasons: msg.reasons || [] });
    return { ok: true };
  },

  async trustSite(msg) {
    const c = await cfg();
    if (!c.allowUserBypass) return { ok: false };
    const host = hostOf(msg.url);
    const { userAllowed = [] } = await chrome.storage.local.get('userAllowed');
    if (!userAllowed.includes(host)) userAllowed.push(host);
    await chrome.storage.local.set({ userAllowed });
    logEvent({ type: 'user_trusted_site', severity: 'low', url: msg.url, host });
    return { ok: true };
  },

  async popupState(msg) {
    const c = await cfg();
    const tab = msg.tabId != null ? await chrome.tabs.get(msg.tabId).catch(() => null) : null;
    const { events = [], creds = [], queue = [], lastSync = 0 } = await chrome.storage.local.get(['events', 'creds', 'queue', 'lastSync']);
    let verdict = tab ? await getVerdict(tab.id) : null;
    if (tab && /^https?:/.test(tab.url || '') && (!verdict || verdict.url !== tab.url)) verdict = Object.assign(verdict || {}, A.analyzeUrl(tab.url, c));
    const { remoteBlock } = await chrome.storage.local.get('remoteBlock');
    return {
      verdict, url: tab && tab.url, events: events.slice(0, 60), enrolled: creds.length, queue: queue.length, lastSync,
      soc: !!c.apiEndpoint, tenantId: c.tenantId, allowBypass: c.allowUserBypass, credentialGuard: c.credentialGuard, version: VERSION,
      mode: c.mode, reporting: c.reporting, consent: !!c.consent, revoked: !!(c.enrollment && c.enrollment.revoked),
      blocklistSize: remoteBlock && remoteBlock.domains ? remoteBlock.domains.length : 0, blocklistAt: remoteBlock ? remoteBlock.t : 0,
      pageScanner: c.pageScanner, webmailScanner: c.webmailScanner, verifyEnabled: c.verifyEnabled, communityAvailable: !!c.communityEndpoint,
      loginDomain: (c.corporateLoginDomains || [])[0] || '', credLearned: creds[0] ? { host: creds[0].host, ts: creds[0].ts } : null,
      oldestQueued: queue.length ? Date.parse(queue[0].ts) || 0 : 0
    };
  },

  // Consent from the welcome page / popup: reporting 'full' (share reports) or 'off' (protect only).
  async setConsent(msg) {
    const { consent = {} } = await chrome.storage.local.get('consent');
    const nickname = String(msg.nickname != null ? msg.nickname : consent.nickname || '').trim().slice(0, 40);
    await chrome.storage.local.set({ consent: { reporting: msg.reporting === 'off' ? 'off' : 'full', nickname, at: Date.now() }, enrollFail: 0 });
    cfgPromise = null;
    if (msg.reporting === 'off') await chrome.storage.local.set({ queue: [] });
    await syncAll();
    const c = await cfg();
    return { ok: true, mode: c.mode, reporting: c.reporting };
  },

  // Verify: account typed on an IdP page (only IdP pages send this), device-code check, prompts.
  async authHint(msg, sender) {
    const tab = sender.tab;
    if (!tab || sender.frameId !== 0) return null;
    const c = await cfg();
    const host = hostOf(sender.url);
    const account = String(msg.account || '').trim().toLowerCase();
    if (!c.verifyEnabled || !idpOf(host, c) || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(account)) return null;
    const a = await tabState(tab.id);
    if (a) await chrome.storage.session.set({ ['auth:' + tab.id]: Object.assign(a, { accountHint: account.slice(0, 320), ts: Date.now() }) });
    return { ok: true };
  },
  async deviceCodeCheck(msg, sender) {
    if (!sender.tab) return null;
    return (await chrome.storage.session.get('dc:' + sender.tab.id))['dc:' + sender.tab.id] || null;
  },
  async verifyState() {
    const { verifyPending = [], binding = null, lastHeartbeat = 0 } = await chrome.storage.local.get(['verifyPending', 'binding', 'lastHeartbeat']);
    return { pending: verifyPending, binding, lastHeartbeat, enabled: (await cfg()).verifyEnabled };
  },
  async verifyAnswer(msg) { return answerVerify(msg.id, msg.answer); },

  // ---- SOC analyst assistant
  async investigate(msg, sender) {
    const fromPage = !(sender.url && sender.url.startsWith(chrome.runtime.getURL('')));
    if (fromPage && !(await onAnalystSite(sender.url))) return { error: 'SOCLens analyst tools are not enabled on this site' };
    return VSSources.investigate(String(msg.value || '').slice(0, 4096), await cfg());
  },
  async detonate(msg) { return VSSources.detonate(String(msg.value || '').slice(0, 4096)); },
  async analystSettings() { return VSSources.settings(); },
  async analystSave(msg) { return VSSources.saveSettings(msg.patch || {}); },
  async testKey(msg) { return VSSources.testKey(String(msg.provider || ''), String(msg.key || '')); },
  async memoryList() { return VSSources.memoryList(); },
  async memorySave(msg) { try { return { ok: true, item: await VSSources.memorySave(msg.entry || {}) }; } catch (e) { return { ok: false, error: e.message }; } },
  async memoryDelete(msg) { return VSSources.memoryDelete(msg.id); },
  async memoryConfirm(msg) { return VSSources.memoryConfirm(msg.id); },
  async memoryContext(msg) { return VSSources.memoryContext(String(msg.text || '').slice(0, 20000)); },
  async memoryImport(msg) { try { return Object.assign({ ok: true }, await VSSources.memoryImport(msg.items)); } catch (e) { return { ok: false, error: e.message }; } },
  async highlightInit(msg, sender) { return { enabled: !!sender.tab && await onAnalystSite(sender.url) }; },
  async quickLook(msg, sender) {
    if (!(await onAnalystSite(sender.url))) return [];
    return VSSources.quickLook((msg.values || []).slice(0, 400), await cfg());
  },
  async openPanel(msg, sender) { return openPanel(sender.tab, msg.value || null); },

  async exportEvents() { return (await chrome.storage.local.get('events')).events || []; },
  async clearCreds() { await chrome.storage.local.remove('creds'); return { ok: true }; },
  async flushNow() { await syncAll(); await flush(); await flushAuth(); await heartbeat(); return { ok: true }; }
};

function hostOf(u) { try { return new URL(u).hostname.toLowerCase(); } catch (_) { return ''; } }

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  const h = msg && handlers[msg.type];
  if (!h) return false;
  // Privileged actions only from our own extension pages.
  const fromExtensionPage = sender.url && sender.url.startsWith(chrome.runtime.getURL(''));
  if (['bypass', 'trustSite', 'popupState', 'setConsent', 'verifyState', 'verifyAnswer', 'exportEvents', 'clearCreds', 'flushNow',
    'detonate', 'testKey', 'analystSettings', 'analystSave', 'memoryList', 'memorySave', 'memoryDelete', 'memoryImport', 'memoryConfirm', 'memoryContext'].includes(msg.type) && !fromExtensionPage) { reply(null); return false; }
  Promise.resolve(h(msg, sender)).then(reply, (e) => reply({ error: String(e && e.message || e) }));
  return true;
});
