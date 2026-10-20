/*
 * SOCLens config: defaults <- user settings (storage.local) <- console policy (GET /v1/config)
 * <- admin policy (storage.managed). Admin policy always wins; keys set by policy are reported in
 * `_managed` (and console-pushed keys in `_remote`) so the UI can lock them.
 *
 * Connection modes:
 *   managed   - apiEndpoint + apiKey configured (by policy or by hand): business tenant
 *   community - a community server is configured (communityEndpoint): after the user's consent the
 *               extension enrolls itself there and gets its own revocable install token
 *   local     - default: no server at all, every protection and analyst tool runs on the device
 */
(function (root) {
  'use strict';

  // No community server is built in: the public extension never talks to any server unless the user
  // or their admin configures one (communityEndpoint, or apiEndpoint + apiKey for a company console).
  const COMMUNITY_ENDPOINT = '';

  const DEFAULTS = {
    // SOC / backend
    apiEndpoint: '',            // e.g. https://shield.example.com  (POST /v1/events, GET /v1/blocklist)
    apiKey: '',
    communityEndpoint: COMMUNITY_ENDPOINT, // optional self-enrolling community console, e.g. https://soclens.example.org
    tenantId: '',
    userId: '',                 // optional: pushed per user via policy so SOC can map alerts
    // Domains
    corporateDomains: [],       // your org's own domains (trusted everywhere, incl. credential guard)
    corporateLoginDomains: ['login.microsoftonline.com', 'login.live.com', 'accounts.google.com'],
    allowedDomains: [],
    blockedDomains: [],
    extraBrands: [],            // [{ name, domains:[...], keywords:[...], pageTerms:[...] }]
    // Behaviour
    warnThreshold: 40,
    blockThreshold: 70,
    credentialGuard: true,
    webmailScanner: true,
    pageScanner: true,
    domainAgeLookup: true,
    allowUserBypass: true,
    verifyEnabled: false        // SOCLens Verify: record IdP sign-ins + heartbeat (business tenants only)
  };

  const LIST_KEYS = ['corporateDomains', 'corporateLoginDomains', 'allowedDomains', 'blockedDomains'];
  // Keys the console may push (GET /v1/config -> policy).
  const REMOTE_KEYS = ['warnThreshold', 'blockThreshold', 'allowUserBypass', 'credentialGuard', 'webmailScanner',
    'pageScanner', 'domainAgeLookup', 'verifyEnabled'];

  function cleanList(v) {
    if (typeof v === 'string') v = v.split(/[\s,;]+/);
    if (!Array.isArray(v)) return [];
    return [...new Set(v.map((d) => String(d).trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^\*\./, ''))
      .filter(Boolean))];
  }

  async function get() {
    let managed = {};
    try { managed = (chrome.storage.managed && await chrome.storage.managed.get(null)) || {}; } catch (_) { managed = {}; }
    const local = await chrome.storage.local.get(['settings', 'userAllowed', 'remoteBlock', 'remotePolicy', 'enrollment', 'consent']);
    const user = local.settings || {};
    const remote = local.remotePolicy || {};
    const cfg = Object.assign({}, DEFAULTS);
    const remoteUsed = [];
    for (const k of Object.keys(DEFAULTS)) {
      if (k in managed) cfg[k] = managed[k];
      else if (REMOTE_KEYS.includes(k) && k in remote) { cfg[k] = remote[k]; remoteUsed.push(k); }
      else if (k in user) cfg[k] = user[k];
    }
    for (const k of LIST_KEYS) cfg[k] = cleanList(cfg[k]);
    cfg.allowedDomains = cleanList(cfg.allowedDomains.concat(local.userAllowed || []));
    cfg.blockedDomains = cleanList(cfg.blockedDomains.concat((local.remoteBlock && local.remoteBlock.domains) || []));
    cfg.blockedSet = new Set(cfg.blockedDomains);
    cfg.warnThreshold = Number(cfg.warnThreshold) || DEFAULTS.warnThreshold;
    cfg.blockThreshold = Number(cfg.blockThreshold) || DEFAULTS.blockThreshold;
    cfg.apiEndpoint = String(cfg.apiEndpoint || '').trim().replace(/\/+$/, '');
    cfg.communityEndpoint = /^https:\/\//i.test(String(cfg.communityEndpoint || '').trim()) ? String(cfg.communityEndpoint).trim().replace(/\/+$/, '') : '';
    cfg._managed = Object.keys(managed).filter((k) => k in DEFAULTS);
    cfg._remote = remoteUsed;

    const enr = local.enrollment;
    cfg.consent = local.consent || null;
    cfg.enrollment = enr ? { tenantId: enr.tenantId, installId: enr.installId, revoked: !!enr.revoked, at: enr.at } : null;
    if (cfg.apiEndpoint && cfg.apiKey) {
      cfg.mode = 'managed';
      cfg.reporting = 'full';
    } else if (cfg.communityEndpoint && cfg.consent && enr && enr.token && !enr.revoked) {
      cfg.mode = 'community';
      cfg.apiEndpoint = cfg.communityEndpoint;
      cfg.apiKey = enr.token;
      cfg.tenantId = enr.tenantId;
      cfg.reporting = cfg.consent.reporting === 'off' ? 'off' : 'full';
    } else {
      cfg.mode = 'local';
      cfg.apiEndpoint = '';
      cfg.reporting = 'off';
    }
    // Verify needs a business tenant whose SIEM sends identity alerts; community users never record sign-ins.
    cfg.verifyEnabled = cfg.mode === 'managed' && cfg.verifyEnabled === true;
    return cfg;
  }

  async function saveUser(settings) {
    const cur = (await chrome.storage.local.get('settings')).settings || {};
    await chrome.storage.local.set({ settings: Object.assign(cur, settings) });
  }

  const api = { DEFAULTS, COMMUNITY_ENDPOINT, REMOTE_KEYS, get, saveUser, cleanList };
  root.VSConfig = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
