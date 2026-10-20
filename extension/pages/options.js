(async function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const fields = [...document.querySelectorAll('[data-k]')];
  const CONNECTION_KEYS = ['apiEndpoint', 'apiKey', 'tenantId', 'userId'];

  async function load() {
    const cfg = await VSConfig.get();
    const { settings = {} } = await chrome.storage.local.get('settings');
    for (const f of fields) {
      const k = f.dataset.k;
      // Show the user's own list (without merged remote/user-trusted extras) unless the key is managed.
      // Connection fields show only what the user typed: never the community endpoint or install token.
      const own = CONNECTION_KEYS.includes(k) ? (settings[k] || '') : settings[k];
      const val = cfg._managed.includes(k) || cfg._remote.includes(k) ? cfg[k] : (k in settings || CONNECTION_KEYS.includes(k)) ? own
        : k === 'blockedDomains' ? VSConfig.DEFAULTS.blockedDomains : cfg[k];
      if (f.type === 'checkbox') f.checked = !!val;
      else if (f.hasAttribute('data-list')) f.value = (Array.isArray(val) ? val : VSConfig.cleanList(val)).join('\n');
      else f.value = val == null ? '' : val;
      const remote = cfg._remote.includes(k);
      if (cfg._managed.includes(k) || remote) {
        f.disabled = true;
        const lab = f.closest('label');
        if (lab && !lab.querySelector('.locked')) { const s = document.createElement('span'); s.className = 'locked'; s.textContent = remote ? 'Set by console' : 'Managed'; (lab.querySelector('b') || lab).appendChild(s); }
      }
    }
    $('managedNote').hidden = !cfg._managed.length && !cfg._remote.length;
    $('modeNote').textContent = cfg.mode === 'community' ? 'Connected to SOCLens community protection (automatic). Fill these in only to use your own SOC instead.'
      : cfg.mode === 'managed' ? 'Connected to your SOC with the details below.' : 'Not connected: everything runs on this device. Enter your company console details to send alerts to your SOC.';
    const { creds = [], events = [], queue = [], lastSync = 0 } = await chrome.storage.local.get(['creds', 'events', 'queue', 'lastSync']);
    $('credState').textContent = creds.length
      ? `Protecting ${creds.length} password${creds.length > 1 ? 's' : ''} (learned ${new Date(creds[0].ts).toLocaleString()} on ${creds[0].host}).`
      : 'No work password learned yet — sign in once on a corporate login page.';
    $('evState').textContent = `${events.length} event(s) stored on this device · ${queue.length} waiting to send` + (lastSync ? ` · last sync ${new Date(lastSync).toLocaleString()}` : '');
  }

  $('save').addEventListener('click', async () => {
    const out = {};
    for (const f of fields) {
      if (f.disabled) continue;
      const k = f.dataset.k;
      if (f.type === 'checkbox') out[k] = f.checked;
      else if (f.type === 'number') out[k] = Math.max(1, Math.min(100, Number(f.value) || VSConfig.DEFAULTS[k]));
      else if (f.hasAttribute('data-list')) out[k] = VSConfig.cleanList(f.value);
      else out[k] = f.value.trim();
    }
    if (out.warnThreshold && out.blockThreshold && out.warnThreshold >= out.blockThreshold) {
      $('status').textContent = 'Warn score must be lower than block score.'; return;
    }
    if (out.apiEndpoint && !/^https:\/\//i.test(out.apiEndpoint)) { $('status').textContent = 'API endpoint must use https://'; return; }
    if (out.communityEndpoint && !/^https:\/\//i.test(out.communityEndpoint)) { $('status').textContent = 'Community server must use https://'; return; }
    await VSConfig.saveUser(out);
    $('status').textContent = 'Saved ✓';
    setTimeout(() => { $('status').textContent = ''; }, 2500);
    load();
  });

  $('sync').addEventListener('click', async () => {
    $('syncState').textContent = 'Syncing…';
    await chrome.runtime.sendMessage({ type: 'flushNow' });
    $('syncState').textContent = 'Done';
    load();
  });

  $('clearCreds').addEventListener('click', async () => {
    if (!confirm('Forget the learned password hash? Credential guard restarts after your next work sign-in.')) return;
    await chrome.runtime.sendMessage({ type: 'clearCreds' });
    load();
  });

  $('export').addEventListener('click', async () => {
    const events = await chrome.runtime.sendMessage({ type: 'exportEvents' });
    const blob = new Blob([JSON.stringify(events, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `soclens-events-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });

  load();
})();
