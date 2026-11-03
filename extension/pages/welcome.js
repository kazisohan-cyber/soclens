(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);

  async function choose(reporting) {
    for (const b of document.querySelectorAll('.choices button')) b.disabled = true;
    $('result').className = '';
    $('result').textContent = 'Connecting…';
    const r = await chrome.runtime.sendMessage({ type: 'setConsent', reporting, nickname: $('nick').value });
    if (r && r.mode === 'community') {
      $('result').className = 'ok';
      $('result').textContent = reporting === 'off'
        ? 'Connected. Protection is on and nothing is shared. You can close this tab.'
        : 'Connected. Protection is on and reports are shared. Thank you! You can close this tab.';
    } else {
      $('result').className = 'err';
      $('result').textContent = 'Saved. The console could not be reached right now, so IOC Triage protects you on this device and will connect later by itself.';
    }
  }

  $('full').addEventListener('click', () => choose('full'));
  $('off').addEventListener('click', () => choose('off'));

  $('openAnalyst').addEventListener('click', () => {
    chrome.windows.getCurrent((w) => {
      if (chrome.sidePanel && chrome.sidePanel.open) chrome.sidePanel.open({ windowId: w.id }).catch(() => chrome.tabs.create({ url: chrome.runtime.getURL('pages/analyst.html') }));
      else chrome.tabs.create({ url: chrome.runtime.getURL('pages/analyst.html') });
    });
  });
  $('openSettings').addEventListener('click', () => chrome.runtime.openOptionsPage());

  // Protection needs Chrome's optional access to every site and to navigation events. Only a click can ask
  // for it, so an admin's policy still leaves this one click to the user.
  const ACCESS = { permissions: ['webNavigation'], origins: ['http://*/*', 'https://*/*'] };
  async function showConsent() {
    const c = await VSConfig.get();
    const { dataConsent } = await chrome.storage.local.get('dataConsent');
    const admin = c._managed.length > 0;
    const permitted = await chrome.permissions.contains(ACCESS);
    const on = (!!dataConsent || admin) && permitted;
    $('consentCard').hidden = on;
    $('agreedCard').hidden = !on;
  }
  $('agree').addEventListener('click', async () => {
    // permissions.request must be the first await so it still runs inside the click.
    const granted = await chrome.permissions.request(ACCESS).catch(() => false);
    if (!granted) {
      $('consentCard').hidden = true;
      $('declinedNote').hidden = false;
      return;
    }
    await chrome.runtime.sendMessage({ type: 'setDataConsent', agree: true });
    showConsent();
  });
  $('decline').addEventListener('click', () => {
    $('consentCard').hidden = true;
    $('declinedNote').hidden = false;
  });
  showConsent();

  // The community offer only exists when a community server is configured (none is built in).
  VSConfig.get().then((c) => {
    const community = !!c.communityEndpoint;
    $('communityCard').hidden = !community;
    $('choiceCard').hidden = !community;
    $('localCard').hidden = community;
  });
})();
