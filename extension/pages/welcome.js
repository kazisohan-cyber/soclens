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

  async function showConsent() {
    const c = await VSConfig.get();
    const { dataConsent } = await chrome.storage.local.get('dataConsent');
    const admin = c._managed.length > 0;
    $('consentCard').hidden = !!dataConsent || admin;
    $('agreedCard').hidden = !dataConsent;
  }
  $('agree').addEventListener('click', async () => {
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
