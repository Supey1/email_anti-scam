// popup.js: three plain questions. Is protection on? Is this page being checked? What can I do to get help?
// Uses the service worker's GET_STATUS / SET_SETTINGS (docs/interfaces.md) and asks the page's own checker whether it is running.

(async () => {
  'use strict';

  const $ = id => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  const ZOOM = { large: 1, larger: 1.2, largest: 1.45 };
  let tab = null;
  let status = null;

  const ask = message => chrome.runtime.sendMessage({ schemaVersion: 1, ...message });

  async function findTab() {
    try {
      // "?tab=<id>" lets tests point the popup at a specific tab; Chrome opens the popup with no parameters.
      if (params.get('tab')) return await chrome.tabs.get(Number(params.get('tab')));
      return (await chrome.tabs.query({ active: true, currentWindow: true }))[0] || null;
    } catch (e) {
      return null;
    }
  }

  async function askPage(type) {
    if (!tab || tab.id === undefined) return undefined;
    try { return await chrome.tabs.sendMessage(tab.id, { type, schemaVersion: 1 }); } catch (e) { return undefined; }
  }

  function showStatus(el, info) {
    el.className = `status ${info.state}`;
    el.replaceChildren(Object.assign(document.createElement('span'), { className: 'icon', textContent: info.icon, ariaHidden: 'true' }), Object.assign(document.createElement('span'), { textContent: info.text }));
  }

  async function render() {
    status = await ask({ type: 'GET_STATUS' });
    const enabled = !!(status.settings && status.settings.protectionEnabled);
    document.documentElement.style.fontSize = `${19 * (ZOOM[status.settings && status.settings.textSize] || 1)}px`;

    showStatus($('protection-status'), enabled
      ? { state: 'yes', icon: '✅', text: 'Yes, protection is on.' }
      : { state: 'no', icon: '⛔', text: 'No, protection is off.' });
    $('toggle-protection').textContent = enabled ? 'Turn protection off' : 'Turn protection on';

    const reply = enabled ? await askPage('PAGE_STATUS') : undefined;
    const info = PopupStatus.describePage({ protectionEnabled: enabled, access: status.access, url: tab && tab.url, reply });
    showStatus($('page-status'), info);
    $('page-detail').textContent = info.detail;
    $('open-settings-from-status').hidden = !info.openSettings;
    $('recheck').hidden = info.state !== 'yes';
  }

  const say = text => { $('action-result').textContent = text; };

  $('toggle-protection').addEventListener('click', async () => {
    const answer = await ask({ type: 'SET_SETTINGS', settings: { protectionEnabled: !status.settings.protectionEnabled } });
    if (answer.type === 'ERROR') say('Sorry, that did not work. Try again.');
    await render();
  });

  $('read-help').addEventListener('click', () => {
    GranblockSpeech.speak($('help-text').textContent, { rate: (status && status.settings && status.settings.speechRate) || 0.9, key: 'popup-help' });
  });

  $('recheck').addEventListener('click', async () => {
    const reply = await askPage('PAGE_RESCAN');
    say(reply && reply.ok ? 'Checked again.' : 'Could not check again. Try reloading the page.');
  });

  const openSettings = () => chrome.runtime.openOptionsPage();
  $('open-options').addEventListener('click', openSettings);
  $('open-settings-from-status').addEventListener('click', openSettings);

  tab = await findTab();
  await render();
})();
