// popup.js: three plain questions. Is protection on? Is this page being checked? What can I do to get help?

(async () => {
  'use strict';
  await Settings.ready;

  const $ = id => document.getElementById(id);
  const params = new URLSearchParams(location.search);
  let tab = null;

  async function findTab() {
    try {
      // "?tab=<id>" lets tests point the popup at a specific tab; Chrome opens the popup with no parameters.
      if (params.get('tab')) return await chrome.tabs.get(Number(params.get('tab')));
      return (await chrome.tabs.query({ active: true, currentWindow: true }))[0] || null;
    } catch (e) {
      return null;
    }
  }

  async function askPage(message) {
    if (!tab || tab.id === undefined) return undefined;
    try { return await chrome.tabs.sendMessage(tab.id, message); } catch (e) { return undefined; }
  }

  function applyTextSize() {
    document.documentElement.style.fontSize = `${Settings.TEXT_PX[Settings.current.textSize] * 0.8}px`;
  }

  function showStatus(el, info) {
    el.className = `status ${info.state}`;
    el.replaceChildren(Object.assign(document.createElement('span'), { className: 'icon', textContent: info.icon, ariaHidden: 'true' }), Object.assign(document.createElement('span'), { textContent: info.text }));
  }

  async function render() {
    applyTextSize();
    const s = Settings.current;

    showStatus($('protection-status'), s.enabled
      ? { state: 'yes', icon: '✅', text: 'Yes, protection is on.' }
      : { state: 'no', icon: '⛔', text: 'No, protection is off.' });
    $('toggle-protection').textContent = s.enabled ? 'Turn protection off' : 'Turn protection on';

    const reply = await askPage({ type: 'STATUS' });
    let access = 'none';
    try {
      const status = await chrome.runtime.sendMessage({ schemaVersion: 1, type: 'GET_STATUS' });
      if (status && status.type === 'STATUS') access = status.access;
    } catch (e) { /* treat as no access */ }
    const info = PopupStatus.describePage({ settings: s, url: tab && tab.url, reply, access });
    showStatus($('page-status'), info);
    $('page-detail').textContent = info.detail;
    const toggle = $('toggle-site');
    toggle.hidden = !info.toggle;
    if (info.toggle) { toggle.textContent = info.toggle.label; toggle.dataset.on = String(info.toggle.on); }
    $('recheck').hidden = info.state !== 'yes';
  }

  function say(text) { $('action-result').textContent = text; }

  $('toggle-protection').addEventListener('click', async () => {
    await Settings.save({ enabled: !Settings.current.enabled });
  });

  $('toggle-site').addEventListener('click', async () => {
    const host = new URL(tab.url).hostname;
    await Settings.save(Settings.withSiteToggled(Settings.current, host, $('toggle-site').dataset.on === 'true'));
  });

  $('read-help').addEventListener('click', () => {
    window.speechSynthesis.cancel();
    const speech = new SpeechSynthesisUtterance($('help-text').textContent);
    speech.rate = Settings.SPEECH_RATE[Settings.current.speechSpeed];
    window.speechSynthesis.speak(speech);
  });

  $('recheck').addEventListener('click', async () => {
    const reply = await askPage({ type: 'RESCAN' });
    say(reply && reply.ok ? 'Checked again.' : 'Could not check again. Try reloading the page.');
  });

  $('open-options').addEventListener('click', () => { chrome.runtime.openOptionsPage(); });

  // Pages react a moment after a setting changes, so look again shortly afterwards.
  Settings.onChange(() => setTimeout(render, 350));

  tab = await findTab();
  await render();
})();
