// options.js: the settings page. Plain choices, saved as soon as they are changed.

(async () => {
  'use strict';
  await Settings.ready;

  const $ = id => document.getElementById(id);
  let savedTimer = null;

  function saved(message = 'Saved.') {
    $('saved').textContent = message;
    clearTimeout(savedTimer);
    savedTimer = setTimeout(() => { $('saved').textContent = ''; }, 3000);
  }

  async function update(partial) {
    await Settings.save(partial);
    saved();
  }

  function radios(name) { return [...document.querySelectorAll(`input[name="${name}"]`)]; }

  function render() {
    const s = Settings.current;
    // The settings page itself always stays at the Large size; only the sample below shows the chosen size.
    document.documentElement.style.fontSize = `${Settings.TEXT_PX.large}px`;
    $('enabled').checked = s.enabled;
    $('checkEmail').checked = s.checkEmail;
    $('checkEmail').disabled = !s.enabled;
    for (const name of ['siteMode', 'readAloud', 'textSize']) for (const r of radios(name)) r.checked = r.value === s[name];
    $('speechSpeed').value = s.speechSpeed;

    const chosen = s.siteMode === 'chosen';
    const list = chosen ? s.onSites : s.offSites;
    $('sites-heading').textContent = chosen ? 'Websites I chose to check' : 'Websites I turned off';
    $('sites-empty').textContent = list.length ? '' : (chosen ? 'None yet. No websites are being checked until you add some. Gmail has its own switch above.' : 'None. Every website is being checked.');
    $('sites').replaceChildren(...list.map(site => {
      const remove = Object.assign(document.createElement('button'), { textContent: 'Remove', type: 'button' });
      remove.setAttribute('aria-label', `Remove ${site}`);
      remove.addEventListener('click', () => update({ [chosen ? 'onSites' : 'offSites']: list.filter(x => x !== site) }));
      const item = document.createElement('li');
      item.append(Object.assign(document.createElement('span'), { textContent: site }), remove);
      return item;
    }));
    $('size-sample').style.fontSize = `${Settings.TEXT_PX[s.textSize]}px`;
  }

  async function renderReports() {
    const { falseAlarms = [] } = await chrome.storage.local.get('falseAlarms');
    $('report-count').textContent = falseAlarms.length
      ? `${falseAlarms.length} saved report${falseAlarms.length === 1 ? '' : 's'}.`
      : 'No saved reports.';
    $('export-reports').disabled = $('clear-reports').disabled = !falseAlarms.length;
  }

  $('enabled').addEventListener('change', e => update({ enabled: e.target.checked }));
  $('checkEmail').addEventListener('change', e => update({ checkEmail: e.target.checked }));
  for (const name of ['siteMode', 'readAloud', 'textSize']) for (const r of radios(name)) r.addEventListener('change', () => update({ [name]: r.value }));
  $('speechSpeed').addEventListener('change', e => update({ speechSpeed: e.target.value }));

  async function addSite() {
    const host = Settings.normalizeHost($('site-input').value);
    if (!host) { $('site-error').textContent = 'That does not look like a website name. Try something like example.com.'; return; }
    $('site-error').textContent = '';
    const key = Settings.current.siteMode === 'chosen' ? 'onSites' : 'offSites';
    $('site-input').value = '';
    await update({ [key]: [...new Set([...Settings.current[key], host])] });
  }
  $('add-site').addEventListener('click', addSite);
  $('site-input').addEventListener('keydown', e => { if (e.key === 'Enter') addSite(); });

  $('test-voice').addEventListener('click', () => {
    GranblockSpeech.speak('This is how a warning will sound. Stop and check this first.', { rate: Settings.SPEECH_RATE[Settings.current.speechSpeed] });
  });

  $('export-reports').addEventListener('click', async () => {
    const { falseAlarms = [] } = await chrome.storage.local.get('falseAlarms');
    const link = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(new Blob([JSON.stringify(falseAlarms, null, 2)], { type: 'application/json' })),
      download: 'false-alarm-reports.json',
    });
    link.click();
    URL.revokeObjectURL(link.href);
  });

  $('clear-reports').addEventListener('click', async () => {
    await chrome.storage.local.remove('falseAlarms');
    await renderReports();
    saved('Reports deleted.');
  });

  // Two clicks, so a slip of the finger can't wipe the settings.
  let resetArmed = false;
  $('reset').addEventListener('click', async () => {
    if (!resetArmed) { resetArmed = true; $('reset').textContent = 'Click again to confirm'; setTimeout(() => { resetArmed = false; $('reset').textContent = 'Put every setting back the way it was'; }, 5000); return; }
    resetArmed = false;
    $('reset').textContent = 'Put every setting back the way it was';
    await Settings.reset();
    saved('Everything is back the way it was.');
  });

  // ---- online lists of fake websites (off unless chosen; see the page text for what each one sends) ----
  const ORIGINS = { 'safe-browsing': ['https://safebrowsing.googleapis.com/*'], 'phishing-database': ['https://raw.githubusercontent.com/*'] };
  async function engine(change) {
    const reply = await chrome.runtime.sendMessage({ schemaVersion: 1, type: change ? 'SET_SETTINGS' : 'GET_SETTINGS', ...(change ? { settings: change } : {}) });
    if (!reply || reply.type !== 'SETTINGS') throw new Error((reply && reply.error) || 'no answer');
    return reply.settings; // never contains the key itself, only providerOptions.apiKeySet
  }
  async function feedStatus(refresh) {
    const reply = await chrome.runtime.sendMessage({ schemaVersion: 1, type: refresh ? 'FEED_REFRESH' : 'FEED_STATUS' });
    if (!reply || reply.type !== 'FEED_STATUS') throw new Error((reply && reply.error) || 'no answer');
    return reply.status;
  }
  const sources = s => (Array.isArray(s.providers) ? s.providers : []);
  async function renderOnline() {
    try {
      const s = await engine();
      const on = sources(s).includes('safe-browsing');
      const feedOn = sources(s).includes('phishing-database');
      $('onlineCheck').checked = on;
      $('feedCheck').checked = feedOn;
      $('feed-refresh').hidden = !feedOn;
      $('sb-key-status').textContent = s.providerOptions.apiKeySet ? 'A key is saved on this computer.' : 'No key saved yet.';
      const st = feedOn ? await feedStatus(false) : null;
      $('feed-status').textContent = !st ? '' : st.ready
        ? `List ready: ${st.entries.toLocaleString()} fake websites, downloaded ${new Date(st.updatedAt).toLocaleString()}.`
        : (st.downloading ? 'Downloading the list…' : `The list has not been downloaded yet.${st.lastError ? ` (${st.lastError})` : ''}`);
    } catch (e) { $('onlineCheck').checked = false; $('feedCheck').checked = false; }
  }
  // Turns one source on or off, keeping the others as they were.
  async function setSource(name, on) {
    const providers = sources(await engine()).filter(p => p !== name).concat(on ? [name] : []);
    await engine({ providers, provider: 'none', remoteLookups: providers.length > 0, lookupTimeoutMs: 4000 });
    if (!on) await chrome.permissions.remove({ origins: ORIGINS[name] }).catch(() => {});
  }
  $('sb-save').addEventListener('click', async () => {
    $('online-error').textContent = '';
    try {
      const key = $('sb-key').value.trim();
      await engine({ providerOptions: { apiKey: key } });
      $('sb-key').value = '';
      if (!key) await setSource('safe-browsing', false);
      saved(key ? 'Key saved.' : 'Key removed.');
    } catch (err) {
      $('online-error').textContent = err.message;
    }
    await renderOnline();
  });
  $('onlineCheck').addEventListener('change', async e => {
    $('online-error').textContent = '';
    try {
      if (e.target.checked) {
        if (!(await engine()).providerOptions.apiKeySet) throw new Error('Paste your Safe Browsing key above and press "Save key" first.');
        if (!await chrome.permissions.request({ origins: ORIGINS['safe-browsing'] })) throw new Error('Chrome did not allow it, so this stays off.');
      }
      await setSource('safe-browsing', e.target.checked);
      saved();
    } catch (err) {
      $('online-error').textContent = err.message;
    }
    await renderOnline();
  });
  async function downloadFeed() {
    $('feed-status').textContent = 'Downloading the list…';
    const st = await feedStatus(true);
    if (!st.ready && st.lastError) throw new Error(st.lastError);
  }
  $('feedCheck').addEventListener('change', async e => {
    $('online-error').textContent = '';
    try {
      if (e.target.checked && !await chrome.permissions.request({ origins: ORIGINS['phishing-database'] })) throw new Error('Chrome did not allow it, so this stays off.');
      await setSource('phishing-database', e.target.checked);
      saved();
      if (e.target.checked) { await renderOnline(); await downloadFeed(); }
    } catch (err) {
      $('online-error').textContent = err.message;
    }
    await renderOnline();
  });
  $('feed-refresh').addEventListener('click', async () => {
    $('online-error').textContent = '';
    try { await downloadFeed(); } catch (err) { $('online-error').textContent = err.message; }
    await renderOnline();
  });

  // ---- website access (Chrome's permission prompt; the service worker starts the page scripts) ----
  const ALL_SITES = ['http://*/*', 'https://*/*'];
  const GMAIL = ['https://mail.google.com/*'];
  const ACCESS_TEXT = {
    all: ['✅', 'yes', 'Checking websites, ads, and Gmail.'],
    gmail: ['⚠️', 'unknown', 'Checking Gmail only. Other websites and ads are not checked.'],
    none: ['⚠️', 'no', 'Not checking websites yet. Known dangerous websites are still blocked. Choose "Check all websites" to be warned about scams.'],
  };

  async function renderAccess() {
    let access = 'none';
    try {
      const status = await chrome.runtime.sendMessage({ schemaVersion: 1, type: 'GET_STATUS' });
      if (status && status.type === 'STATUS') access = status.access;
    } catch (e) { /* treat as no access */ }
    const [icon, state, text] = ACCESS_TEXT[access] || ACCESS_TEXT.none;
    const box = $('access-status');
    box.className = `status ${state}`;
    box.replaceChildren(Object.assign(document.createElement('span'), { className: 'icon', textContent: icon }), Object.assign(document.createElement('span'), { textContent: text }));
    box.firstChild.setAttribute('aria-hidden', 'true');
    // The chosen one is marked with a check mark and a heavy green border, so it's clear which is selected.
    for (const choice of ['all', 'gmail', 'none']) {
      const button = $(`access-${choice}`);
      if (!button.dataset.label) button.dataset.label = button.textContent;
      const chosen = access === choice;
      button.setAttribute('aria-pressed', String(chosen));
      button.classList.toggle('selected', chosen);
      button.textContent = `${chosen ? '✓ ' : ''}${button.dataset.label}`;
    }
  }

  async function setAccess(choice) {
    $('access-error').textContent = '';
    try {
      if (choice === 'all') {
        if (!await chrome.permissions.request({ origins: ALL_SITES })) $('access-error').textContent = 'Chrome did not allow it, so websites won\'t be checked. You can try again any time.';
      } else if (choice === 'gmail') {
        // When all websites are already allowed, Chrome says yes to Gmail without recording it on its own,
        // so taking "all websites" away would leave nothing. Take it away first, then make sure Gmail is really held.
        let ok = await chrome.permissions.request({ origins: GMAIL });
        if (ok) {
          await chrome.permissions.remove({ origins: ALL_SITES }).catch(() => {});
          ok = await chrome.permissions.contains({ origins: GMAIL }) || await chrome.permissions.request({ origins: GMAIL });
        }
        if (!ok) $('access-error').textContent = 'Chrome did not allow it, so Gmail won\'t be checked.';
      } else {
        await chrome.permissions.remove({ origins: [...ALL_SITES, ...GMAIL] });
      }
    } catch (e) {
      $('access-error').textContent = `That didn't work: ${e.message}`;
    }
    await chrome.runtime.sendMessage({ schemaVersion: 1, type: 'ACCESS_CHANGED' }).catch(() => {});
    await renderAccess();
  }
  for (const choice of ['all', 'gmail', 'none']) $(`access-${choice}`).addEventListener('click', () => setAccess(choice));
  // Chrome can change access too (the person can take it away in Chrome's own settings).
  chrome.permissions.onAdded.addListener(renderAccess);
  chrome.permissions.onRemoved.addListener(renderAccess);
  $('welcome').hidden = !new URLSearchParams(location.search).has('welcome');

  Settings.onChange(render);
  chrome.storage.onChanged.addListener(renderReports);
  render();
  renderReports();
  renderAccess();
  renderOnline();
})();
