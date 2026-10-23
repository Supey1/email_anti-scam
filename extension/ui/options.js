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
    document.documentElement.style.fontSize = `${Settings.TEXT_PX[s.textSize]}px`;
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
    window.speechSynthesis.cancel();
    const speech = new SpeechSynthesisUtterance('This is how a warning will sound. Stop and check this first.');
    speech.rate = Settings.SPEECH_RATE[Settings.current.speechSpeed];
    window.speechSynthesis.speak(speech);
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

  Settings.onChange(render);
  chrome.storage.onChanged.addListener(renderReports);
  render();
  renderReports();
})();
