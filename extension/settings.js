// settings.js: the settings page (and welcome page) of the extension.
// Everything goes through the service worker (docs/interfaces.md, "Service
// worker messages"); website access goes through Chrome's permission prompt.

const ALL_SITES = ['http://*/*', 'https://*/*'];
const GMAIL = ['https://mail.google.com/*'];

const $ = id => document.getElementById(id);
const send = message => chrome.runtime.sendMessage({ schemaVersion: 1, ...message });
let status = null;

function say(text) {
  $('message').textContent = text || '';
}

async function load() {
  status = await send({ type: 'GET_STATUS' });
  if (!status || status.type !== 'STATUS') {
    say('The settings could not be loaded. Close this page and open it again.');
    return;
  }
  draw();
}

function draw() {
  const { settings, access } = status;
  const on = settings.protectionEnabled;

  // Protection, in one sentence.
  const box = $('status');
  let icon, text, cls;
  if (!on) { icon = '⏸'; text = 'Protection is off. Nothing is checked or blocked.'; cls = 'off'; }
  else if (access === 'all') { icon = '✅'; text = 'Protection is on: checking websites, ads, and Gmail, and blocking known dangerous websites.'; cls = 'on'; }
  else if (access === 'gmail') { icon = '⚠️'; text = 'Protection is on for Gmail only. Known dangerous websites are blocked, but other websites aren\'t checked.'; cls = 'partial'; }
  else { icon = '⚠️'; text = 'Protection is on, but it can only block known dangerous websites. Choose "Check all websites" below to be warned about scams.'; cls = 'partial'; }
  box.className = `status ${cls}`;
  box.replaceChildren(Object.assign(document.createElement('span'), { className: 'icon', textContent: icon }), Object.assign(document.createElement('span'), { textContent: text }));
  box.firstChild.setAttribute('aria-hidden', 'true');
  const toggle = $('toggle-protection');
  toggle.textContent = on ? 'Turn protection off' : 'Turn protection on';
  toggle.className = on ? '' : 'primary';

  for (const [id, value] of [['access-all', 'all'], ['access-gmail', 'gmail'], ['access-none', 'none']]) {
    $(id).setAttribute('aria-pressed', String(access === value));
  }
  // Until websites are checked, the recommended choice is the obvious next step.
  $('access-all').classList.toggle('next-step', access !== 'all');

  for (const input of document.querySelectorAll('input[name="textSize"]')) input.checked = input.value === settings.textSize;
  for (const input of document.querySelectorAll('input[name="speechRate"]')) input.checked = Number(input.value) === settings.speechRate;
  $('autoRead').checked = settings.autoRead;
  $('sample').style.zoom = { large: 1, larger: 1.2, largest: 1.45 }[settings.textSize] || 1;

  const list = $('allowlist');
  list.replaceChildren(...settings.allowlist.map(site => {
    const remove = Object.assign(document.createElement('button'), { textContent: 'Remove' });
    remove.setAttribute('aria-label', `Remove ${site}`);
    remove.addEventListener('click', () => save({ allowlist: settings.allowlist.filter(s => s !== site) }));
    const li = document.createElement('li');
    li.append(`${site} `, remove);
    return li;
  }));
  $('allowlist-empty').hidden = settings.allowlist.length > 0;
}

async function save(change) {
  const answer = await send({ type: 'SET_SETTINGS', settings: change });
  if (answer.type !== 'SETTINGS') { say(`That didn't work: ${answer.error}`); return; }
  say('');
  await load();
}

// Website access. Chrome shows its own question; the person decides there.
async function setAccess(choice) {
  say('');
  try {
    if (choice === 'all') {
      const granted = await chrome.permissions.request({ origins: ALL_SITES });
      if (!granted) say('Chrome did not allow it, so websites won\'t be checked. You can try again any time.');
    } else if (choice === 'gmail') {
      const granted = await chrome.permissions.request({ origins: GMAIL });
      if (granted) await chrome.permissions.remove({ origins: ALL_SITES }).catch(() => {});
      else say('Chrome did not allow it, so Gmail won\'t be checked.');
    } else {
      await chrome.permissions.remove({ origins: [...ALL_SITES, ...GMAIL] });
    }
  } catch (e) {
    say(`That didn't work: ${e.message}`);
  }
  await send({ type: 'ACCESS_CHANGED' });
  await load();
}

$('toggle-protection').addEventListener('click', () => save({ protectionEnabled: !status.settings.protectionEnabled }));
$('access-all').addEventListener('click', () => setAccess('all'));
$('access-gmail').addEventListener('click', () => setAccess('gmail'));
$('access-none').addEventListener('click', () => setAccess('none'));
for (const input of document.querySelectorAll('input[name="textSize"]')) input.addEventListener('change', () => save({ textSize: input.value }));
for (const input of document.querySelectorAll('input[name="speechRate"]')) input.addEventListener('change', () => save({ speechRate: Number(input.value) }));
$('autoRead').addEventListener('change', () => save({ autoRead: $('autoRead').checked }));

// "Try it": the sample warning, read the way real warnings are.
$('sample-buttons').append(GranblockSpeech.makeButton(document, {
  getParts: () => ['Stop and check this link.', $('sample-text').textContent],
  key: 'settings-sample',
  rate: () => (status ? status.settings.speechRate : 0.9),
}));

// Chrome can change access too (the person can take it away in Chrome's own settings).
chrome.permissions.onAdded.addListener(() => load());
chrome.permissions.onRemoved.addListener(() => load());

$('welcome').hidden = !new URLSearchParams(location.search).has('welcome');
load();
