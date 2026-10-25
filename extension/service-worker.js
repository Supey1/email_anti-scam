// service-worker.js: the extension's background helper.
//
// It connects Chrome to background/messages.js, which does the actual work:
//   - keeps Chrome's network-blocking rules in step with the known-threat list,
//     so known dangerous websites are blocked before they load, however you get there
//   - answers "is this address known to be dangerous?" (LOOKUP_URL)
//   - opens the extension's own warning page (ui/warning.html) when the click
//     guard stops a link, and continues only when the person chooses to (never
//     to a known dangerous website)
//   - reads and changes the protection settings; shows "OFF" on the toolbar
//     button when protection is off
//   - starts and stops the page scripts to match the website access the
//     person has given (asked for on the welcome page, never at install)
//   - keeps "false alarm" reports on this computer
// Message formats: docs/interfaces.md ("Service worker messages").
//
// Chrome can stop this script whenever it's idle, so nothing important lives
// only in memory: settings, threat updates, and false-alarm reports are in
// chrome.storage.local. Anything in memory is rebuilt on first use after a restart.

importScripts(
  // The person's choices (extension/settings.js)
  'settings.js',
  // The scam checks (to check a link again before "continue")
  'data/threat-list.js',
  'data/addresses.js',
  'data/companies.js',
  'data/services.js',
  'data/people.js',
  'core/url-normalizer.js',
  'core/domain-rules.js',
  'core/url-rules.js',
  'core/text-rules.js',
  'core/risk-policy.js',
  'core/explanations.js',
  'core/analyzer.js',
  'rules.js',
  // The background itself
  'background/threat-rules.js',
  'background/phishtank-feed.js',
  'background/threat-lookup.js',
  'background/content-scripts.js',
  'background/speech-relay.js',
  'background/messages.js',
);

const storageArea = area => ({
  get: key => area.get(key).then(items => items[key]),
  set: items => area.set(items),
  remove: keys => area.remove(keys),
});

const background = GranblockBackground.createBackground({
  storage: storageArea(chrome.storage.local),
  fetch: (...args) => fetch(...args),
  dnr: chrome.declarativeNetRequest,
  tabs: chrome.tabs,
  permissions: chrome.permissions,
  scripting: chrome.scripting,
  bundled: () => [
    ...KNOWN_THREAT_DOMAINS.map(value => ({ type: 'domain', value, source: KNOWN_THREAT_SOURCE.name, trusted: KNOWN_THREAT_SOURCE.trusted })),
    ...KNOWN_THREAT_URLS.map(value => ({ type: 'url', value, source: KNOWN_THREAT_SOURCE.name, trusted: KNOWN_THREAT_SOURCE.trusted })),
  ],
  warningPage: chrome.runtime.getURL('ui/warning.html'),
  checkLink: ({ url, text, entries }) => {
    GranblockCore.urlRules.useThreatEntries(entries);
    return checkLinkClick({ url, text });
  },
  badge: on => Promise.all([
    chrome.action.setBadgeText({ text: on ? '' : 'OFF' }),
    chrome.action.setBadgeBackgroundColor({ color: '#b00020' }),
  ]),
  extensionOrigin: chrome.runtime.getURL(''),
  newToken: () => crypto.randomUUID(),
});
// For the browser tests (tests/browser/blocking.test.js).
GranblockBackground.instance = background;

chrome.runtime.onInstalled.addListener(details => {
  background.refreshRules();
  // Right after installing: the welcome page, where the person chooses which websites to check.
  if (details.reason === 'install') chrome.tabs.create({ url: chrome.runtime.getURL('ui/options.html?welcome=1') });
});
// The person turned protection on or off (popup or settings page): apply it.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.settings) background.settingsChanged();
});
chrome.runtime.onStartup.addListener(() => background.refreshRules());
// Website access given or taken away (here or in Chrome's own settings):
// start or stop the page scripts, and switch blocking between our blocked
// page and Chrome's plain "blocked" page.
chrome.permissions.onAdded.addListener(() => background.refreshRules());
chrome.permissions.onRemoved.addListener(() => background.refreshRules());

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  background.handleMessage(message, sender).then(sendResponse);
  return true; // we'll answer later
});

// Warning cards inside web pages ask us to read aloud with Chrome's own speech (no click needed, speed honoured).
chrome.runtime.onConnect.addListener(port => {
  GranblockBackground.speechRelay.handlePort(port, chrome.tts, () => chrome.runtime.lastError);
});
