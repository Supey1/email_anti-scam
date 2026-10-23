// service-worker.js: the extension's background helper.
//
// It connects Chrome to background/messages.js, which does the actual work:
//   - keeps Chrome's network-blocking rules in step with the known-threat list,
//     so known dangerous websites are blocked before they load, however you get there
//   - answers "is this address known to be dangerous?" (LOOKUP_URL)
//   - opens the extension's own warning page
//   - reads and changes the protection settings
//   - starts and stops the page scripts to match the website access the
//     person has given (asked for on the welcome page, never at install)
//   - passes warnings from ads and other frames up to the main page
// Message formats: docs/interfaces.md ("Service worker messages").
//
// Chrome can stop this script whenever it's idle, so nothing important lives
// only in memory: settings and threat updates are in chrome.storage.local,
// warnings for the warning page in chrome.storage.session (gone when the
// browser closes). Anything in memory is rebuilt on first use after a restart.

importScripts(
  'data/threat-list.js',
  'data/addresses.js',
  'data/companies.js',
  'data/services.js',
  'core/url-normalizer.js',
  'core/domain-rules.js',
  'core/url-rules.js',
  'background/threat-rules.js',
  'background/threat-lookup.js',
  'background/content-scripts.js',
  'background/messages.js',
);

const storageArea = area => ({
  get: key => area.get(key).then(items => items[key]),
  set: items => area.set(items),
  remove: keys => area.remove(keys),
});

const background = GranblockBackground.createBackground({
  storage: storageArea(chrome.storage.local),
  session: storageArea(chrome.storage.session),
  dnr: chrome.declarativeNetRequest,
  tabs: chrome.tabs,
  permissions: chrome.permissions,
  scripting: chrome.scripting,
  bundled: () => [
    ...KNOWN_THREAT_DOMAINS.map(value => ({ type: 'domain', value, source: KNOWN_THREAT_SOURCE.name, trusted: KNOWN_THREAT_SOURCE.trusted })),
    ...KNOWN_THREAT_URLS.map(value => ({ type: 'url', value, source: KNOWN_THREAT_SOURCE.name, trusted: KNOWN_THREAT_SOURCE.trusted })),
  ],
  blockPage: chrome.runtime.getURL('blocked.html'),
  extensionOrigin: chrome.runtime.getURL(''),
  newToken: () => crypto.randomUUID(),
});
// For the browser tests (tests/browser/acceptance.test.js).
GranblockBackground.instance = background;

chrome.runtime.onInstalled.addListener(details => {
  background.refreshRules();
  // Right after installing: the welcome page, where the person chooses which websites to check.
  if (details.reason === 'install') chrome.tabs.create({ url: chrome.runtime.getURL('settings.html?welcome=1') });
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
