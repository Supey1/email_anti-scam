// service-worker.js: the extension's background helper. It has two jobs.
//
// 1. Block known dangerous websites (threat-list.js) at the browser level.
//    Chrome checks these rules before a page loads, so they also catch typed
//    addresses, redirects, and pop-ups that guard.js never sees. Instead of
//    the dangerous page, the person sees blocked.html.
// 2. Pass warnings from ads and other frames up to the main page, so the
//    warning covers the whole screen (see guard.js).

importScripts('threat-list.js');

const BLOCK_PAGE = chrome.runtime.getURL('blocked.html');

// Replaces our blocking rules with the current list.
async function installBlockRules() {
  const oldRules = await chrome.declarativeNetRequest.getDynamicRules();
  const rules = KNOWN_THREAT_DOMAINS.map((domain, i) => ({
    id: i + 1,
    priority: 1,
    // The page you were trying to open -> our "this is dangerous" page.
    action: { type: 'redirect', redirect: { url: `${BLOCK_PAGE}#${encodeURIComponent(domain)}` } },
    condition: { requestDomains: [domain], resourceTypes: ['main_frame'] },
  }));
  if (KNOWN_THREAT_DOMAINS.length) {
    // Inside a frame on another page (like an ad), just don't load it.
    rules.push({
      id: rules.length + 1,
      priority: 1,
      action: { type: 'block' },
      condition: { requestDomains: KNOWN_THREAT_DOMAINS, resourceTypes: ['sub_frame'] },
    });
  }
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: oldRules.map(rule => rule.id),
    addRules: rules,
  });
}

chrome.runtime.onInstalled.addListener(installBlockRules);
chrome.runtime.onStartup.addListener(installBlockRules);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || message.type !== 'granblock-warning' || !sender.tab || sender.frameId === 0) return;
  chrome.tabs.sendMessage(sender.tab.id, message, { frameId: 0 })
    .then(reply => sendResponse(reply))
    .catch(() => sendResponse({ shown: false })); // e.g. the main page is one we can't run on
  return true; // we'll answer later
});
