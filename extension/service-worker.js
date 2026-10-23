// service-worker.js: blocks websites already known to be dangerous, before the page loads.
// Uses Chrome's declarativeNetRequest rules, built from the list in threats.js.

importScripts('threats.js');

function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function installThreatRules() {
  const blockPage = chrome.runtime.getURL('blocked.html');
  const addRules = THREAT_DOMAINS.map((domain, i) => ({
    id: i + 1,
    priority: 1,
    action: { type: 'redirect', redirect: { regexSubstitution: `${blockPage}?url=\\0` } },
    condition: {
      // matches the domain and its subdomains, only for the address bar (not images, scripts, etc.)
      regexFilter: `^https?://([^/]+\\.)?${escapeRegex(domain)}([:/?#].*)?$`,
      resourceTypes: ['main_frame'],
    },
  }));
  const old = await chrome.declarativeNetRequest.getDynamicRules();
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: old.map(r => r.id), addRules });
}

chrome.runtime.onInstalled.addListener(installThreatRules);
chrome.runtime.onStartup.addListener(installThreatRules);
