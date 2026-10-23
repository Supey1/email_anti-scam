// service-worker.js: the extension's background part.
//  1. Blocks websites already known to be dangerous, before the page loads (declarativeNetRequest).
//  2. Shows the extension-owned warning page when click-guard.js stops a link.
//  3. Continues to a destination only when the person chooses to, and never for a "block".
//  4. Saves false-alarm reports locally during testing.
//
// A service worker can stop when idle, so nothing here relies on remembered variables:
// the rules live in Chrome, reports live in chrome.storage.

importScripts('threats.js', 'rules.js', 'analyzer.js');

const WARNING_PAGE = chrome.runtime.getURL('ui/warning.html');
const MAX_REPORTS = 100;

function escapeRegex(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

async function installThreatRules() {
  const addRules = THREAT_DOMAINS.map((domain, i) => ({
    id: i + 1,
    priority: 1,
    action: { type: 'redirect', redirect: { regexSubstitution: `${WARNING_PAGE}?kind=dnr&url=\\0` } },
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

function isWebAddress(url) {
  try { return /^https?:$/.test(new URL(url).protocol); } catch (e) { return false; }
}

function fromOurWarningPage(sender) {
  return sender.id === chrome.runtime.id && !!sender.url && sender.url.startsWith(WARNING_PAGE) && !!sender.tab;
}

async function saveReport(report) {
  const { falseAlarms = [] } = await chrome.storage.local.get('falseAlarms');
  falseAlarms.push({ at: new Date().toISOString(), host: String(report.host || ''), verdict: String(report.verdict || ''), source: String(report.source || ''), reasons: (report.reasons || []).slice(0, 5).map(String) });
  await chrome.storage.local.set({ falseAlarms: falseAlarms.slice(-MAX_REPORTS) });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !message) return;

  if (message.type === 'SHOW_WARNING' && sender.tab && isWebAddress(message.url)) {
    const url = `${WARNING_PAGE}?kind=click&text=${encodeURIComponent(String(message.text || '').slice(0, 200))}&url=${encodeURIComponent(message.url)}`;
    // A click that would have opened a new tab gets the warning in a new tab; otherwise it replaces the page.
    const done = () => sendResponse({ ok: true });
    const fail = () => sendResponse({ ok: false });
    if (message.newTab) chrome.tabs.create({ url, active: true, index: sender.tab.index + 1, openerTabId: sender.tab.id }).then(done, fail);
    else chrome.tabs.update(sender.tab.id, { url }).then(done, fail);
    return true;
  }

  if (message.type === 'CONTINUE' && fromOurWarningPage(sender) && isWebAddress(message.url)) {
    // Check again here: a block can never be continued past, whatever the page asked.
    const result = analyzeLink({ text: String(message.text || ''), href: message.url });
    if (result.verdict === 'block') { sendResponse({ ok: false }); return; }
    chrome.tabs.update(sender.tab.id, { url: message.url }).then(() => sendResponse({ ok: true }), () => sendResponse({ ok: false }));
    return true;
  }

  if (message.type === 'REPORT_FALSE_ALARM' && message.report) {
    saveReport(message.report).then(() => sendResponse({ ok: true }), () => sendResponse({ ok: false }));
    return true;
  }
});
