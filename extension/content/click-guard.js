// click-guard.js: stops a risky link from being followed, BEFORE the browser navigates.
//
// Workflow: listen for link clicks -> find the link and where it really goes -> run the local
// checks (analyzeLink) -> if the verdict is warn or block, cancel the click and ask the service
// worker to show the extension-owned warning page. Safe links are left completely alone.
//
// What it catches: ordinary clicks, Enter on a focused link, middle-click, Ctrl/Cmd/Shift-click,
// links with target="_blank", links inside shadow DOM, SVG links, and clicks on elements inside a link.
//
// What it CANNOT guarantee (see docs/click-guard-limits.md):
//   - navigation done by a website's own script (location.href = ..., window.open, meta refresh,
//     redirects after the page loads), or a click the page triggers with a.click()
//   - links opened from the right-click menu, dragged to the address bar, or opened by other extensions
//   - a link whose address a site's own click handler rewrites after our check
//   - links inside iframes the extension isn't running in
// Sites already known to be dangerous are still blocked when they load (service-worker.js),
// however the person got there.

(() => {
  'use strict';

  const onGmail = location.hostname === 'mail.google.com';
  const GMAIL_BODY = 'div.a3s'; // Gmail: only guard links inside an opened email
  const XLINK = 'http://www.w3.org/1999/xlink';

  // The <a> (or <area>) the click is really on, even from a child element, shadow DOM, or SVG.
  function findAnchor(event) {
    for (const node of event.composedPath()) {
      if (node.nodeType !== Node.ELEMENT_NODE) continue;
      if ((node.localName === 'a' || node.localName === 'area') && (node.hasAttribute('href') || node.hasAttributeNS(XLINK, 'href'))) return node;
    }
    return null;
  }

  // Where the link goes, as a full address. Works for HTML and SVG links.
  function destinationOf(anchor) {
    const raw = anchor.getAttribute('href') ?? anchor.getAttributeNS(XLINK, 'href');
    try { return new URL(raw, anchor.ownerDocument.baseURI); } catch (e) { return null; }
  }

  // Would the browser have opened this click in a new tab or window?
  function opensNewTab(event, anchor) {
    const target = (anchor.getAttribute('target') || (document.querySelector('base[target]') || {}).target || '').toLowerCase();
    return onGmail || target === '_blank' || event.ctrlKey || event.metaKey || event.shiftKey || event.button === 1;
  }

  function reportFalseAlarm(result, url) {
    chrome.runtime.sendMessage({ type: 'REPORT_FALSE_ALARM', report: { host: url.hostname, verdict: result.verdict, reasons: result.reasons.slice(0, 5), source: 'click-guard' } }).catch(() => {});
  }

  // Asks the service worker for the extension's warning page. If that isn't possible
  // (for example the extension was just updated), shows the in-page card so the click still ends safely.
  function showWarning(result, url, text, newTab) {
    const fallback = () => EmailAntiScamPanel.showWarning({
      result,
      modal: true,
      destination: `This link really goes to: ${url.hostname}`,
      onContinue: result.verdict === 'warn' ? () => (newTab ? window.open(url.href, '_blank', 'noopener') : location.assign(url.href)) : null,
      onReport: () => reportFalseAlarm(result, url),
    });
    try {
      chrome.runtime.sendMessage({ type: 'SHOW_WARNING', url: url.href, text, newTab }).then(reply => { if (!reply || !reply.ok) fallback(); }, fallback);
    } catch (e) {
      fallback();
    }
  }

  function handle(event) {
    // Only real clicks by a person. A script's own a.click() is a known limit, listed above.
    if (!event.isTrusted) return;
    if (event.type === 'auxclick' && event.button !== 1) return; // right-click is the context menu, not a navigation

    const anchor = findAnchor(event);
    if (!anchor) return;
    const url = destinationOf(anchor);
    if (!url || !/^https?:$/.test(url.protocol)) return; // javascript:, mailto:, tel:, etc. are not web destinations
    if (anchor.closest('#email-anti-scam-warning')) return;
    if (onGmail && !anchor.closest(GMAIL_BODY)) return;
    if (!onGmail && RULES.baseDomain(url.hostname) === RULES.baseDomain(location.hostname)) return; // same website

    const text = (anchor.textContent || '').trim();
    const result = analyzeLink({ text, href: url.href });
    if (result.verdict === 'allow') return; // normal behavior: do nothing at all

    event.preventDefault();
    event.stopImmediatePropagation();
    showWarning(result, url, text, opensNewTab(event, anchor));
  }

  document.addEventListener('click', handle, true);
  document.addEventListener('auxclick', handle, true);
})();
