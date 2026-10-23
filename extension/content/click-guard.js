// click-guard.js: stops a risky link from being followed, BEFORE the browser navigates.
// Runs on every website (including inside ads and other frames) and on Gmail (only for links in an email).
//
// Workflow: listen for link clicks -> find the link, where it really goes, and the words around it (the rest
// of an ad) -> ask the detection engine, analyze() (docs/interfaces.md, source "link") -> if the engine
// recommends GO_BACK or DO_NOT_ENTER_INFO, cancel the click and ask the service worker to show the
// extension's own warning page (blocked.html). Everything else is left completely alone, including weak
// warnings (VERIFY_INDEPENDENTLY): those never interrupt a click. This file makes no judgement about
// scams itself.
//
// What it catches: ordinary clicks, Enter on a focused link, middle-click, Ctrl/Cmd/Shift-click, links with
// target="_blank", links inside shadow DOM, SVG links, links inside frames, and clicks on elements inside a link.
//
// What it CANNOT guarantee (see docs/click-guard-limits.md):
//   - navigation done by a website's own script (location.href = ..., window.open, meta refresh,
//     redirects after the page loads), or a click the page triggers with a.click()
//   - links opened from the right-click menu, dragged to the address bar, or opened by other extensions
//   - a link whose address a site's own click handler rewrites after our check
//   - a typed or pasted address
// Sites on the known-dangerous list are still blocked when they load (background/threat-rules.js),
// however the person got there.

// Other files can add evidence about a link. gmail.js says when a link is inside an email that looks like
// a scam. Each provider gets the clicked link and returns extra context fields (surroundingResult), or nothing.
const GUARD_CONTEXT_PROVIDERS = [];

(() => {
  'use strict';

  const XLINK = 'http://www.w3.org/1999/xlink';
  const IN_TOP_FRAME = window.top === window;
  const MAX_NEARBY = 400;

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

  // What the link says: its words, or for a picture its description.
  function linkText(anchor) {
    const img = anchor.querySelector && anchor.querySelector('img[alt]');
    return (anchor.textContent || '').replace(/\s+/g, ' ').trim() || anchor.getAttribute('aria-label') || anchor.getAttribute('title') || (img ? img.alt : '');
  }

  // The words around a link: the largest surrounding box that still holds only a few sentences. For an ad, that is
  // usually the whole ad. A marked advertisement (content/ad-signals.js) gives another view of the same thing; the
  // longer of the two wins, because a link that is itself marked (an ad-network link, say) says almost nothing alone.
  function nearbyText(anchor) {
    let text = '';
    for (let node = anchor; node && node !== document.documentElement; node = node.parentElement) {
      const t = (node.innerText || '').replace(/\s+/g, ' ').trim();
      if (t.length > MAX_NEARBY) break;
      text = t;
    }
    const ad = typeof AdSignals !== 'undefined' ? AdSignals.contextFor(anchor) : null;
    return (ad && ad.text && ad.text.length > text.length ? ad.text : text).slice(0, MAX_NEARBY);
  }

  // Would the browser have opened this click in a new tab or window? (In Gmail the warning always opens in a new tab,
  // so the mailbox the person is reading stays where it is.)
  function opensNewTab(event, anchor) {
    if (location.hostname === 'mail.google.com') return true;
    const target = (anchor.getAttribute('target') || (document.querySelector('base[target]') || {}).target || '').toLowerCase();
    return target === '_blank' || event.ctrlKey || event.metaKey || event.shiftKey || event.button === 1;
  }

  function reportFalseAlarm(result, url) {
    if (typeof chrome === 'undefined' || !chrome.runtime || !chrome.runtime.sendMessage) return;
    chrome.runtime.sendMessage({ type: 'REPORT_FALSE_ALARM', schemaVersion: 1, report: { host: url.hostname, verdict: result.verdict, reasons: result.reasons.map(r => r.explanation).slice(0, 5), source: 'click-guard' } }).catch(() => {});
  }

  // Asks the service worker for the extension's own warning page (OPEN_WARNING_PAGE). If that isn't possible
  // (for example the extension was just updated), shows the in-page card so the click still ends safely.
  function showWarning(result, url, text, newTab) {
    const fallback = () => EmailAntiScamPanel.showWarning({
      result,
      modal: true,
      destination: [`This link really goes to: ${url.hostname}`],
      onContinue: () => (newTab ? window.open(url.href, '_blank', 'noopener') : location.assign(url.href)),
      onReport: () => reportFalseAlarm(result, url),
    });
    try {
      chrome.runtime.sendMessage({ type: 'OPEN_WARNING_PAGE', schemaVersion: 1, result, url: url.href, linkText: text, newTab })
        .then(reply => { if (!reply || reply.type !== 'WARNING_PAGE_OPENED') fallback(); }, fallback);
    } catch (e) {
      fallback();
    }
  }

  function handle(event) {
    // Only real clicks by a person. A script's own a.click() is a known limit, listed above.
    if (!event.isTrusted) return;
    if (event.type === 'click' && event.button !== 0) return;
    if (event.type === 'auxclick' && event.button !== 1) return; // right-click is the context menu, not a navigation

    const anchor = findAnchor(event);
    if (!anchor) return;
    const url = destinationOf(anchor);
    if (!url || !/^https?:$/.test(url.protocol)) return; // javascript:, mailto:, tel:, etc. are not web destinations
    if (anchor.closest('#email-anti-scam-warning')) return;

    const text = linkText(anchor);
    const context = { nearbyText: nearbyText(anchor), insideFrame: !IN_TOP_FRAME };
    for (const provider of GUARD_CONTEXT_PROVIDERS) Object.assign(context, provider(anchor) || {});
    const result = analyze({
      source: 'link',
      pageUrl: (location.protocol === 'file:' && document.documentElement.getAttribute('data-practice-url')) || location.href,
      pageTitle: '',
      visibleText: '',
      links: [{ text: text.slice(0, 200), url: url.href }],
      forms: [],
      context,
    });
    // The engine decides whether to interrupt: only these two actions stop a click.
    if (!Explain.interrupts(result)) return;

    event.preventDefault();
    event.stopImmediatePropagation();
    showWarning(result, url, text.slice(0, 200), opensNewTab(event, anchor));
  }

  window.addEventListener('click', handle, true);
  window.addEventListener('auxclick', handle, true);
})();
