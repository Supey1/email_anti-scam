// guard.js: stops a risky link click BEFORE the browser leaves the page.
// Runs on every website, including inside ads and other frames.
//
// 1. Notices a click on a link (left click, middle click, Ctrl/Cmd click, or Enter).
// 2. Reads the link, where it really goes, and the words around it (like the rest of an ad).
// 3. Checks it with analyzeLink() from rules.js.
// 4. If it looks dangerous, cancels the click and shows the big warning (warning.js).
//
// Known limits: links opened from the right-click menu, or pages that move
// you somewhere using their own code instead of a normal link, don't go
// through here. Known dangerous websites are still blocked by
// service-worker.js; other tricks need to be tested one by one.

// Other files can add evidence about a link. For example, gmail.js says when a
// link is inside an email that looks like a scam. Each provider gets the
// clicked link and returns extra context for analyzeLink(), or nothing.
const GUARD_CONTEXT_PROVIDERS = [];

(() => {
  'use strict';

  const IN_TOP_FRAME = window.top === window;
  const HAS_EXTENSION = typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id;

  // What the link says: its words, or for a picture, its description.
  function linkText(anchor) {
    const img = anchor.querySelector('img[alt]');
    return (anchor.innerText || '').trim() || anchor.getAttribute('aria-label') ||
      anchor.getAttribute('title') || (img ? img.alt : '');
  }

  // The words around a link: the smallest surrounding box with a few sentences
  // in it. For an ad, that's usually the whole ad.
  function nearbyText(anchor) {
    let text = '';
    for (let node = anchor; node && node !== document.documentElement; node = node.parentElement) {
      const t = (node.innerText || '').trim();
      if (t.length > 400) break;
      text = t;
    }
    return text;
  }

  function openLink(href, newTab) {
    if (newTab) window.open(href, '_blank', 'noopener');
    else window.location.assign(href);
  }

  // Shows the warning in this page. Clicks inside an ad's frame are sent to the
  // main page first, so the warning covers the whole screen, not just the ad.
  function present({ href, result, newTab }) {
    if (!IN_TOP_FRAME && HAS_EXTENSION) {
      chrome.runtime.sendMessage({ type: 'granblock-warning', href, result, newTab: true })
        .then(reply => { if (!reply || !reply.shown) present.local({ href, result, newTab }); })
        .catch(() => present.local({ href, result, newTab }));
      return;
    }
    present.local({ href, result, newTab });
  }
  present.local = ({ href, result, newTab }) => {
    const blocked = result.action === 'block';
    showWarning({
      kind: blocked ? 'block' : 'link',
      result,
      onBack: () => {},
      onContinue: blocked ? null : () => openLink(href, newTab),
    });
  };

  function onClick(event) {
    if (event.type === 'click' && event.button !== 0) return;
    if (event.type === 'auxclick' && event.button !== 1) return;
    const anchor = event.composedPath().find(n => n instanceof Element && n.matches('a[href], area[href]'));
    if (!anchor || typeof anchor.href !== 'string' || !/^https?:/i.test(anchor.href)) return;

    const context = { pageUrl: window.location.href, nearbyText: nearbyText(anchor) };
    for (const provider of GUARD_CONTEXT_PROVIDERS) Object.assign(context, provider(anchor) || {});
    const result = analyzeLink({ text: linkText(anchor), href: anchor.href }, context);
    if (result.action === 'allow') return;

    // Stop the browser AND the page's own code from following the link.
    event.preventDefault();
    event.stopImmediatePropagation();
    const newTab = anchor.target === '_blank' || event.ctrlKey || event.metaKey || event.shiftKey || event.button === 1;
    present({ href: anchor.href, result, newTab });
  }

  // "true" = see the click first, before the page's own code does.
  window.addEventListener('click', onClick, true);
  window.addEventListener('auxclick', onClick, true);

  // The main page shows warnings for clicks that happened inside its frames.
  if (IN_TOP_FRAME && HAS_EXTENSION) {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message && message.type === 'granblock-warning') {
        present.local(message);
        sendResponse({ shown: true });
      }
    });
  }
})();
