// gmail-adapter.js: the Gmail-specific part. It reads the open email and produces EVIDENCE in the
// shared format (docs/interfaces.md, source "email"). It decides nothing about scams, and all of
// Gmail's page structure lives in this file so the generic page scanner never needs to know it.
//
// Gmail changes its markup now and then. If emails stop being found, update SELECTORS below.
// Each field lists selectors to try in order; diagnose() reports which ones match, and
// tests/browser/gmail-adapter.test.js checks the extraction against a Gmail-shaped page.
//
// Privacy: only the open email's own message text is read: never the compose box, the search box,
// or any input. The mailbox part of the address (the "#inbox/..." message id) is dropped.

const GmailAdapter = (() => {
  'use strict';

  const SELECTORS = {
    subject: ['h2.hP'],
    sender: ['span.gD'],   // has email="..." and name="..." attributes
    body: ['div.a3s'],     // the message text, one per opened message in a thread
  };

  const LIMITS = { maxTextChars: 20000, maxLinks: 100, maxLinkTextChars: 100, throttleMs: 400 };
  const collapse = text => text.replace(/\s+/g, ' ').trim();

  function visible(el) { return !!el && el.offsetParent !== null; }

  function queryVisible(doc, selectors) {
    for (const selector of selectors) {
      const found = [...doc.querySelectorAll(selector)].filter(visible);
      if (found.length) return found;
    }
    return [];
  }

  // How many visible elements each selector group matches right now (for troubleshooting).
  function diagnose(doc = document) {
    const counts = {};
    for (const [field, selectors] of Object.entries(SELECTORS)) counts[field] = queryVisible(doc, selectors).length;
    return counts;
  }

  // Reads the open email. Returns evidence, or null when no email is open (or its message text can't be found).
  function readOpenEmail(doc = document, limits = LIMITS) {
    const bodies = queryVisible(doc, SELECTORS.body);
    if (!bodies.length) return null;
    const body = bodies[bodies.length - 1]; // newest opened message in a thread

    const subjectEl = queryVisible(doc, SELECTORS.subject)[0];
    const senders = queryVisible(doc, SELECTORS.sender);
    const senderEl = senders[senders.length - 1];
    const subject = subjectEl ? collapse(subjectEl.textContent) : '';

    const links = [];
    for (const a of body.querySelectorAll('a[href]')) {
      if (links.length >= limits.maxLinks) break;
      if (!/^https?:$/.test(a.protocol)) continue;
      const img = a.querySelector('img[alt]');
      links.push({ text: collapse(a.textContent || (img && img.alt) || a.getAttribute('aria-label') || '').slice(0, limits.maxLinkTextChars), url: a.href });
    }

    const location = doc.defaultView ? doc.defaultView.location : { origin: '', pathname: '' };
    return {
      source: 'email',
      pageUrl: location.origin + location.pathname, // no "#inbox/<message id>"
      pageTitle: subject,
      visibleText: collapse(body.innerText || body.textContent || '').slice(0, limits.maxTextChars),
      links,
      forms: [],
      context: {
        senderName: senderEl ? (senderEl.getAttribute('name') || collapse(senderEl.textContent)) : '',
        senderEmail: senderEl ? (senderEl.getAttribute('email') || '') : '',
        subject,
      },
    };
  }

  // Watches Gmail for opened emails. onEvidence(evidence) runs once per email shown;
  // onClear() runs when no email is open. Returns { stop(), scanNow() }.
  function start({ onEvidence, onClear, doc = document, limits = LIMITS }) {
    let lastSignature = '';
    let timer = null;

    function scan() {
      timer = null;
      const evidence = readOpenEmail(doc, limits);
      if (!evidence) {
        if (lastSignature) { lastSignature = ''; onClear(); }
        return;
      }
      const signature = `${evidence.context.senderEmail}|${evidence.context.subject}|${evidence.visibleText.length}|${evidence.links.length}`;
      if (signature === lastSignature) return;
      lastSignature = signature;
      onEvidence(evidence);
    }

    // Gmail changes the page without reloading, so watch for changes and re-check a few times per second at most.
    const observer = new MutationObserver(() => { if (!timer) timer = setTimeout(scan, limits.throttleMs); });
    observer.observe(doc.body, { childList: true, subtree: true });
    scan();

    return {
      stop() { observer.disconnect(); if (timer) clearTimeout(timer); },
      scanNow: scan,
    };
  }

  return { start, readOpenEmail, diagnose, SELECTORS, LIMITS };
})();
