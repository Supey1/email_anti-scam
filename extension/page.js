// page.js: runs on ordinary websites (not Gmail).
// Connects the scanner (collects evidence) to the engine (decides) and the panel (shows).
// This file makes no decision about scams itself: it shows a warning only when the engine's
// recommendedAction says to interrupt (GO_BACK or DO_NOT_ENTER_INFO). Weaker warnings never cover the page.

(() => {
  'use strict';

  let evidence = null; // everything the scanner has seen on this page, within limits
  let lastSignature = '';
  const dismissed = new Set();
  let scanner = null;

  function leave() {
    if (history.length > 1) history.back(); else location.replace('about:blank');
  }

  function evaluate() {
    const result = analyze(evidence);
    if (!Explain.interrupts(result)) return;
    const signature = result.verdict + result.recommendedAction + result.reasons.map(r => r.code).join('|');
    if (signature === lastSignature || dismissed.has(signature)) return;
    lastSignature = signature;
    dismissed.add(signature); // "Hide" keeps it hidden until something new is found

    EmailAntiScamPanel.showWarning({
      result,
      modal: false,
      onBack: leave,
      onReport: () => typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage && chrome.runtime.sendMessage({
        type: 'REPORT_FALSE_ALARM',
        schemaVersion: 1,
        report: { host: location.hostname, verdict: result.verdict, reasons: result.reasons.map(r => r.explanation).slice(0, 5), source: 'page-scan' },
      }).catch(() => {}),
    });
  }

  scanner = PageScanner.start({
    onEvidence(found, meta) {
      evidence = meta.scan === 'initial' || !evidence ? found : PageScanner.merge(evidence, found);
      evaluate();
    },
  });

  // The popup asks whether this page is really being checked, and can ask for a fresh check.
  const HAS_EXTENSION = typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id;
  if (HAS_EXTENSION) chrome.runtime.onMessage.addListener((message, sender, respond) => {
    if (!message || message.type === undefined) return;
    if (message.type === 'PAGE_STATUS') respond({ type: 'PAGE_STATUS_RESULT', schemaVersion: 1, checking: true, kind: 'webpage' });
    if (message.type === 'PAGE_RESCAN') {
      lastSignature = '';
      dismissed.clear();
      scanner.scanNow();
      respond({ type: 'PAGE_RESCAN_RESULT', schemaVersion: 1, ok: true });
    }
  });
})();
