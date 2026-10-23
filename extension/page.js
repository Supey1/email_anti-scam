// page.js: runs on ordinary websites (not Gmail).
// Connects the scanner (collects evidence) to the analyzer (decides) and the panel (shows).
// This file makes no decisions about scams itself.

(() => {
  'use strict';

  let evidence = null; // everything the scanner has seen on this page, within limits
  let lastSignature = '';
  const dismissed = new Set();

  function leave() {
    if (history.length > 1) history.back(); else location.replace('about:blank');
  }

  function evaluate() {
    const result = analyze(evidence);
    if (result.verdict === 'allow') return;
    const signature = result.verdict + result.reasons.join('|');
    if (signature === lastSignature || dismissed.has(signature)) return;
    lastSignature = signature;
    dismissed.add(signature); // "Hide" keeps it hidden until something new is found

    EmailAntiScamPanel.showWarning({
      result,
      modal: false,
      onBack: leave,
      onReport: () => chrome.runtime.sendMessage({
        type: 'REPORT_FALSE_ALARM',
        report: { host: location.hostname, verdict: result.verdict, reasons: result.reasons.slice(0, 5), source: 'page-scan' },
      }).catch(() => {}),
    });
  }

  PageScanner.start({
    onEvidence(found) {
      evidence = found.context.scan === 'initial' || !evidence ? found : PageScanner.merge(evidence, found);
      evaluate();
    },
  });
})();
