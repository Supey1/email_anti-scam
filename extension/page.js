// page.js: runs on ordinary websites (not Gmail).
// Connects the scanner (collects evidence) to the analyzer (decides) and the panel (shows).
// This file makes no decisions about scams itself.

(() => {
  'use strict';

  let evidence = null; // everything the scanner has seen on this page, within limits
  let lastSignature = '';
  const dismissed = new Set();

  // TEMPORARY ADAPTER (see docs/integration-checklist.md): the analyzer still takes the old
  // input shape. Delete this once analyzer.js accepts the evidence in docs/interfaces.md.
  function toAnalyzerInput(e) {
    return {
      url: e.pageUrl,
      title: e.pageTitle,
      visibleText: e.visibleText,
      links: e.links.map(l => ({ text: l.text, href: l.url })),
      forms: e.forms,
    };
  }

  function leave() {
    if (history.length > 1) history.back(); else location.replace('about:blank');
  }

  function evaluate() {
    const result = analyzePage(toAnalyzerInput(evidence));
    if (result.verdict === 'allow') return;
    const signature = result.verdict + result.reasons.join('|');
    if (signature === lastSignature || dismissed.has(signature)) return;
    lastSignature = signature;
    dismissed.add(signature); // "Hide" keeps it hidden until something new is found

    EmailAntiScamPanel.showWarning({
      verdict: result.verdict,
      reasons: result.reasons,
      advice: result.recommendedAction,
      modal: false,
      onBack: leave,
    });
  }

  PageScanner.start({
    onEvidence(found) {
      evidence = found.context.scan === 'initial' || !evidence ? found : PageScanner.merge(evidence, found);
      evaluate();
    },
  });
})();
