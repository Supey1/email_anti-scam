// page.js: runs on ordinary websites (not Gmail), in the main page only.
// Connects the scanner (collects evidence) to the scam checks (checkWebpage in rules.js) and the panel (shows).
// A warning card appears for any warning (block, or warn). A strong one (GO_BACK / DO_NOT_ENTER_INFO) is the same
// card with a stop-style headline; a weaker one ("Be careful: check this first") is the same card, gently worded.
// Neither covers the page or takes focus, and only the strong ones ever stop a click (click-guard.js).
// This file makes no decisions about scams itself. It only starts and stops checking
// according to the person's settings.

(() => {
  'use strict';

  let scanner = null;
  let evidence = null; // everything the scanner has seen on this page, within limits
  let lastSignature = '';
  const dismissed = new Set();

  function leave() {
    if (history.length > 1) history.back(); else location.replace('about:blank');
  }

  function evaluate() {
    const result = checkWebpage(evidence);
    if (result.verdict !== 'warn' && result.verdict !== 'block') return; // nothing found, or could not check
    const signature = result.verdict + result.reasons.map(r => r.code).join('|');
    if (signature === lastSignature || dismissed.has(signature)) return;
    lastSignature = signature;
    dismissed.add(signature); // "Hide" keeps it hidden until something new is found

    EmailAntiScamPanel.showWarning({
      result,
      modal: false,
      onBack: leave,
      onReport: () => chrome.runtime.sendMessage({
        type: 'REPORT_FALSE_ALARM',
        report: { host: location.hostname, verdict: result.verdict, reasons: result.reasons.slice(0, 5).map(r => r.explanation), source: 'page-scan' },
      }).catch(() => {}),
    });
  }

  function startChecking() {
    if (scanner) return;
    evidence = null;
    scanner = PageScanner.start({
      onEvidence(found) {
        evidence = found.context.scan === 'initial' || !evidence ? found : PageScanner.merge(evidence, found);
        evaluate();
      },
    });
  }

  function stopChecking() {
    if (!scanner) return;
    scanner.stop();
    scanner = null;
    EmailAntiScamPanel.close();
  }

  // Check this website only if the person's settings say so.
  function apply() {
    if (Settings.shouldCheckSite(Settings.current, location.hostname)) startChecking(); else stopChecking();
  }
  Settings.ready.then(apply);
  Settings.onChange(apply);

  // The popup asks whether this page is really being checked, and can ask for a fresh check.
  chrome.runtime.onMessage.addListener((message, sender, respond) => {
    if (message.type === 'STATUS') respond({ checking: !!scanner, kind: 'webpage' });
    if (message.type === 'RESCAN') {
      if (scanner) { lastSignature = ''; dismissed.clear(); scanner.scanNow(); }
      respond({ ok: !!scanner });
    }
  });
})();
