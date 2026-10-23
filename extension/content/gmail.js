// gmail.js: connects the Gmail adapter to the engine and the warning interface.
// No scam logic here: evidence in from gmail-adapter.js, a result from analyze(), words from Explain.

(() => {
  'use strict';

  let lastResult = null; // the engine's answer for the email on screen
  let watcher = null;

  const HAS_EXTENSION = typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id;

  function reportFalseAlarm(evidence, result) {
    if (!HAS_EXTENSION) return;
    chrome.runtime.sendMessage({
      type: 'REPORT_FALSE_ALARM',
      schemaVersion: 1,
      report: { host: (evidence.context.senderEmail.split('@')[1] || 'unknown'), verdict: result.verdict, reasons: result.reasons.map(r => r.explanation).slice(0, 5), source: 'gmail' },
    }).catch(() => {});
  }

  // Extra facts shown under the explanation: who sent it, and where its links really go.
  function extrasFor(evidence, result) {
    const extras = [{
      heading: 'Who sent this',
      lines: [{ text: evidence.context.senderName || 'Unknown sender' }, evidence.context.senderEmail ? { text: evidence.context.senderEmail, muted: true } : null],
    }];
    const hosts = [];
    for (const item of result.evidence) {
      if (item.kind !== 'url') continue;
      try { const host = new URL(item.value).hostname; if (!hosts.includes(host)) hosts.push(host); } catch (e) { /* not an address */ }
    }
    if (hosts.length) extras.push({ heading: 'Where the warning links really go', lines: hosts.slice(0, 3).map(host => ({ text: host, muted: true })) });
    return extras;
  }

  function show(evidence, result) {
    lastResult = result;
    EmailAntiScamPanel.showWarning({
      result,
      modal: false,
      extras: extrasFor(evidence, result),
      primaryLabel: 'Got it',
      leaveChip: true, // after "Got it" or "Hide", a small button brings the panel back
      onReport: () => reportFalseAlarm(evidence, result),
    });
  }

  // Links inside an email that looks like a scam are held to a higher standard (the engine's INSIDE_SCAM_EMAIL).
  GUARD_CONTEXT_PROVIDERS.push(anchor => {
    if (!lastResult || !anchor.closest || !anchor.closest(GmailAdapter.SELECTORS.body[0])) return null;
    const stops = lastResult.verdict === 'block' || (lastResult.verdict === 'warn' && lastResult.recommendedAction === 'GO_BACK');
    return stops ? { surroundingResult: { verdict: lastResult.verdict, recommendedAction: 'GO_BACK' } } : null;
  });

  watcher = GmailAdapter.start({
    onEvidence(evidence) { show(evidence, analyze(evidence)); },
    onClear() { lastResult = null; EmailAntiScamPanel.close({ removeChip: true }); },
  });

  // The popup asks whether Gmail is really being checked, and can ask for a fresh check.
  if (HAS_EXTENSION) chrome.runtime.onMessage.addListener((message, sender, respond) => {
    if (!message || message.type === undefined) return;
    if (message.type === 'PAGE_STATUS') respond({ type: 'PAGE_STATUS_RESULT', schemaVersion: 1, checking: true, kind: 'email' });
    if (message.type === 'PAGE_RESCAN') { watcher.scanNow(); respond({ type: 'PAGE_RESCAN_RESULT', schemaVersion: 1, ok: true }); }
  });
})();
