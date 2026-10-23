// gmail.js: connects the Gmail adapter to the shared analyzer and the warning interface.
// No scam logic here: evidence in from gmail-adapter.js, a result from checkEmail() (rules.js), words from Explain.
//
// EmailAntiScamGmail.currentResult is the open email's result: click-guard.js stops any link
// inside an email that looks like a scam.
const EmailAntiScamGmail = { currentResult: null };

(() => {
  'use strict';

  let reopen = null;

  // Inside the extension. (tests/fake-gmail.html also runs this file on its own, without it.)
  const inExtension = typeof chrome !== 'undefined' && !!chrome.runtime && !!chrome.runtime.id;

  function reportFalseAlarm(evidence, result) {
    if (!inExtension) return;
    chrome.runtime.sendMessage({
      type: 'REPORT_FALSE_ALARM',
      report: { host: (evidence.context.senderEmail.split('@')[1] || 'unknown'), verdict: result.verdict, reasons: result.reasons.slice(0, 5).map(r => r.explanation), source: 'gmail' },
    }).catch(() => {});
  }

  // Extra facts shown under the explanation: who sent it and where the links really go.
  function extrasFor(evidence, result) {
    const extras = [{
      heading: 'Who sent this',
      lines: [{ text: evidence.context.senderName || 'Unknown sender' }, evidence.context.senderEmail ? { text: evidence.context.senderEmail, muted: true } : null],
    }];
    const links = (result.links || []).filter(l => l.host).slice(0, 5);
    if (links.length) {
      extras.push({
        heading: 'Links in this email',
        lines: links.flatMap(l => [
          { text: l.text || '(picture or button)' },
          { text: `Really goes to: ${l.host}`, muted: true },
          l.flags.length ? { text: `⚠ ${l.flags.join(', ')}`, flag: true } : null,
        ]),
      });
    }
    return extras;
  }

  function show(evidence, result) {
    EmailAntiScamPanel.showWarning({
      result,
      modal: false,
      extras: extrasFor(evidence, result),
      primaryLabel: 'Got it',
      where: 'email',
      leaveChip: true, // after "Got it" or "Hide", a small button brings the panel back
      onReport: () => reportFalseAlarm(evidence, result),
    });
  }

  let watcher = null;

  function apply() {
    if (Settings.shouldCheckEmail(Settings.current)) {
      if (watcher) return;
      watcher = GmailAdapter.start({
        onEvidence(evidence) {
          const result = checkEmail(evidence);
          EmailAntiScamGmail.currentResult = result;
          show(evidence, result);
        },
        onClear() { EmailAntiScamGmail.currentResult = null; EmailAntiScamPanel.close({ removeChip: true }); },
      });
    } else if (watcher) {
      watcher.stop();
      watcher = null;
      EmailAntiScamGmail.currentResult = null;
      EmailAntiScamPanel.close({ removeChip: true });
    }
  }
  Settings.ready.then(apply);
  Settings.onChange(apply);

  // The popup asks whether Gmail is really being checked, and can ask for a fresh check.
  if (inExtension) chrome.runtime.onMessage.addListener((message, sender, respond) => {
    if (message.type === 'STATUS') respond({ checking: !!watcher, kind: 'email' });
    if (message.type === 'RESCAN') { if (watcher) watcher.scanNow(); respond({ ok: !!watcher }); }
  });
})();
