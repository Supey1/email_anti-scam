// guard.js: stops a risky link click BEFORE the browser navigates.
// Runs on every website, and on Gmail (only for links inside an email).
//
// Limits: this covers ordinary clicks and keyboard "Enter" on a link. A website's own
// script that opens a page by itself, or a link opened from the right-click menu,
// is not caught here (known-dangerous sites are still blocked by the service worker).

(() => {
  'use strict';

  const onGmail = location.hostname === 'mail.google.com';
  const GMAIL_BODY = 'div.a3s';

  function findLink(event) {
    return event.composedPath().find(n => n instanceof HTMLAnchorElement && n.href);
  }

  function handle(event) {
    // Our own "Continue anyway" re-click is not a real click (isTrusted is false), so it passes through.
    if (!event.isTrusted) return;
    if (event.type === 'auxclick' && event.button !== 1) return;

    const link = findLink(event);
    if (!link || !/^https?:/i.test(link.href)) return;
    if (onGmail && !link.closest(GMAIL_BODY)) return;
    if (!onGmail && RULES.baseDomain(link.hostname) === RULES.baseDomain(location.hostname)) return;

    const result = analyzeLink({ text: link.textContent.trim(), href: link.href });
    if (result.verdict === 'allow') return;

    event.preventDefault();
    event.stopImmediatePropagation();
    EmailAntiScamPanel.showWarning({
      verdict: result.verdict,
      reasons: result.reasons,
      advice: result.recommendedAction,
      destination: `This link really goes to: ${result.host}`,
      modal: true,
      onContinue: result.verdict === 'warn' ? () => link.click() : null,
    });
  }

  document.addEventListener('click', handle, true);
  document.addEventListener('auxclick', handle, true);
})();
