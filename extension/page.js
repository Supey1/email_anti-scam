// page.js: runs on ordinary websites (not Gmail).
// Collects evidence from the page, checks it with analyzePage(), and shows a warning
// card if the page has credible warning signs. Watches for content added later.

(() => {
  'use strict';

  const MAX_TEXT = 20000;
  const MAX_LINKS = 200;
  let lastSignature = '';
  let dismissed = new Set();
  let pending = null;

  function collectEvidence() {
    const forms = [...document.forms].map(f => ({
      action: f.action || location.href,
      hasPassword: !!f.querySelector('input[type="password"]'),
      hasPayment: !!f.querySelector('input[autocomplete="cc-number"], input[name*="card" i][type="text"]'),
    }));
    // Pages built with scripts often have password boxes outside any <form>.
    const loose = [...document.querySelectorAll('input[type="password"]')].filter(i => !i.form);
    if (loose.length) forms.push({ action: location.href, hasPassword: true, hasPayment: false });

    return {
      source: 'webpage',
      url: location.href,
      title: document.title,
      visibleText: (document.body ? document.body.innerText : '').slice(0, MAX_TEXT),
      links: [...document.links].slice(0, MAX_LINKS).map(a => ({ text: a.textContent.trim().slice(0, 100), href: a.href })),
      forms,
    };
  }

  function scan() {
    if (document.hidden) return;
    const result = analyzePage(collectEvidence());
    if (result.verdict === 'allow') return;
    const signature = result.verdict + result.reasons.join('|');
    if (signature === lastSignature || dismissed.has(signature)) return;
    lastSignature = signature;

    const leave = () => { if (history.length > 1) history.back(); else location.replace('about:blank'); };
    EmailAntiScamPanel.showWarning({
      verdict: result.verdict,
      reasons: result.reasons,
      advice: result.recommendedAction,
      modal: false,
      onBack: leave,
    });
    dismissed.add(signature); // "Hide" keeps it hidden until something new is found
  }

  const observer = new MutationObserver(() => {
    if (pending) return;
    pending = setTimeout(() => { pending = null; scan(); }, 1500);
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
  scan();
})();
