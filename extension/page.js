// page.js: checks the website you're looking at (every site except Gmail,
// which gmail.js handles).
// 1. Reads the page's address, title, main heading, words, and sign-in boxes.
// 2. Checks it with analyzePage() from rules.js.
// 3. If it looks like a scam, covers it with the big warning (warning.js).
//
// Many scam pop-ups appear after the page has loaded, so we keep watching for
// changes for a while. We only warn once per page: if the person chooses to
// stay, we don't keep interrupting them.

(() => {
  'use strict';

  if (window.top !== window) return; // only the main page; guard.js covers ads and frames

  const RECHECK_DELAY = 2000; // re-check at most every 2 seconds...
  const MAX_RECHECKS = 30;    // ...and stop after a while, so busy pages don't slow down

  let warned = false;
  let rechecks = 0;
  let lastTextLength = -1;

  // Practice pages (tests/*.html) are opened as files, which have no web
  // address. They pretend to be a website by setting data-practice-url.
  function pageUrl() {
    if (window.location.protocol === 'file:') {
      return document.documentElement.dataset.practiceUrl || window.location.href;
    }
    return window.location.href;
  }

  function readPage() {
    const passwordForms = [...document.querySelectorAll('input[type="password"]')]
      .map(input => input.form)
      .filter(Boolean);
    return {
      url: pageUrl(),
      title: document.title,
      headings: [...document.querySelectorAll('h1')].slice(0, 3).map(h => h.innerText).join('\n'),
      text: document.body ? document.body.innerText.slice(0, 5000) : '',
      hasPassword: !!document.querySelector('input[type="password"]'),
      // Where each sign-in form sends what you type. (A form with no address sends it back to this page.)
      formActions: passwordForms.map(form => new URL(form.getAttribute('action') || '', pageUrl()).href),
    };
  }

  function leavePage() {
    if (window.history.length > 1) window.history.back();
    else window.location.replace('about:blank');
  }

  function check() {
    if (warned || !document.body) return;
    const page = readPage();
    if (page.text.length === lastTextLength) return;
    lastTextLength = page.text.length;

    const result = analyzePage(page);
    if (result.action === 'allow') return;
    warned = true;
    const blocked = result.action === 'block';
    showWarning({
      kind: blocked ? 'block' : 'page',
      result,
      onBack: leavePage,
      onContinue: blocked ? null : () => {},
    });
  }

  let pending = null;
  const observer = new MutationObserver(() => {
    if (pending || warned) return;
    pending = setTimeout(() => {
      pending = null;
      if (++rechecks > MAX_RECHECKS) observer.disconnect();
      else check();
    }, RECHECK_DELAY);
  });
  observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
  check();
})();
