// Click protection success: for every risky-click scenario, was navigation REALLY stopped?
// Run with:  node tests/browser/click-matrix.test.js
// "Supported" scenarios (ones the engine says must interrupt) must be stopped every time, or the test fails.
// "Weak" scenarios are warnings the engine deliberately does not interrupt on. "Documented limit" scenarios are
// ways a page can move you that no click guard sees. Both are recorded as not stopped, so the numbers are not flattered. Results go to tests/results/click-protection.json
// and into docs/test-results.md (node tests/metrics.js --write).
// "Stopped" means the browser never requested the destination AND the page was not navigated there.

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { launch, run } = require('./harness');

const WARNING = /\/blocked\.html/;
const results = [];

// kind: 'same' = click in the same tab, 'tab' = click that opens a new tab, 'page' = open, then act
const S = (id, file, selector, host, options = {}) => ({ id, supported: true, file, selector, host, ...options });
const L = (id, file, selector, host, options = {}) => ({ id, supported: false, file, selector, host, ...options });

const W = (id, file, selector, host, options = {}) => ({ id, supported: false, weak: true, file, selector, host, ...options });

const scenarios = [
  S('plain click on a look-alike company link', 'click-guard.html', '#bad', 'paypa1-secure.example'),
  S('target=_blank', 'click-guard.html', '#bad-blank', 'paypa1-secure.example', { opensTab: true }),
  S('Ctrl-click', 'click-guard.html', '#bad', 'paypa1-secure.example', { click: { modifiers: ['Control'] }, opensTab: true }),
  S('Shift-click', 'click-guard.html', '#bad', 'paypa1-secure.example', { click: { modifiers: ['Shift'] }, opensTab: true }),
  S('middle-click', 'click-guard.html', '#bad', 'paypa1-secure.example', { click: { button: 'middle' }, opensTab: true }),
  S('keyboard Enter', 'click-guard.html', '#bad', 'paypa1-secure.example', { keyboard: true }),
  S('click on an element inside the link', 'click-guard.html', '#nested-inner', 'paypa1-secure.example'),
  S('link with unusual attributes', 'click-guard.html', '#unusual', 'paypa1-secure.example'),
  S('SVG link', 'click-guard.html', '#svg', 'paypa1-secure.example'),
  S('link inside shadow DOM', 'click-guard.html', '#shadow-link', 'paypa1-secure.example'),
  S('known dangerous address', 'click-guard.html', '#known', 'known-phish.example'),
  S('look-alike behind a search-engine redirect', 'fake-redirect.html', '#wrapped-bad', 'paypa1-secure.example'),
  S('look-alike company address', 'fake-redirect.html', '#direct-bad', 'paypa1-secure.example'),
  S('look-alike link on a generic page', 'fake-webpage.html', '#lookalike', 'paypa1-secure.example'),
  S('prize advertisement', 'fake-ad.html', '#ad-prize-link', 'claim-gift.example', { wait: 800 }),
  S('prize advertisement inserted later', 'fake-ad.html', '#ad-late-link', 'claim-gift.example', { wait: 2500 }),
  S('link added to the page later', 'fake-webpage.html', '#late', 'paypa1-secure.example', { before: p => p.evaluate(() => { const a = document.createElement('a'); a.id = 'late'; a.href = 'https://paypa1-secure.example/late'; a.textContent = 'Log in to PayPal'; document.body.append(a); }) }),
  S('look-alike link on a fake login page', 'fake-login.html', '#verify', 'paypa1-secure.example'),
  S('click inside a frame', 'fake-iframes.html', null, 'claim-gift.example', { frame: '#same-origin', frameSelector: '#frame-link', wait: 1500 }),
  S('click inside a srcdoc frame', 'fake-iframes.html', null, 'claim-gift.example', { frame: '#srcdoc', frameSelector: '#frame-link', wait: 1500 }),

  // Weak warnings: shown, never interrupting, by the engine's design (docs/interfaces.md). Recorded, not counted as failures.
  W('hidden destination alone (weak warning)', 'click-guard.html', '#weak', 'other-site.example'),
  W('raw number address alone (weak warning)', 'click-guard.html', '#weak-number', '192.168.4.20'),

  L('page script sets the address', 'fake-redirect.html', '#js-location', 'other-site.example'),
  L('page script opens a window', 'fake-redirect.html', '#js-open', 'other-site.example', { opensTab: true }),
  L('link rewrites itself when clicked', 'fake-redirect.html', '#rewrite', 'other-site.example'),
  L('script clicks a link by itself', 'fake-redirect.html', '#script-click', 'other-site.example'),
  L('form sends you to another site', 'fake-redirect.html', '#form-get', 'other-site.example'),
  L('page redirects itself after loading', 'fake-redirect.html', '#meta-page', 'other-site.example'),
  L('unknown redirect service', 'fake-redirect.html', '#open-redirect', 'redirector.example'),
];

async function perform(env, s) {
  const page = await env.context.newPage();
  await page.goto(env.secure + s.file);
  await page.waitForTimeout(s.wait || 600);
  if (s.before) await s.before(page);
  await page.evaluate(() => document.getElementById('email-anti-scam-warning')?.remove()); // the corner card can cover the link
  env.requests.length = 0;
  const extra = [];
  env.context.on('page', p => extra.push(p));
  if (s.frame) await page.frameLocator(s.frame).locator(s.frameSelector).click();
  else if (s.keyboard) { await page.focus(s.selector); await page.keyboard.press('Enter'); }
  else await page.click(s.selector, s.click || {});
  await page.waitForTimeout(1500);
  const requested = env.reached(s.host);
  const navigatedHere = new URL(s.host.includes(':') ? 'http://x' : `http://${s.host}`).hostname && [page, ...extra].some(p => { try { return new URL(p.url()).hostname === s.host; } catch (e) { return false; } });
  const sawWarning = [page, ...extra].some(p => WARNING.test(p.url())) || !!(await page.evaluate(() => !!document.getElementById('email-anti-scam-warning')));
  for (const p of extra) await p.close().catch(() => {});
  await page.close();
  return { stopped: !requested && !navigatedHere, sawWarning, requested };
}

const tests = scenarios.map(s => ({
  name: `${s.supported ? 'supported' : s.weak ? 'weak     ' : 'limit    '}: ${s.id}`,
  fn: async env => {
    const r = await perform(env, s);
    results.push({ id: s.id, supported: s.supported, weak: !!s.weak, stopped: r.stopped, warned: r.sawWarning });
    if (s.supported) assert.ok(r.stopped && r.sawWarning, `NOT stopped (requested the destination: ${r.requested}, warning shown: ${r.sawWarning})`);
    else if (s.weak) assert.ok(!r.stopped, 'a weak warning interrupted a click, but only strong evidence should');
    else console.log(`      (documented limit) ${r.stopped ? 'was stopped after all' : 'not stopped, as documented'}`);
  },
}));

(async () => {
  const env = await launch();
  const origExit = process.exit;
  process.exit = code => {
    const supported = results.filter(r => r.supported);
    const summary = { supported: supported.length, stopped: supported.filter(r => r.stopped && r.warned).length, limits: results.filter(r => !r.supported && !r.weak).length, limitsStopped: results.filter(r => !r.supported && !r.weak && r.stopped).length, weak: results.filter(r => r.weak).length, scenarios: results };
    fs.writeFileSync(path.join(__dirname, '..', 'results', 'click-protection.json'), JSON.stringify(summary, null, 2) + '\n');
    console.log(`\nClick protection success: ${summary.stopped}/${summary.supported} supported scenarios stopped; ${summary.limits - summary.limitsStopped}/${summary.limits} documented limits confirmed as not stopped`);
    origExit(code);
  };
  await run(tests, env);
})();
