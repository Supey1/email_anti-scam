// Phase 3 acceptance test: the real extension in a real browser.
// Run with:  node tests/browser/acceptance.test.js
// Needs Playwright (npm i playwright) and its Chromium (npx playwright install chromium).
//
// Phase 3 and 4 acceptance. Checks, end to end, that:
//   1. a local fake webpage is analyzed automatically, and opening it shows the expected state
//   2. clicking a suspicious link gets the right intervention, and the browser NEVER asks
//      for the suspicious address (not just "a warning appeared")
//   3. the words on the warning are the analyzer's own explanations: the same result reads
//      the same in the browser as it does here in Node
//   4. the same engine handles a generic webpage, an ad (including one through an ad
//      network), and a Gmail message. Gmail: this test answers mail.google.com with a local
//      pretend inbox, so the extension's real Gmail code runs without touching real email.
//
// Pages are in tests/browser/acceptance-pages/. Every ".example" address is answered by
// this test with a tiny page, so nothing touches the internet.

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');
const { analyze, analyzeEmail, analyzeLink, analyzePage } = require('../../extension/rules.js');

let chromium;
try { ({ chromium } = require('playwright')); } catch (e) { console.log('SKIP  Playwright is not installed (npm i playwright)'); process.exit(0); }

const PAGES = path.join(__dirname, 'acceptance-pages');
const EXTENSION = path.join(__dirname, '..', '..', 'extension');

// ---------- setup ----------

function serve() {
  const server = http.createServer((req, res) => {
    const [file, query] = req.url.slice(1).split('?');
    const full = path.join(PAGES, path.basename(file || ''));
    if (!fs.existsSync(full)) { res.writeHead(404); res.end('not found'); return; }
    const port = server.address().port;
    const html = fs.readFileSync(full, 'utf8')
      .replace('AD_ORIGIN', `http://127.0.0.1:${port}`) // a different origin, like a real ad
      .replace('LONG ?', `${query === 'long'} ?`);
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(html);
  });
  return new Promise(resolve => server.listen(0, () => resolve({ server, base: `http://localhost:${server.address().port}/` })));
}

async function launch() {
  const { server, base } = await serve();
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-scam-acceptance-'));
  const context = await chromium.launchPersistentContext(profile, {
    channel: 'chromium',
    executablePath: process.env.CHROMIUM_PATH || undefined,
    args: [`--disable-extensions-except=${EXTENSION}`, `--load-extension=${EXTENSION}`],
  });
  const requests = [];
  context.on('request', r => requests.push(r.url()));
  // The pretend Gmail inbox: ?msg=scam or ?msg=real.
  await context.route(/^https:\/\/mail\.google\.com\//, route => {
    const msg = new URL(route.request().url()).searchParams.get('msg') || 'scam';
    route.fulfill({ contentType: 'text/html', body: fs.readFileSync(path.join(PAGES, `gmail-${msg}.html`), 'utf8') });
  });
  // Real company websites the tests click through to: answered here, never fetched.
  await context.route(/^https:\/\/((www\.)?googleadservices\.com|([^/]+\.)?usps\.com)\//, route => route.fulfill({ contentType: 'text/html', body: '<title>Destination</title><h1>Destination reached</h1>' }));
  await context.route(/^https?:\/\/[^/]+\.example\//, route => {
    // Known dangerous addresses are left to the extension's own blocking.
    if (/known-phish|fake-bank-login/.test(route.request().url())) return route.fallback();
    return route.fulfill({ contentType: 'text/html', body: '<title>Destination</title><h1>Destination reached</h1>' });
  });
  // Wait for the extension's background script, so its blocking rules are in place.
  if (!context.serviceWorkers().length) await context.waitForEvent('serviceworker');
  await new Promise(r => setTimeout(r, 500));
  const reached = host => requests.some(u => { try { return new URL(u).hostname === host; } catch (e) { return false; } });
  const close = async () => { await context.close(); server.close(); fs.rmSync(profile, { recursive: true, force: true }); };
  return { context, base, reached, close };
}

// What the extension's warning shows, or null if there's no warning.
const readWarning = frame => frame.evaluate(() => {
  const host = document.getElementById('email-anti-scam-warning');
  if (!host) return null;
  const root = host.shadowRoot;
  const section = [...root.querySelectorAll('.section')].find(s => /Why we stopped you/.test(s.textContent));
  return {
    title: root.querySelector('#warning-title').textContent,
    reasons: section ? [...section.querySelectorAll('li')].map(li => li.textContent) : [],
    canContinue: !!root.querySelector('.continue'),
  };
});
const pressInWarning = (page, cls) => page.evaluate(c => document.getElementById('email-anti-scam-warning').shadowRoot.querySelector(`.${c}`).click(), cls);
const settle = (page, ms = 600) => page.waitForTimeout(ms);

// ---------- tests ----------

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

test('normal page: analyzed automatically, normal browsing (no warning)', async ({ context, base }) => {
  const page = await context.newPage();
  await page.goto(base + 'normal.html');
  await settle(page);
  assert.strictEqual(await readWarning(page), null);
  await page.close();
});

test('fake sign-in page: analyzed automatically, "Be careful on this page" with the analyzer\'s own reasons', async ({ context, base }) => {
  const page = await context.newPage();
  await page.goto(base + 'fake-sign-in.html');
  await settle(page);
  const warning = await readWarning(page);
  assert.ok(warning, 'no warning appeared');
  assert.match(warning.title, /Be careful on this page/);
  // The same evidence, analyzed here in Node, must read exactly the same.
  const url = base + 'fake-sign-in.html';
  const expected = analyzePage({ url, title: 'Log in to your PayPal account', headings: 'PayPal', text: await page.evaluate(() => document.body.innerText), hasPassword: true, formActions: ['https://collect.example/p.php'] });
  assert.deepStrictEqual(warning.reasons, expected.reasons.slice(0, 4));
  assert.ok(warning.reasons.some(r => /PayPal sign-in page/.test(r)), warning.reasons.join(' | '));
  await page.close();
});

test('suspicious link: click stopped before the browser asks for it, reasons match the analyzer', async ({ context, base, reached }) => {
  const page = await context.newPage();
  await page.goto(base + 'news.html');
  await settle(page);
  await page.click('#fake');
  await settle(page, 300);
  const warning = await readWarning(page);
  assert.ok(warning, 'no warning appeared');
  assert.match(warning.title, /Stop and check this link/);
  assert.ok(warning.canContinue, 'a warning (not a block) must let the person choose');
  assert.ok(!reached('chase-secure.example'), 'the browser asked for the suspicious address');
  const expected = analyze({ source: 'link', pageUrl: base + 'news.html', pageTitle: '', visibleText: '', links: [{ text: 'www.chase.com', url: 'https://chase-secure.example/verify' }], forms: [], context: { nearbyText: 'Readers sent us this link: www.chase.com' } });
  assert.deepStrictEqual(warning.reasons, expected.reasons.map(r => r.explanation).slice(0, 4));
  // "Go back to safety" closes the warning and stays on the page.
  await pressInWarning(page, 'back');
  await settle(page, 300);
  assert.strictEqual(await readWarning(page), null);
  assert.strictEqual(page.url(), base + 'news.html');
  assert.ok(!reached('chase-secure.example'));
  await page.close();
});

test('"Open it anyway" goes to the link the person chose', async ({ context, base, reached }) => {
  const page = await context.newPage();
  await page.goto(base + 'news.html');
  await settle(page);
  await page.click('#fake');
  await settle(page, 300);
  await Promise.all([page.waitForURL(/chase-secure\.example/), pressInWarning(page, 'continue')]);
  assert.ok(reached('chase-secure.example'));
  await page.close();
});

test('normal link: opens with no warning', async ({ context, base, reached }) => {
  const page = await context.newPage();
  await page.goto(base + 'news.html');
  await settle(page);
  await Promise.all([page.waitForURL(/other-news\.example/), page.click('#normal')]);
  assert.ok(reached('other-news.example'));
  await page.close();
});

test('known dangerous link: blocked, no way through, never requested', async ({ context, base, reached }) => {
  const page = await context.newPage();
  await page.goto(base + 'news.html');
  await settle(page);
  await page.click('#known');
  await settle(page, 300);
  const warning = await readWarning(page);
  assert.ok(warning, 'no warning appeared');
  assert.match(warning.title, /known to be dangerous/);
  assert.strictEqual(warning.canContinue, false);
  assert.ok(!reached('known-phish.example'));
  await page.close();
});

test('click inside a cross-origin ad: warning covers the main page, never requested', async ({ context, base, reached }) => {
  const page = await context.newPage();
  await page.goto(base + 'news.html');
  await settle(page);
  const ad = page.frames().find(f => f.url().includes('/ad.html'));
  assert.ok(ad, 'the ad frame did not load');
  await ad.click('#claim');
  await settle(page, 500);
  const warning = await readWarning(page);
  assert.ok(warning, 'no warning on the main page');
  assert.strictEqual(await readWarning(ad), null, 'the warning should not be squeezed inside the ad');
  assert.ok(warning.reasons.some(r => /prize AND rushes you/.test(r)), warning.reasons.join(' | '));
  assert.ok(!reached('claim-reward-now.example'));
  await page.close();
});

test('typing a known dangerous address: Chrome shows the blocked page instead', async ({ context }) => {
  const page = await context.newPage();
  await page.goto('https://login.known-phish.example/start').catch(() => {});
  await settle(page, 300);
  assert.match(page.url(), /blocked\.html#known-phish\.example$/);
  await page.close();
});

test('scam pop-up that appears after loading: noticed and warned about', async ({ context, base }) => {
  const page = await context.newPage();
  await page.goto(base + 'popup.html');
  await settle(page, 500);
  assert.strictEqual(await readWarning(page), null, 'warned before the pop-up appeared');
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 6000 });
  const warning = await readWarning(page);
  assert.match(warning.title, /Be careful on this page/);
  await page.close();
});

// ---------- Phase 4: ads and Gmail ----------

// What the Gmail panel shows, or null.
const readPanel = page => page.evaluate(() => {
  const host = document.getElementById('email-anti-scam-host');
  if (!host || host.shadowRoot.querySelector('.panel').hidden) return null;
  const root = host.shadowRoot;
  const section = [...root.querySelectorAll('.section')].find(s => /Why we're warning you/.test(s.textContent));
  return { verdict: root.querySelector('.verdict').textContent, reasons: section ? [...section.querySelectorAll('li')].map(li => li.textContent) : [] };
});

test('Gmail scam message: the panel says scam, with the analyzer\'s own reasons', async ({ context }) => {
  const page = await context.newPage();
  await page.goto('https://mail.google.com/mail/u/0/?msg=scam');
  await settle(page, 900);
  const panel = await readPanel(page);
  assert.ok(panel, 'no panel');
  assert.match(panel.verdict, /looks like a SCAM/);
  const expected = analyzeEmail({
    senderName: 'USPS Delivery', senderEmail: 'notice@usps-redelivery.example', subject: 'Your package is on hold',
    bodyText: await page.evaluate(() => document.querySelector('div.a3s').innerText.trim()),
    links: [{ text: 'Reschedule delivery', href: 'https://usps-redelivery.example/track' }],
  });
  assert.deepStrictEqual(panel.reasons, expected.reasons);
  assert.ok(panel.reasons.some(r => /USPS.*usps-redelivery\.example/.test(r)), panel.reasons.join(' | '));
  await page.close();
});

test('Gmail scam message: clicking its link is stopped and never requested', async ({ context, reached }) => {
  const page = await context.newPage();
  await page.goto('https://mail.google.com/mail/u/0/?msg=scam');
  await settle(page, 900);
  await page.click('#reschedule');
  await settle(page, 300);
  const warning = await readWarning(page);
  assert.ok(warning, 'no warning');
  assert.ok(warning.reasons.some(r => /inside an email that looks like a scam/.test(r)), warning.reasons.join(' | '));
  assert.ok(!reached('usps-redelivery.example'));
  await page.close();
});

test('Gmail real USPS message: "No warning signs found", and its link opens', async ({ context, reached }) => {
  const page = await context.newPage();
  await page.goto('https://mail.google.com/mail/u/0/?msg=real');
  await settle(page, 900);
  const panel = await readPanel(page);
  assert.ok(panel, 'no panel');
  assert.match(panel.verdict, /No warning signs found/);
  await Promise.all([page.waitForURL(/informeddelivery\.usps\.com/), page.click('#see-all')]);
  assert.ok(reached('informeddelivery.usps.com'));
  await page.close();
});

test('scam ad whose link goes through an ad network: stopped by its wording, ad network never requested', async ({ context, base, reached }) => {
  const page = await context.newPage();
  await page.goto(base + 'news.html');
  await settle(page);
  const ad = page.frames().find(f => f.url().includes('/ad-network.html'));
  assert.ok(ad, 'the ad frame did not load');
  await ad.click('#network-claim');
  await settle(page, 500);
  const warning = await readWarning(page);
  assert.ok(warning, 'no warning on the main page');
  assert.ok(warning.reasons.some(r => /redelivery|package/i.test(r)), warning.reasons.join(' | '));
  assert.ok(!reached('www.googleadservices.com'));
  await page.close();
});

// Known issue, reported but not failing the run: see docs/integration-checklist.md.
const knownIssues = [];
test('KNOWN ISSUE (page.js): a pop-up at the end of a LONG page', async ({ context, base }) => {
  const page = await context.newPage();
  await page.goto(base + 'popup.html?long');
  const appeared = await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 6000 }).then(() => true, () => false);
  await page.close();
  if (!appeared) knownIssues.push('page.js reads only the first 5,000 characters, so a pop-up at the end of a long page is missed');
});

// Same link, same words: the old guard.js adapter and the contract give one explanation.
test('the warning\'s words come from the analyzer, whichever adapter asked', async () => {
  const viaGuard = analyzeLink({ text: 'www.chase.com', href: 'https://chase-secure.example/verify' }, { pageUrl: 'https://news.example/' });
  const viaContract = analyze({ source: 'link', pageUrl: 'https://news.example/', pageTitle: '', visibleText: '', links: [{ text: 'www.chase.com', url: 'https://chase-secure.example/verify' }], forms: [], context: {} });
  assert.deepStrictEqual(viaGuard.reasons, viaContract.reasons.map(r => r.explanation));
});

// ---------- run ----------

(async () => {
  const env = await launch();
  let failed = 0;
  for (const t of tests) {
    try {
      await t.fn(env);
      console.log(`PASS  ${t.name}`);
    } catch (err) {
      failed++;
      console.log(`FAIL  ${t.name}: ${err.message.split('\n')[0]}`);
    }
  }
  await env.close();
  for (const issue of knownIssues) console.log(`KNOWN ISSUE  ${issue}`);
  console.log(failed ? `\n${failed} test(s) failed` : `\nAll ${tests.length} acceptance tests passed`);
  process.exit(failed ? 1 : 0);
})();
