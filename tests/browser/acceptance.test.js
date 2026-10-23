// Phase 3 acceptance test: the real extension in a real browser.
// Run with:  node tests/browser/acceptance.test.js
// Needs Playwright (npm i playwright) and its Chromium (npx playwright install chromium).
//
// Phase 3, 4, and 5 acceptance. Checks, end to end, that:
//   1. a local fake webpage is analyzed automatically, and opening it shows the expected state
//   2. clicking a suspicious link gets the right intervention, and the browser NEVER asks
//      for the suspicious address (not just "a warning appeared")
//   3. the words on the warning are the analyzer's own explanations: the same result reads
//      the same in the browser as it does here in Node
//   4. the same engine handles a generic webpage, an ad (including one through an ad
//      network), and a Gmail message. Gmail: this test answers mail.google.com with a local
//      pretend inbox, so the extension's real Gmail code runs without touching real email.
//   5. Chrome's own network rules block known dangerous test addresses, and DON'T block
//      normal addresses that look like them; updates, false positives, and lookup errors
//      behave as described in docs/threat-intelligence.md.
//   6. the settings page turns protection on and off, sets text size and reading aloud;
//      a fresh install (no website access yet) still blocks known dangerous websites;
//      and settings, rules, and page scripts survive a browser restart.
//
// Website access: the real extension asks for it on its welcome page, and Chrome shows a
// prompt a test can't click. So most tests run on a COPY of the extension whose manifest
// already grants it (as if the person clicked "Allow"), and the "fresh install" tests run
// on an unchanged copy, with no access.
//
// Every test address is answered by this test, so an address that "loads" is one Chrome
// let through; Chrome's blocking acts before that, so a blocked one never reaches it.
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

// A copy of the extension. access: true adds the website access the person would
// give on the welcome page.
function copyExtension(access) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-scam-extension-'));
  fs.cpSync(EXTENSION, dir, { recursive: true });
  if (access) {
    const manifestPath = path.join(dir, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    manifest.host_permissions = ['http://*/*', 'https://*/*'];
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  }
  return dir;
}

//   access     give website access (see copyExtension above)
//   extension  reuse this copy, and profile this browser profile (for the restart test)
async function launch({ access = true, extension = copyExtension(access), profile = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-scam-acceptance-')), keep = false } = {}) {
  const { server, base } = await serve();
  const context = await chromium.launchPersistentContext(profile, {
    channel: 'chromium',
    executablePath: process.env.CHROMIUM_PATH || undefined,
    args: [`--disable-extensions-except=${extension}`, `--load-extension=${extension}`],
  });
  const requests = [];
  const served = []; // test addresses that actually reached the network (Chrome let them through)
  context.on('request', r => requests.push(r.url()));
  // The pretend Gmail inbox: ?msg=scam or ?msg=real.
  await context.route(/^https:\/\/mail\.google\.com\//, route => {
    const msg = new URL(route.request().url()).searchParams.get('msg') || 'scam';
    route.fulfill({ contentType: 'text/html', body: fs.readFileSync(path.join(PAGES, `gmail-${msg}.html`), 'utf8') });
  });
  // Real company websites the tests click through to: answered here, never fetched.
  await context.route(/^https:\/\/((www\.)?googleadservices\.com|([^/]+\.)?usps\.com)\//, route => route.fulfill({ contentType: 'text/html', body: '<title>Destination</title><h1>Destination reached</h1>' }));
  await context.route(/^https?:\/\/[^/]+\.example\//, route => {
    served.push(new URL(route.request().url()).hostname);
    route.fulfill({ contentType: 'text/html', body: '<title>Destination</title><h1>Destination reached</h1>' });
  });
  // Wait for the extension's background script: its blocking rules, and (with access) its page scripts.
  const worker = context.serviceWorkers()[0] || await context.waitForEvent('serviceworker');
  for (let i = 0; i < 50; i++) {
    const [rules, scripts] = await worker.evaluate(async () => [
      (await chrome.declarativeNetRequest.getDynamicRules()).length,
      (await chrome.scripting.getRegisteredContentScripts()).length,
    ]);
    if (rules > 0 && (!access || scripts === 3)) break;
    await new Promise(r => setTimeout(r, 100));
  }
  await new Promise(r => setTimeout(r, 300));
  const reached = host => requests.some(u => { try { return new URL(u).hostname === host; } catch (e) { return false; } });
  const close = async () => {
    await context.close();
    server.close();
    if (!keep) for (const dir of [profile, extension]) fs.rmSync(dir, { recursive: true, force: true });
  };
  // Sends a message straight to the service worker, as the extension's own settings page would.
  const extensionOrigin = worker.url().replace(/service-worker\.js$/, '');
  const toWorker = (message, sender = { url: `${extensionOrigin}settings.html` }) =>
    worker.evaluate(([m, s]) => GranblockBackground.instance.handleMessage(m, s), [{ schemaVersion: 1, ...message }, sender]);
  const settingsPage = async () => {
    const page = await context.newPage();
    await page.goto(`${extensionOrigin}settings.html`);
    await page.waitForFunction(() => /Protection/.test(document.getElementById('status').textContent));
    return page;
  };
  return { context, base, reached, served: host => served.includes(host), close, worker, toWorker, settingsPage, extensionOrigin, profile, extension };
}

// What the extension's warning shows, or null if there's no warning. It is either the in-page card (inside a
// shadow root) or, for a stopped click or a blocked website, the extension's own page (blocked.html).
const readWarning = frame => frame.evaluate(() => {
  const own = location.protocol === 'chrome-extension:';
  const host = document.getElementById('email-anti-scam-warning');
  if (!own && !host) return null;
  const root = own ? document : host.shadowRoot;
  const card = root.querySelector('.card');
  if (!card) return null;
  const reasonText = li => [...li.childNodes].filter(n => n.nodeName !== 'STRONG').map(n => n.textContent).join('');
  const lis = [...root.querySelectorAll('.card .section > ul > li'), ...root.querySelectorAll('.card details.more li')];
  return {
    title: root.querySelector('h1').textContent,
    label: root.querySelector('.label').textContent,
    reasons: lis.map(reasonText),
    canContinue: [...root.querySelectorAll('button')].some(b => /Continue anyway/.test(b.textContent)),
  };
});
// "back" is the big safe button; "continue" is the small secondary one (warnings only).
const pressInWarning = (page, which) => page.evaluate(w => {
  const own = location.protocol === 'chrome-extension:';
  const root = own ? document : document.getElementById('email-anti-scam-warning').shadowRoot;
  const buttons = [...root.querySelectorAll('button')];
  (w === 'back' ? buttons.find(b => b.classList.contains('primary')) : buttons.find(b => /Continue anyway/.test(b.textContent))).click();
}, which);
const BLOCKED_PAGE = /^chrome-extension:\/\/[^/]+\/blocked\.html/;
// The page text the way the scanner reads it (whitespace collapsed), so the same words reach the engine here.
const pageWords = page => page.evaluate(() => document.body.innerText.replace(/\s+/g, ' ').trim());
const settle = (page, ms = 600) => page.waitForTimeout(ms);

// ---------- tests ----------

// Three groups, each in its own browser: with website access (most tests), a fresh
// install without it, and a restart.
const groups = { access: [], fresh: [], restart: [] };
const test = (name, fn) => groups.access.push({ name, fn });
const freshTest = (name, fn) => groups.fresh.push({ name, fn });
const restartTest = (name, fn) => groups.restart.push({ name, fn });

test('normal page: analyzed automatically, normal browsing (no warning)', async ({ context, base }) => {
  const page = await context.newPage();
  await page.goto(base + 'normal.html');
  await settle(page);
  assert.strictEqual(await readWarning(page), null);
  await page.close();
});

test('fake sign-in page: analyzed automatically, told "do not type" with the analyzer\'s own reasons', async ({ context, base }) => {
  const page = await context.newPage();
  await page.goto(base + 'fake-sign-in.html');
  await settle(page);
  const warning = await readWarning(page);
  assert.ok(warning, 'no warning appeared');
  assert.strictEqual(warning.title, 'Do not type anything on this page');
  // The same evidence, analyzed here in Node, must read exactly the same.
  const expected = analyze({ source: 'webpage', pageUrl: base + 'fake-sign-in.html', pageTitle: 'Log in to your PayPal account', visibleText: await pageWords(page), links: [],
    forms: [{ action: 'https://collect.example/p.php', hasPassword: true, hasPaymentField: false }], context: { mainHeadings: ['PayPal'] } });
  assert.deepStrictEqual(warning.reasons, expected.reasons.map(r => r.explanation));
  assert.ok(warning.reasons.some(r => /PayPal sign-in page/.test(r)), warning.reasons.join(' | '));
  await page.close();
});

test('suspicious link: click stopped before the browser asks for it, reasons match the analyzer', async ({ context, base, reached }) => {
  const page = await context.newPage();
  await page.goto(base + 'news.html');
  await settle(page);
  await page.click('#fake');
  await page.waitForURL(BLOCKED_PAGE);
  const warning = await readWarning(page);
  assert.ok(warning, 'no warning appeared');
  assert.strictEqual(warning.title, 'Stop and check this first');
  assert.ok(warning.canContinue, 'a warning (not a block) must let the person choose');
  assert.ok(!reached('chase-secure.example'), 'the browser asked for the suspicious address');
  const expected = analyze({ source: 'link', pageUrl: base + 'news.html', pageTitle: '', visibleText: '', links: [{ text: 'www.chase.com', url: 'https://chase-secure.example/verify' }], forms: [], context: { nearbyText: 'Readers sent us this link: www.chase.com', insideFrame: false } });
  assert.deepStrictEqual(warning.reasons, expected.reasons.map(r => r.explanation));
  // "Go back to safety" returns to the page with the link.
  await pressInWarning(page, 'back');
  await page.waitForURL(base + 'news.html');
  assert.strictEqual(await readWarning(page), null);
  assert.ok(!reached('chase-secure.example'));
  await page.close();
});

test('"Open it anyway" goes to the link the person chose', async ({ context, base, reached }) => {
  const page = await context.newPage();
  await page.goto(base + 'news.html');
  await settle(page);
  await page.click('#fake');
  await page.waitForURL(BLOCKED_PAGE);
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
  await page.waitForURL(BLOCKED_PAGE);
  const warning = await readWarning(page);
  assert.ok(warning, 'no warning appeared');
  assert.strictEqual(warning.label, 'DANGER');
  assert.ok(warning.reasons.some(r => /known to be dangerous|known dangerous/i.test(r)), warning.reasons.join(' | '));
  assert.strictEqual(warning.canContinue, false);
  assert.ok(!reached('known-phish.example'));
  await page.close();
});

test('click inside a cross-origin ad: the warning covers the whole tab, never requested', async ({ context, base, reached }) => {
  const page = await context.newPage();
  await page.goto(base + 'news.html');
  await settle(page);
  const ad = page.frames().find(f => f.url().includes('/ad.html'));
  assert.ok(ad, 'the ad frame did not load');
  await ad.click('#claim');
  await page.waitForURL(BLOCKED_PAGE);
  const warning = await readWarning(page);
  assert.ok(warning, 'no warning on the main page');
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
  assert.match(warning.title, /Stop and check this first|Do not type anything on this page/);
  await page.close();
});

// ---------- Phase 4: ads and Gmail ----------

// What the Gmail panel shows, or null. (It is the same card as the page warning, so readWarning reads it.)
const readPanel = readWarning;

test('Gmail scam message: the panel warns, with the analyzer\'s own reasons', async ({ context }) => {
  const page = await context.newPage();
  await page.goto('https://mail.google.com/mail/u/0/?msg=scam');
  await settle(page, 900);
  const panel = await readPanel(page);
  assert.ok(panel, 'no panel');
  assert.strictEqual(panel.title, 'Stop and check this first');
  const expected = analyze({
    source: 'email', pageUrl: 'https://mail.google.com/mail/u/0/', pageTitle: 'Your package is on hold',
    visibleText: await page.evaluate(() => document.querySelector('div.a3s').innerText.replace(/\s+/g, ' ').trim()),
    links: [{ text: 'Reschedule delivery', url: 'https://usps-redelivery.example/track' }], forms: [],
    context: { senderName: 'USPS Delivery', senderEmail: 'notice@usps-redelivery.example', subject: 'Your package is on hold' },
  });
  assert.deepStrictEqual(panel.reasons, expected.reasons.map(r => r.explanation));
  assert.ok(panel.reasons.some(r => /USPS.*usps-redelivery\.example/.test(r)), panel.reasons.join(' | '));
  await page.close();
});

test('Gmail scam message: clicking its link is stopped (the warning opens in a new tab) and never requested', async ({ context, reached }) => {
  const page = await context.newPage();
  await page.goto('https://mail.google.com/mail/u/0/?msg=scam');
  await settle(page, 900);
  const [popup] = await Promise.all([context.waitForEvent('page'), page.click('#reschedule')]);
  await popup.waitForURL(BLOCKED_PAGE);
  const warning = await readWarning(popup);
  assert.ok(warning, 'no warning');
  assert.ok(warning.reasons.some(r => /inside an email that looks like a scam/.test(r)), warning.reasons.join(' | '));
  assert.ok(!reached('usps-redelivery.example'));
  assert.match(page.url(), /mail\.google\.com/, 'the mailbox stays where it was');
  await popup.close(); await page.close();
});

test('Gmail real USPS message: "No warning signs found", and its link opens', async ({ context, reached }) => {
  const page = await context.newPage();
  await page.goto('https://mail.google.com/mail/u/0/?msg=real');
  await settle(page, 900);
  const panel = await readPanel(page);
  assert.ok(panel, 'no panel');
  assert.strictEqual(panel.label, 'NO WARNING SIGNS');
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
  await page.waitForURL(BLOCKED_PAGE);
  const warning = await readWarning(page);
  assert.ok(warning, 'no warning on the main page');
  assert.ok(warning.reasons.some(r => /redelivery|package/i.test(r)), warning.reasons.join(' | '));
  assert.ok(!reached('www.googleadservices.com'));
  await page.close();
});

// ---------- Phase 5: browser-level blocking and threat lookups ----------

const BLOCKED = /^chrome-extension:\/\/[^/]+\/blocked\.html/;
// Types an address and reports what happened:
//   'blocked'           Chrome sent it to our blocked page
//   'blocked by Chrome' Chrome stopped it with its own error page (no website access yet)
//   'loaded'            it loaded
async function typeAddress(context, url) {
  const page = await context.newPage();
  let error = '';
  await page.goto(url).catch(e => { error = e.message; });
  await page.waitForTimeout(200);
  const where = BLOCKED.test(page.url()) ? 'blocked'
    : /ERR_BLOCKED_BY_CLIENT/.test(error) ? 'blocked by Chrome'
      : page.url() === url ? 'loaded' : `other: ${page.url()} ${error}`;
  await page.close();
  return where;
}

test('Chrome blocks the synthetic known-dangerous addresses: whole websites and a single address', async ({ context }) => {
  for (const url of ['https://known-phish.example/', 'https://login.known-phish.example/x', 'http://fake-bank-login.example/a',
    'https://hacked-blog.example/wp-content/uploads/secure/login.html']) {
    assert.strictEqual(await typeAddress(context, url), 'blocked', url);
  }
});

test('Chrome does NOT block normal addresses that look like listed ones', async ({ context }) => {
  for (const url of ['https://known-phish-news.example/', 'https://known-phish.example.other.example/', 'https://notknown-phish.example/',
    'https://hacked-blog.example/2024/recipes', 'https://hacked-blog.example/wp-content/uploads/secure-ish/page', 'https://other-news.example/lottery']) {
    assert.strictEqual(await typeAddress(context, url), 'loaded', url);
  }
});

test('an entry added later is blocked by Chrome AND by the click guard; marking it a false positive undoes both', async ({ context, base, toWorker }) => {
  const added = await toWorker({ type: 'UPDATE_THREAT_RULES', add: [{ type: 'domain', value: 'added-later.example', source: 'test', trusted: true }] });
  assert.strictEqual(added.type, 'THREAT_RULES_UPDATED');
  assert.strictEqual(await typeAddress(context, 'https://added-later.example/'), 'blocked');

  const clickIt = async () => {
    const page = await context.newPage();
    await page.goto(base + 'normal.html');
    await settle(page);
    await page.evaluate(() => {
      const a = Object.assign(document.createElement('a'), { id: 'late', href: 'https://added-later.example/', textContent: 'Open' });
      document.body.append(a);
    });
    await page.click('#late');
    await settle(page, 600);
    const warning = BLOCKED_PAGE.test(page.url()) ? await readWarning(page).catch(() => null) : null;
    await page.close();
    return warning;
  };
  const before = await clickIt();
  assert.ok(before && before.label === 'DANGER', 'the click guard does not know the new entry');

  await toWorker({ type: 'UPDATE_THREAT_RULES', falsePositives: ['added-later.example'] });
  assert.strictEqual(await typeAddress(context, 'https://added-later.example/'), 'loaded');
  assert.strictEqual(await clickIt(), null, 'the click guard still blocks a removed false positive');
  assert.strictEqual(await typeAddress(context, 'https://known-phish.example/'), 'blocked', 'other entries must stay');
});

test('an entry from an untrusted source is never hard-blocked by Chrome', async ({ context, toWorker }) => {
  await toWorker({ type: 'UPDATE_THREAT_RULES', add: [{ type: 'domain', value: 'maybe-bad.example', source: 'unchecked feed', trusted: false }] });
  assert.strictEqual(await typeAddress(context, 'https://maybe-bad.example/'), 'loaded');
  const lookup = await toWorker({ type: 'LOOKUP_URL', url: 'https://maybe-bad.example/' }, {});
  assert.deepStrictEqual([lookup.status, lookup.source.trusted], ['match', false]);
});

test('lookup answers: match, no_match (never "safe"), and error when the service fails or is too slow', async ({ toWorker }) => {
  const page = { url: 'https://news.example/' }; // a content script, not the extension
  assert.strictEqual((await toWorker({ type: 'LOOKUP_URL', url: 'https://known-phish.example/' }, page)).status, 'match');
  const none = await toWorker({ type: 'LOOKUP_URL', url: 'https://other-news.example/' }, page);
  assert.strictEqual(none.status, 'no_match');
  assert.ok(!/safe/i.test(JSON.stringify(none)));
  await toWorker({ type: 'SET_SETTINGS', settings: { remoteLookups: true, provider: 'mock', providerOptions: { fail: true } } });
  const failed = await toWorker({ type: 'LOOKUP_URL', url: 'https://other-news.example/x' }, page);
  assert.deepStrictEqual([failed.status, /could not be reached/.test(failed.reason)], ['error', true]);
  await toWorker({ type: 'SET_SETTINGS', settings: { providerOptions: { delayMs: 800 }, lookupTimeoutMs: 150 } });
  const slow = await toWorker({ type: 'LOOKUP_URL', url: 'https://other-news.example/y' }, page);
  assert.deepStrictEqual([slow.status, /no answer within 150 ms/.test(slow.reason)], ['error', true]);
  const refused = await toWorker({ type: 'SET_SETTINGS', settings: { protectionEnabled: false } }, page);
  assert.strictEqual(refused.type, 'ERROR', 'a website changed the settings');
  await toWorker({ type: 'SET_SETTINGS', settings: { remoteLookups: false, provider: 'none', providerOptions: {}, lookupTimeoutMs: 1500 } });
});

test('the extension\'s own warning page shows an analyzer result, with "open anyway" only for a warning', async ({ context, base, toWorker }) => {
  const page = await context.newPage();
  await page.goto(base + 'normal.html');
  const tab = await context.serviceWorkers()[0].evaluate(async url => (await chrome.tabs.query({})).find(t => t.url === url).id, base + 'normal.html');
  const result = analyze({ source: 'link', pageUrl: base, pageTitle: '', visibleText: '', links: [{ text: 'www.chase.com', url: 'https://chase-secure.example/verify' }], forms: [], context: {} });
  const opened = await toWorker({ type: 'OPEN_WARNING_PAGE', result, url: 'https://chase-secure.example/verify', linkText: 'www.chase.com' }, { url: base + 'normal.html', tab: { id: tab, index: 0 } });
  assert.strictEqual(opened.type, 'WARNING_PAGE_OPENED');
  await page.waitForURL(BLOCKED_PAGE);
  await page.waitForFunction(() => !!document.querySelector('.card'));
  const shown = await readWarning(page);
  assert.strictEqual(shown.title, 'Stop and check this first');
  assert.deepStrictEqual(shown.reasons, result.reasons.map(r => r.explanation));
  assert.ok(shown.canContinue);
  assert.match(await page.evaluate(() => document.body.innerText), /You clicked a link that says: \u201cwww\.chase\.com\u201d[\s\S]*It really goes to: chase-secure\.example/);
  await page.close();
});

// ---------- Phase 6: settings, reading aloud, fresh install, restart ----------

// The card's text size is 24px at "large" and scales with the setting: 24 x 1.45 = 34.8px at "largest".
const warningSize = page => page.evaluate(() => document.getElementById('email-anti-scam-warning').shadowRoot.querySelector('.card').style.fontSize);
const readButton = page => page.evaluate(() => [...document.getElementById('email-anti-scam-warning').shadowRoot.querySelectorAll('button')].find(b => /Read to me|Stop reading|read aloud/.test(b.textContent)).textContent);
const openFakeSignIn = async (context, base) => {
  const page = await context.newPage();
  await page.goto(base + 'fake-sign-in.html');
  await settle(page, 800);
  return page;
};

test('settings page: says what protection is doing, in plain words, and explains each permission', async ({ settingsPage }) => {
  const page = await settingsPage();
  assert.match(await page.textContent('#status'), /Protection is on: checking websites, ads, and Gmail/);
  assert.strictEqual(await page.getAttribute('#access-all', 'aria-pressed'), 'true');
  const privacy = await page.textContent('#privacy-heading + table');
  for (const words of ['Read and change your data on websites', 'Block content on any page', 'Storage', 'Scripting']) assert.ok(privacy.includes(words), words);
  await page.close();
});

test('settings page: turning protection off stops warnings and blocking; turning it on brings them back', async ({ context, base, settingsPage }) => {
  const settings = await settingsPage();
  await settings.click('#toggle-protection');
  await settings.waitForFunction(() => /Protection is off/.test(document.getElementById('status').textContent));
  let page = await openFakeSignIn(context, base);
  assert.strictEqual(await readWarning(page), null, 'still warning with protection off');
  await page.close();
  assert.strictEqual(await typeAddress(context, 'https://known-phish.example/'), 'loaded', 'still blocking with protection off');

  await settings.click('#toggle-protection');
  await settings.waitForFunction(() => /Protection is on/.test(document.getElementById('status').textContent));
  await settle(settings, 500);
  page = await openFakeSignIn(context, base);
  assert.ok(await readWarning(page), 'no warning after turning protection back on');
  await page.close();
  assert.strictEqual(await typeAddress(context, 'https://known-phish.example/'), 'blocked');
  await settings.close();
});

test('settings page: text size applies to warnings', async ({ context, base, settingsPage }) => {
  const settings = await settingsPage();
  await settings.check('input[name="textSize"][value="largest"]');
  await settle(settings, 400);
  const page = await openFakeSignIn(context, base);
  assert.strictEqual(await warningSize(page), '34.8px');
  await page.close();
  await settings.check('input[name="textSize"][value="large"]');
  await settle(settings, 300);
  await settings.close();
});

test('read aloud: with no voices on this computer, the button says so and the warning stays on screen', async ({ context, base }) => {
  const page = await openFakeSignIn(context, base);
  assert.match(await readButton(page), /Read to me/);
  await page.evaluate(() => [...document.getElementById('email-anti-scam-warning').shadowRoot.querySelectorAll('button')].find(b => /Read to me/.test(b.textContent)).click());
  await page.waitForFunction(() => [...document.getElementById('email-anti-scam-warning').shadowRoot.querySelectorAll('button')].some(b => /Couldn't read aloud|Stop reading/.test(b.textContent)));
  const text = await readButton(page);
  // This test browser has no voices. On a computer with voices it reads, and the button says "Stop reading".
  assert.match(text, /Couldn't read aloud\. The warning is written on screen|Stop reading/);
  assert.ok((await readWarning(page)).reasons.length > 0, 'the written warning must stay');
  await page.close();
});

test('read aloud automatically: a new warning starts reading by itself when the setting is on', async ({ context, base, settingsPage }) => {
  const settings = await settingsPage();
  await settings.check('#autoRead');
  await settle(settings, 400);
  const page = await openFakeSignIn(context, base);
  // It tried to read without a click: here (no voices) that shows as "Couldn't read aloud".
  await page.waitForFunction(() => ![...document.getElementById('email-anti-scam-warning').shadowRoot.querySelectorAll('button')].some(b => /Read to me/.test(b.textContent)));
  await page.close();
  await settings.uncheck('#autoRead');
  await settle(settings, 300);
  await settings.close();
});

freshTest('fresh install: the welcome page opens by itself and explains what access is for', async ({ context }) => {
  let welcome = context.pages().find(p => /settings\.html\?welcome=1/.test(p.url()));
  for (let i = 0; !welcome && i < 30; i++) { await new Promise(r => setTimeout(r, 100)); welcome = context.pages().find(p => /settings\.html\?welcome=1/.test(p.url())); }
  assert.ok(welcome, 'no welcome page');
  await welcome.waitForFunction(() => /Protection/.test(document.getElementById('status').textContent));
  assert.strictEqual(await welcome.isVisible('#welcome'), true);
  assert.match(await welcome.textContent('#status'), /can only block known dangerous websites/);
  assert.strictEqual(await welcome.getAttribute('#access-none', 'aria-pressed'), 'true');
});

freshTest('fresh install: no website access means no page scripts at all', async ({ context, base, worker }) => {
  assert.deepStrictEqual(await worker.evaluate(() => chrome.scripting.getRegisteredContentScripts()), []);
  const page = await openFakeSignIn(context, base);
  assert.strictEqual(await page.evaluate(() => !!document.getElementById('email-anti-scam-warning')), false);
  await page.close();
});

freshTest('fresh install: known dangerous websites are STILL blocked (by Chrome), normal ones load', async ({ context, served }) => {
  assert.strictEqual(await typeAddress(context, 'https://known-phish.example/'), 'blocked by Chrome');
  assert.ok(!served('known-phish.example'));
  for (const url of ['https://known-phish-news.example/', 'https://other-news.example/lottery']) assert.strictEqual(await typeAddress(context, url), 'loaded', url);
});

restartTest('a browser restart keeps the settings, the rules, the page scripts, and lookups', async () => {
  const extension = copyExtension(true);
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-scam-restart-'));
  const first = await launch({ extension, profile, keep: true });
  await first.toWorker({ type: 'SET_SETTINGS', settings: { textSize: 'largest', speechRate: 0.7 } });
  await first.toWorker({ type: 'UPDATE_THREAT_RULES', add: [{ type: 'domain', value: 'kept-after-restart.example', source: 'test', trusted: true }] });
  await first.close();

  const second = await launch({ extension, profile });
  try {
    const { settings } = await second.toWorker({ type: 'GET_SETTINGS' });
    assert.deepStrictEqual([settings.textSize, settings.speechRate, settings.protectionEnabled], ['largest', 0.7, true]);
    assert.strictEqual(await typeAddress(second.context, 'https://kept-after-restart.example/'), 'blocked');
    assert.strictEqual(await typeAddress(second.context, 'https://known-phish.example/'), 'blocked');
    assert.strictEqual((await second.toWorker({ type: 'LOOKUP_URL', url: 'https://kept-after-restart.example/' }, {})).status, 'match');
    const page = await openFakeSignIn(second.context, second.base);
    assert.ok(await readWarning(page), 'page scripts not running after the restart');
    assert.strictEqual(await warningSize(page), '34.8px');
    await page.close();
  } finally {
    await second.close();
  }
});

test('a pop-up at the end of a LONG page is noticed (the scanner reads the whole page, newest text last)', async ({ context, base }) => {
  const page = await context.newPage();
  await page.goto(base + 'popup.html?long');
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 8000 });
  await page.close();
});

// Same link, same words: the old guard.js adapter and the contract give one explanation.
test('the warning\'s words come from the analyzer, whichever adapter asked', async () => {
  const viaGuard = analyzeLink({ text: 'www.chase.com', href: 'https://chase-secure.example/verify' }, { pageUrl: 'https://news.example/' });
  const viaContract = analyze({ source: 'link', pageUrl: 'https://news.example/', pageTitle: '', visibleText: '', links: [{ text: 'www.chase.com', url: 'https://chase-secure.example/verify' }], forms: [], context: {} });
  assert.deepStrictEqual(viaGuard.reasons, viaContract.reasons.map(r => r.explanation));
});

// ---------- run ----------

(async () => {
  let failed = 0;
  let total = 0;
  const runGroup = async (title, list, options) => {
    if (!list.length) return;
    console.log(`\n--- ${title} ---`);
    const env = options ? await launch(options) : {};
    for (const t of list) {
      if (process.env.TEST_FILTER && !t.name.includes(process.env.TEST_FILTER)) continue; // run just the tests whose name contains this text
      total++;
      try {
        await t.fn(env);
        console.log(`PASS  ${t.name}`);
      } catch (err) {
        failed++;
        console.log(`FAIL  ${t.name}: ${err.message.split('\n')[0]}`);
      }
    }
    if (options) await env.close();
  };
  await runGroup('with website access (as after the welcome page)', groups.access, { access: true });
  await runGroup('fresh install, no website access yet', groups.fresh, { access: false });
  await runGroup('browser restart', groups.restart, null);
  console.log(failed ? `\n${failed} test(s) failed` : `\nAll ${total} acceptance tests passed`);
  process.exit(failed ? 1 : 0);
})();
