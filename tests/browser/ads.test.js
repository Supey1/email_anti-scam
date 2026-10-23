// Advertisement support matrix, in real Chromium with the real extension.
// Run with:  node tests/browser/ads.test.js
// Each test is one row of docs/ad-support-matrix.md, using tests/pages/ads.html.
// We identify suspicious ads. We never hide, remove, or block advertisements.

const assert = require('assert');
const { launch, run } = require('./harness');

const WARNING = /\/ui\/warning\.html/;
const tests = [];
const test = (name, fn) => tests.push({ name, fn });

async function open({ context, base }) {
  const page = await context.newPage();
  await page.goto(base + 'ads.html');
  await page.waitForTimeout(3500); // initial scan, plus the ad that is inserted after 1.5 s
  return page;
}
const card = page => page.evaluate(() => {
  const host = document.getElementById('email-anti-scam-warning');
  return host ? host.shadowRoot.querySelector('.card').innerText.replace(/\s+/g, ' ') : null;
});

// Only the supported SUSPICIOUS ads should have been reported, and the ordinary ones never.
test('page-level: suspicious ads are reported with plain reasons; the page is not called dangerous', async env => {
  const page = await open(env);
  const text = await card(page);
  assert.ok(text, 'no warning card appeared');
  assert.match(text, /CAUTION/);
  assert.doesNotMatch(text, /DANGER/);
  assert.match(text, /claim-gift\.example/);
  await page.close();
});

// Click on each ad: supported suspicious ads are stopped (never requested); ordinary ones work.
const stopped = ['A1-link', 'A2-link', 'A3', 'A4-link', 'A5-link', 'A6-link', 'A8-link'];
for (const id of stopped) {
  test(`${id}: suspicious ad click is stopped before navigation`, async env => {
    const page = await open(env);
    await page.evaluate(() => document.getElementById('email-anti-scam-warning')?.remove());
    await page.click(`#${id}`);
    await page.waitForURL(WARNING);
    assert.ok(!env.reached('claim-gift.example') && !env.reached('other-site.example'), 'the browser asked for the suspicious site');
    await page.close();
  });
}

for (const id of ['B1-link', 'B2-link', 'B3-link', 'B4-link']) {
  test(`${id}: ordinary ad is left alone; the ad stays and its link works`, async env => {
    const page = await open(env);
    const adId = id.replace('-link', '');
    assert.ok(await page.locator(`#${adId}`).isVisible(), 'the ad must not be hidden or removed');
    await page.click(`#${id}`);
    await page.waitForURL(/\.example\//);
    assert.match(await page.evaluate(() => document.body.innerText), /Destination reached/);
    await page.close();
  });
}

test('ordinary ads are never named in the warning', async env => {
  const page = await open(env);
  const text = await card(page);
  for (const word of ['garden-store', 'books.example', 'shoes.example', 'Summer sale']) assert.ok(!text.includes(word), `${word} was reported`);
  await page.close();
});

// Unsupported patterns: documented, and no false claim of coverage.
// ---------- what the scanner identifies as ads (evidence, before any judging) ----------

const path = require('path');
const EXT = path.join(__dirname, '..', '..', 'extension', 'content');

// Runs a fresh scanner (and ad detector) inside the page and returns its first evidence.
async function scanEvidence({ context, base }) {
  const page = await context.newPage();
  await page.goto(base + 'ads.html');
  await page.waitForTimeout(500);
  await page.addScriptTag({ path: path.join(EXT, 'ad-signals.js') });
  await page.addScriptTag({ path: path.join(EXT, 'page-scanner.js') });
  const evidence = await page.evaluate(() => new Promise(resolve => {
    const scanner = PageScanner.start({ onEvidence: e => { resolve(e); scanner.stop(); } });
  }));
  return { page, evidence };
}

test('matrix: supported ad patterns are identified, with why and where they lead', async env => {
  const { page, evidence } = await scanEvidence(env);
  const byUrl = Object.fromEntries(evidence.context.ads.map(a => [a.link && a.link.url, a]));
  const expect = {
    'https://claim-gift.example/a1': /^class:ad-slot/,
    'https://claim-gift.example/a2': /^attribute:data-ad-slot/,
    'https://claim-gift.example/a3': /rel:sponsored/,
    'https://claim-gift.example/a4': /^label:Advertisement/,
    'https://claim-gift.example/a5': /label:Sponsored/,
    'https://other-site.example/a6': /^class:advert/,
    'https://claim-gift.example/a7': /^frame:ad-frame/, // inside the same-origin ad frame
    'https://garden-store.example/sale': /^class:ad-slot/,
    'https://books.example/cookbook': /^attribute:data-ad-slot/,
    'https://shoes.example/new': /label:Advertisement/,
  };
  for (const [url, why] of Object.entries(expect)) {
    assert.ok(byUrl[url], `not identified as an ad: ${url}`);
    assert.match(byUrl[url].signals.join(' '), why, url);
  }
  assert.ok(byUrl['https://claim-gift.example/a1'].text.includes('You have won a $2,000 gift card'));
  assert.strictEqual(byUrl['https://claim-gift.example/a1'].link.text, 'Claim reward');
  assert.strictEqual(byUrl['https://claim-gift.example/a7'].frame, true);
  await page.close();
});

test('matrix: unsupported patterns are not claimed (unmarked, shadow DOM, image-only without a link text)', async env => {
  const { page, evidence } = await scanEvidence(env);
  const urls = evidence.context.ads.map(a => a.link && a.link.url);
  assert.ok(!urls.includes('https://claim-gift.example/c2'), 'unmarked ad cannot be identified');
  assert.ok(!urls.includes('https://claim-gift.example/c3'), 'shadow DOM is not entered');
  await page.close();
});

test('C1: a cross-origin ad frame is counted as unreadable, never guessed at', async env => {
  const { page, evidence } = await scanEvidence(env);
  assert.strictEqual(evidence.context.adFrames.unreadable, 1);
  assert.strictEqual(evidence.context.adFrames.readable, 1);
  assert.ok(await page.locator('#C1').isVisible(), 'the ad frame is left in place');
  await page.close();
});

test('ad text is kept out of the page text, so an ad does not make the whole page look bad', async env => {
  const { page, evidence } = await scanEvidence(env);
  for (const adText of ['$2,000', 'Summer sale', 'cookbook', 'Free $500']) assert.ok(!evidence.visibleText.includes(adText), `ad text leaked into the page text: ${adText}`);
  assert.ok(evidence.visibleText.includes('Advertisement support matrix'), 'normal page text is still collected');
  await page.close();
});

test('C4: an image-only ad has no text to judge; nothing is flagged and the link works', async env => {
  const page = await open(env);
  await page.click('#C4-link');
  await page.waitForURL(/claim-gift\.example\/c4/);
  await page.close();
});

// An ad whose link goes through an ad network: the link itself is the only thing marked as an ad, so its words are
// the box around it. Before the fix only "Reschedule now" reached the engine and the scam was not stopped.
test('ad-network link: a scam ad is stopped by the words around the link, and the ad network is never requested', async env => {
  const page = await env.context.newPage();
  await page.goto(env.secure + 'ad-network-link.html');
  await page.waitForTimeout(1200);
  await page.evaluate(() => document.getElementById('email-anti-scam-warning')?.remove());
  await page.click('#scam-link');
  await page.waitForURL(WARNING);
  assert.ok(!env.reached('www.googleadservices.com'), 'the browser asked for the ad network');
  await page.close();
});

test('ad-network link: an ordinary ad through the same kind of link opens normally', async env => {
  const page = await env.context.newPage();
  await page.goto(env.secure + 'ad-network-link.html');
  await page.waitForTimeout(1200);
  await page.evaluate(() => document.getElementById('email-anti-scam-warning')?.remove());
  await page.click('#fine-link');
  await page.waitForURL(/doubleclick\.net\/click/, { timeout: 8000 });
  assert.ok(!WARNING.test(page.url()));
  await page.close();
});

(async () => { await run(tests, await launch()); })();
