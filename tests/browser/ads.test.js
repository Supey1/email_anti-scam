// Advertisement support matrix, in real Chromium with the real extension.
// Run with:  node tests/browser/ads.test.js
// Each test is one row of docs/ad-support-matrix.md, using tests/pages/ads.html.
// We never hide, remove, or block advertisements. When someone clicks a link inside an ad, the words around the
// link (the rest of the ad) go to the engine as context.nearbyText, and the engine decides. Ads are not scored separately.

const assert = require('assert');
const path = require('path');
const { launch, run } = require('./harness');

const WARNING = /\/blocked\.html/;
const EXT = path.join(__dirname, '..', '..', 'extension', 'content');
const tests = [];
const test = (name, fn) => tests.push({ name, fn });

async function open({ context, secure }) {
  const page = await context.newPage();
  await page.goto(secure + 'ads.html');
  await page.waitForTimeout(2500); // the ad inserted after 1.5 s has arrived
  return page;
}

// ---------- what is recognized as an ad (so its words can travel with a click) ----------

test('matrix: supported ad patterns are recognized, with the reason', async env => {
  const page = await open(env);
  await page.addScriptTag({ path: path.join(EXT, 'ad-signals.js') });
  const found = await page.evaluate(() => Object.fromEntries(AdSignals.find([document.documentElement]).map(c => [c.id || c.querySelector('a')?.id, AdSignals.describe(c).signals.join(' ')])));
  const expect = {
    A1: /class:ad-slot/, A2: /attribute:data-ad-slot/, 'A3': /rel:sponsored/, A4: /label:Advertisement/, A5: /label:Sponsored/,
    A6: /class:advert/, A8: /class:ad-slot/, B1: /class:ad-slot/, B2: /attribute:data-ad-slot/, B3: /label:Advertisement/,
  };
  for (const [id, why] of Object.entries(expect)) {
    assert.ok(id in found, `not recognized as an ad: ${id} (found: ${Object.keys(found)})`);
    assert.match(found[id], why, id);
  }
  await page.close();
});

test('matrix: unsupported patterns are not claimed (unmarked ads, ads in shadow DOM)', async env => {
  const page = await open(env);
  await page.addScriptTag({ path: path.join(EXT, 'ad-signals.js') });
  const ids = await page.evaluate(() => AdSignals.find([document.documentElement]).map(c => c.id));
  assert.ok(!ids.includes('C2'), 'an ad with no marker cannot be recognized');
  assert.ok(!ids.includes('C3-host'), 'shadow DOM is not entered');
  await page.close();
});

test('the whole ad is the words around the link, not just the link', async env => {
  const page = await open(env);
  await page.addScriptTag({ path: path.join(EXT, 'ad-signals.js') });
  const near = await page.evaluate(() => AdSignals.contextFor(document.getElementById('A1-link')).text);
  assert.ok(near.includes('You have won a $2,000 gift card') && near.includes('Claim reward'));
  // A link whose own id looks like an ad marker must still give the whole ad, not just the link.
  const fake = await page.evaluate(() => { const d = document.createElement('div'); d.className = 'ad-slot'; d.innerHTML = '<p>Big prize words here</p><a id="ad-weird-link" href="https://x.example/">Go</a>'; document.body.append(d); return AdSignals.contextFor(document.getElementById('ad-weird-link')).text; });
  assert.ok(fake.includes('Big prize words here'));
  await page.close();
});

// ---------- clicks ----------

// The engine decides which ad clicks to interrupt: a prize with pressure, from an unverified site, does.
for (const id of ['A1-link', 'A4-link', 'A5-link', 'A8-link']) {
  test(`${id}: a prize advertisement click is stopped before navigation`, async env => {
    const page = await open(env);
    await page.click(`#${id}`);
    await page.waitForURL(WARNING);
    assert.ok(!env.reached('claim-gift.example'), 'the browser asked for the suspicious site');
    await page.close();
  });
}

test('A7: a click inside an ad frame is stopped too (the click guard runs in frames)', async env => {
  const page = await open(env);
  await page.frameLocator('#A7').locator('a').click();
  await page.waitForURL(WARNING);
  assert.ok(!env.reached('claim-gift.example'));
  await page.close();
});

test('a click inside a frame made with srcdoc is stopped too', async env => {
  const page = await open(env);
  await page.frameLocator('#A7-srcdoc').locator('a').click();
  await page.waitForURL(WARNING);
  assert.ok(!env.reached('claim-gift.example'));
  await page.close();
});

test('weak signs in an ad (no pressure, hidden destination) are not interrupted: the engine decides', async env => {
  for (const [id, host] of [['A2-link', 'claim-gift.example'], ['A6-link', 'other-site.example']]) {
    const page = await open(env);
    await page.click(`#${id}`);
    await page.waitForURL(new RegExp(host.replace('.', '\\.')));
    await page.close();
  }
});

for (const id of ['B1-link', 'B2-link', 'B3-link', 'B4-link']) {
  test(`${id}: an ordinary ad is left alone; the ad stays and its link works`, async env => {
    const page = await open(env);
    const adId = id.replace('-link', '');
    assert.ok(await page.locator(`#${adId}`).isVisible(), 'the ad must not be hidden or removed');
    await page.click(`#${id}`);
    await page.waitForURL(/\.example\//);
    assert.match(await page.evaluate(() => document.body.innerText), /Destination reached/);
    await page.close();
  });
}

test('C1: a cross-origin ad frame is left alone and stays in place', async env => {
  const page = await open(env);
  assert.ok(await page.locator('#C1').isVisible());
  await page.close();
});

test('C4: an image-only ad has no words to judge; its link works unless the address itself is a problem', async env => {
  const page = await open(env);
  await page.click('#C4-link');
  await page.waitForURL(/claim-gift\.example\/c4/);
  await page.close();
});

(async () => { await run(tests, await launch()); })();
