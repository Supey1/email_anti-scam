// Systematic behavior tests in real Chromium with the real extension, one group per test page.
// Run with:  node tests/browser/systematic.test.js
// The LIMITS group asserts what the extension does NOT stop, so nobody claims more than is true.

const assert = require('assert');
const path = require('path');
const { launch, run } = require('./harness');

const EXT = path.join(__dirname, '..', '..', 'extension');
const WARNING = /\/ui\/warning\.html/;
const tests = [];
const test = (name, fn) => tests.push({ name, fn });

// Pages are opened over https (https://pages.example/) unless a test asks for plain http.
const open = async ({ context, plain, secure }, file, wait = 600, plainHttp = false) => {
  const page = await context.newPage();
  await page.goto((plainHttp ? plain : secure) + file);
  await page.waitForTimeout(wait);
  return page;
};
const card = page => page.evaluate(() => {
  const h = document.getElementById('email-anti-scam-warning');
  return h ? h.shadowRoot.querySelector('.card').innerText.replace(/\s+/g, ' ') : null;
});
const text = page => page.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
const worker = env => env.context.serviceWorkers()[0];

// Runs the scanner (and ad detector) inside the page and returns the first evidence it produces.
async function evidenceOf(page) {
  await page.addScriptTag({ path: path.join(EXT, 'content', 'ad-signals.js') });
  await page.addScriptTag({ path: path.join(EXT, 'content', 'page-scanner.js') });
  return page.evaluate(() => new Promise(resolve => { const s = PageScanner.start({ onEvidence: e => { resolve(e); s.stop(); } }); }));
}

// ======================= fake-webpage.html: generic extraction and warnings =======================

test('webpage: extraction keeps visible text and real link destinations, and skips hidden or typed content', async env => {
  const page = await open(env, 'fake-webpage.html');
  const e = await evidenceOf(page);
  assert.ok(e.visibleText.includes('your yearly summary is ready'));
  const json = JSON.stringify(e);
  for (const secret of ['HIDDEN-SECRET-TEXT', 'TYPED-USER-SECRET', 'TYPED-PASSWORD-SECRET', 'TEXTAREA-SECRET']) assert.ok(!json.includes(secret), `${secret} was collected`);
  const mismatch = e.links.find(l => l.url === 'https://other-site.example/summary');
  assert.strictEqual(mismatch.text, 'www.chase.com/summary', 'the displayed text and the real destination are both kept');
  assert.ok(e.links.some(l => /fake-legitimate\.html$/.test(l.url)));
  assert.ok(!e.links.some(l => /^mailto:|#visible$/.test(l.url)), 'fragment and mailto links are not destinations');
  assert.deepStrictEqual(e.forms.map(f => [f.action, f.hasPassword, f.hasPayment]), [['https://collect-login.example/post', true, false]]);
  await page.close();
});

test('webpage: a lone password form to another site is ambiguous (single sign-on looks the same): no page warning over https, a warning over plain http', async env => {
  const secure = await open(env, 'fake-webpage.html', 1800);
  assert.strictEqual(await card(secure), null, 'by design, one cross-site password form alone is not enough');
  await secure.close();
  const plain = await open(env, 'fake-webpage.html', 1800, true);
  const c = await card(plain);
  assert.match(c, /CAUTION/);
  assert.match(c, /sent to a different website \(collect-login\.example\)/);
  assert.match(c, /sent without protection/);
  await plain.close();
});

test('webpage: the link whose words name another site is stopped; fragment and same-site links work', async env => {
  const page = await open(env, 'fake-webpage.html');
  await page.click('#mismatch');
  await page.waitForURL(WARNING);
  assert.ok(!env.reached('other-site.example'));
  const body = await text(page);
  assert.match(body, /says it goes to chase\.com, Chase's real website, but it really goes to other-site\.example/);
  await page.goBack();
  await page.waitForURL(/fake-webpage\.html/);
  await page.click('#fragment');
  await page.click('#same');
  await page.waitForURL(/fake-legitimate\.html/);
  await page.close();
});

// ======================= fake-ad.html: promotional text and suspicious destinations =======================

test('ads: only the prize ads are reported; ordinary ads stay in place and their links work', async env => {
  const page = await open(env, 'fake-ad.html', 3500);
  const c = await card(page);
  assert.ok(c, 'no warning card');
  assert.match(c, /claim-gift\.example/);
  for (const name of ['garden-store', 'books.example']) assert.ok(!c.includes(name), `${name} was reported`);
  for (const id of ['ad-prize', 'ad-sale', 'ad-book', 'ad-tracked', 'ad-late']) assert.ok(await page.locator(`#${id}`).isVisible(), `${id} must stay on the page`);
  await page.click('#ad-sale-link');
  await page.waitForURL(/garden-store\.example\/sale/);
  await page.close();
});

test('ads: the prize ad, and an ad inserted later, are stopped before navigation (mouse and keyboard)', async env => {
  const page = await open(env, 'fake-ad.html', 2500);
  await page.evaluate(() => document.getElementById('email-anti-scam-warning')?.remove());
  await page.focus('#ad-late-link');
  await page.keyboard.press('Enter');
  await page.waitForURL(WARNING);
  await page.goBack();
  await page.waitForURL(/fake-ad\.html/);
  await page.waitForTimeout(500);
  await page.evaluate(() => document.getElementById('email-anti-scam-warning')?.remove());
  const [popup] = await Promise.all([env.context.waitForEvent('page'), page.click('#ad-prize-link', { modifiers: ['Control'] })]);
  await popup.waitForURL(WARNING);
  assert.ok(!env.reached('claim-gift.example'));
  await popup.close(); await page.close();
});

test('ads: an ordinary ad that goes through an ad tracker is NOT stopped (this was a known false alarm)', async env => {
  const page = await open(env, 'fake-ad.html', 600);
  await page.route('https://ad.doubleclick.net/**', route => route.fulfill({ contentType: 'text/html', body: '<h1>Destination reached</h1>' }));
  await page.click('#ad-tracked-link');
  await page.waitForURL(/ad\.doubleclick\.net\/click/, { timeout: 8000 });
  assert.ok(!WARNING.test(page.url()));
  await page.close();
});

// ======================= fake-redirect.html: redirects and click interception =======================

test('redirects: a redirect wrapper around a number address, a look-alike, and a known-dangerous link are all stopped', async env => {
  // (A number address or a look-alike ALONE is a "check first" sign that doesn't stop a click; these links also name a bank.)
  for (const [id, host] of [['wrapped-bad', '192.168.4.20'], ['direct-bad', 'paypa1-secure.example'], ['known-bad', 'known-phish.example']]) {
    const page = await open(env, 'fake-redirect.html');
    await page.click(`#${id}`);
    await page.waitForURL(WARNING);
    assert.ok(!env.reached(host), `${host} was requested`);
    await page.close();
  }
});

test('redirects: the backstop: a page that redirects itself to a KNOWN dangerous address is blocked by the browser-level rule', async env => {
  const page = await open(env, 'fake-redirect.html');
  await page.click('#meta-known');
  await page.waitForURL(WARNING, { timeout: 8000 });
  assert.match(await text(page), /DANGER/);
  assert.strictEqual(await page.locator('text=Continue anyway').count(), 0);
  await page.close();
});

// ======================= fake-form.html: form destinations =======================

test('forms: metadata is right, no typed value is collected, and a lone card form to a payment site is not alarming', async env => {
  const page = await open(env, 'fake-form.html', 2500);
  const e = await evidenceOf(page);
  assert.ok(!JSON.stringify(e).includes('LOOSE-SECRET'));
  const byAction = Object.fromEntries(e.forms.map(f => [f.action.replace(/^https?:\/\/[^/]+/, '') || f.action, f]));
  const own = e.forms.find(f => /\/login$/.test(f.action));
  const search = e.forms.find(f => /search\.example/.test(f.action));
  const pay = e.forms.find(f => /pay-now\.example/.test(f.action));
  const loose = e.forms.find(f => f.action === page.url());
  assert.ok(own.hasPassword && !own.hasPayment);
  assert.ok(!search.hasPassword && !search.hasPayment, 'a search form is not sensitive');
  assert.ok(pay.hasPayment);
  assert.ok(loose && loose.hasPassword, 'a password box outside any form is still noticed');
  // Design decision (docs/testing.md): one card form to another site is common (payment providers), so it alone is not a warning.
  assert.strictEqual(await card(page), null);
  await page.close();
});

test('forms: on a plain-http page the same card form IS warned about (no secure connection)', async env => {
  const page = await open(env, 'fake-form.html', 2500, true);
  const c = await card(page);
  assert.match(c, /sent without protection/);
  assert.match(c, /sent to a different website \(pay-now\.example\)/);
  await page.close();
});

test('forms: a password form that sends the password to a different website IS warned about (fake-login)', async env => {
  const page = await open(env, 'fake-login.html', 1500);
  assert.match(await card(page), /sent to a different website \(collect-login\.example\)/);
  await page.close();
});

// ======================= fake-legitimate.html: false positives =======================

test('legitimate page: scary words and well-known links cause no warning card and stop no link', async env => {
  const page = await open(env, 'fake-legitimate.html', 3000);
  assert.strictEqual(await card(page), null, `unexpected warning: ${await card(page)}`);
  for (const [id, pattern] of [['paypal', /paypal\.com\/donate/], ['amazon', /amazon\.com\/wishlist/], ['short', /bit\.ly\/library-events/], ['partner', /county-books\.example/], ['ad', /bakery\.example/]]) {
    await page.click(`#${id}`);
    await page.waitForURL(pattern, { timeout: 8000 });
    assert.ok(!WARNING.test(page.url()), `${id} was stopped`);
    await page.goBack();
    await page.waitForURL(/fake-legitimate\.html/);
  }
  await page.close();
});

// ======================= new tabs, dynamic elements, frames =======================

test('dynamic: a suspicious link added to the page after it loaded is stopped', async env => {
  const page = await open(env, 'fake-webpage.html');
  await page.evaluate(() => {
    const a = document.createElement('a');
    a.id = 'late'; a.href = 'https://other-site.example/late'; a.textContent = 'www.chase.com/late';
    document.body.append(a);
  });
  await page.click('#late');
  await page.waitForURL(WARNING);
  assert.ok(!env.reached('other-site.example'));
  await page.close();
});

test('frames: a same-origin ad frame is read, but a link clicked INSIDE a frame is not intercepted (limit)', async env => {
  const page = await open(env, 'fake-iframes.html', 2500);
  assert.match(await card(page), /claim-gift\.example/, 'the same-origin ad frame was read');
  await page.frameLocator('#same-origin').locator('#frame-link').click();
  await page.waitForTimeout(800);
  assert.ok(env.reached('claim-gift.example'), 'documented limit: clicks inside frames are not guarded');
  await page.close();
});

test('frames: a cross-origin frame cannot be read, and the page is not claimed to be checked inside it (limit)', async env => {
  const page = await open(env, 'fake-iframes.html', 1500);
  const e = await evidenceOf(page);
  assert.strictEqual(e.context.adFrames.unreadable, 1);
  await page.close();
});

// ======================= limits =======================

test('limit: typing a novel malicious address straight into the address bar is NOT stopped; a known one is', async env => {
  const novel = await env.context.newPage();
  await novel.goto('http://novel-bad.example/login');
  assert.ok(!WARNING.test(novel.url()), 'a novel address typed directly is not stopped by the click guard');
  assert.match(await text(novel), /Destination reached/);
  await novel.close();
  const known = await env.context.newPage();
  await known.goto('http://known-phish.example/login').catch(() => {});
  await known.waitForURL(WARNING, { timeout: 8000 });
  await known.close();
});

test('limit: navigation done by the page\'s own script, scripted clicks, self-rewriting links, forms, and unknown redirectors are not stopped', async env => {
  const cases = [
    ['js-location', 'other-site.example'], ['rewrite', 'other-site.example'], ['script-click', 'other-site.example'],
    ['form-get', 'other-site.example'], ['open-redirect', 'redirector.example'], ['meta-page', 'other-site.example'],
  ];
  for (const [id, host] of cases) {
    const page = await open(env, 'fake-redirect.html');
    await page.click(`#${id}`);
    await page.waitForTimeout(1200);
    assert.ok(env.reached(host), `${id}: expected the documented limit (navigation proceeds) but ${host} was never requested`);
    await page.close();
  }
  const popupPage = await open(env, 'fake-redirect.html');
  const [popup] = await Promise.all([env.context.waitForEvent('page'), popupPage.click('#js-open')]);
  await popup.waitForTimeout(800);
  assert.ok(env.reached('other-site.example'));
  await popup.close(); await popupPage.close();
});

// ======================= extension reload / lost connection =======================
// A real extension reload cannot be driven here: in this headless Chromium the extension is removed and not
// loaded again (see docs/testing.md for the manual check). What matters to a person is what an ALREADY-OPEN page does
// once its connection to the extension is gone, where every chrome.runtime call throws "Extension context invalidated".
// This test cuts that connection inside the extension's own script world and checks the page is still protected.

async function cutExtensionConnection(env, page) {
  const cdp = await env.context.newCDPSession(page);
  const worlds = [];
  cdp.on('Runtime.executionContextCreated', e => worlds.push(e.context));
  await cdp.send('Runtime.enable');
  const mine = worlds.find(w => w.auxData && w.auxData.type === 'isolated' && /Anti-Scam/i.test(w.name));
  assert.ok(mine, 'could not find the extension\'s script world');
  await cdp.send('Runtime.evaluate', {
    contextId: mine.id,
    expression: "chrome.runtime.sendMessage = () => { throw new Error('Extension context invalidated.'); }; 'cut'",
  });
}

test('lost connection: an already-open page still cancels a risky click and explains it in-page', async env => {
  const page = await open(env, 'fake-redirect.html');
  await cutExtensionConnection(env, page);
  await page.evaluate(() => document.getElementById('email-anti-scam-warning')?.remove());
  env.requests.length = 0;
  await page.click('#direct-bad');
  await page.waitForTimeout(800);
  const c = await card(page);
  assert.ok(c, 'the in-page card must appear when the extension cannot be reached');
  assert.match(c, /PayPal/);
  assert.ok(!env.reached('paypa1-secure.example'), 'navigation must still be cancelled');
  assert.ok(!WARNING.test(page.url()));
  await page.close();
});

(async () => { await run(tests, await launch()); })();
