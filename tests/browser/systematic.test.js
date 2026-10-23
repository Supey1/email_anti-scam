// Systematic behavior tests in real Chromium with the real extension, one group per test page.
// Run with:  node tests/browser/systematic.test.js
// The LIMITS group asserts what the extension does NOT stop, so nobody claims more than is true.

const assert = require('assert');
const path = require('path');
const { launch, run } = require('./harness');
const { validateInput } = require('../contract.js');
const { analyze } = require('../../extension/rules.js');

const EXT = path.join(__dirname, '..', '..', 'extension');
const WARNING = /\/blocked\.html/;
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

// Runs the page scanner inside the page and returns the first evidence it produces. The evidence must follow the
// contract, and the engine's answer for it is computed here in Node with the real engine: the same two steps the
// extension does (scanner, then analyze), checked across the boundary.
async function evidenceOf(page) {
  await page.addScriptTag({ path: path.join(EXT, 'content', 'page-scanner.js') });
  const evidence = await page.evaluate(() => new Promise(resolve => { const s = PageScanner.start({ onEvidence: e => { resolve(e); s.stop(); } }); }));
  assert.deepStrictEqual(validateInput(evidence), [], 'scanner output breaks the contract');
  return evidence;
}
const engineSays = e => { const r = analyze(e); return { verdict: r.verdict, action: r.recommendedAction, codes: r.reasons.map(x => x.code) }; };

// ======================= fake-webpage.html: generic extraction and warnings =======================

test('webpage: extraction keeps visible text and real link destinations, and skips hidden or typed content', async env => {
  const page = await open(env, 'fake-webpage.html');
  const e = await evidenceOf(page);
  assert.ok(e.visibleText.includes('your yearly summary is ready'));
  const json = JSON.stringify(e);
  for (const secret of ['HIDDEN-SECRET-TEXT', 'TYPED-USER-SECRET', 'TYPED-PASSWORD-SECRET', 'TEXTAREA-SECRET']) assert.ok(!json.includes(secret), `${secret} was collected`);
  const mismatch = e.links.find(l => l.url === 'https://other-site.example/summary');
  assert.strictEqual(mismatch.text, 'www.mybank.example/summary', 'the displayed text and the real destination are both kept');
  assert.ok(e.links.some(l => /fake-legitimate\.html$/.test(l.url)));
  assert.ok(!e.links.some(l => /^mailto:|#visible$/.test(l.url)), 'fragment and mailto links are not destinations');
  assert.deepStrictEqual(e.forms.map(f => [f.action, f.hasPassword, f.hasPaymentField]), [['https://collect-login.example/post', true, false]]);
  assert.deepStrictEqual(e.context.mainHeadings, ['Account Notice']);
  await page.close();
});

test('webpage: a lone password form to another site is only a weak warning: the engine says "verify", so no page card covers the page', async env => {
  for (const plainHttp of [false, true]) {
    const page = await open(env, 'fake-webpage.html', 1800, plainHttp);
    const said = engineSays(await evidenceOf(page));
    assert.strictEqual(said.verdict, 'warn');
    assert.strictEqual(said.action, 'VERIFY_INDEPENDENTLY', `plainHttp=${plainHttp}: ${JSON.stringify(said)}`);
    assert.ok(said.codes.includes('CREDENTIALS_SENT_ELSEWHERE'));
    assert.strictEqual(await card(page), null, 'a weak warning must not cover the page');
    await page.close();
  }
});

test('webpage: a link made to look like PayPal is stopped; a hidden destination alone, fragment and same-site links are not', async env => {
  const page = await open(env, 'fake-webpage.html');
  await page.click('#lookalike');
  await page.waitForURL(WARNING);
  assert.ok(!env.reached('paypa1-secure.example'));
  const body = await text(page);
  assert.match(body, /You clicked a link that says: \u201cLog in to PayPal\u201d/);
  assert.match(body, /It really goes to: paypa1-secure\.example/);
  await page.goBack();
  await page.waitForURL(/fake-webpage\.html/);
  await page.click('#fragment');
  await page.click('#mismatch');
  await page.waitForURL(/other-site\.example\/summary/);
  assert.ok(!WARNING.test(page.url()), 'a hidden destination alone is a weak warning and does not stop the click');
  await page.close();
});

// ======================= fake-ad.html: promotional text and suspicious destinations =======================

test('ads: a prize advertisement makes the page warn; ordinary ads stay in place, unnamed, and their links work', async env => {
  const page = await open(env, 'fake-ad.html', 3500);
  const c = await card(page);
  assert.ok(c, 'no warning card');
  assert.match(c, /prize/i);
  for (const name of ['garden-store', 'books.example', 'shoes']) assert.ok(!c.includes(name), `${name} was reported`);
  for (const id of ['ad-prize', 'ad-sale', 'ad-book', 'ad-tracked', 'ad-late']) assert.ok(await page.locator(`#${id}`).isVisible(), `${id} must stay on the page`);
  await page.evaluate(() => document.getElementById('email-anti-scam-warning')?.remove());
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

test('ads: an ordinary ad that goes through an ad tracker is a weak warning only: its click is not interrupted', async env => {
  const page = await open(env, 'fake-ad.html', 600);
  await page.evaluate(() => document.getElementById('email-anti-scam-warning')?.remove());
  await page.click('#ad-tracked-link');
  await page.waitForURL(/ad\.doubleclick\.net\/click/, { timeout: 8000 });
  assert.ok(!WARNING.test(page.url()));
  await page.close();
});

// ======================= fake-redirect.html: redirects and click interception =======================

test('redirects: a redirect wrapper around a look-alike, a plain look-alike, and a known-dangerous link are all stopped', async env => {
  for (const [id, host] of [['wrapped-bad', 'paypa1-secure.example'], ['direct-bad', 'paypa1-secure.example'], ['known-bad', 'known-phish.example']]) {
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
  assert.strictEqual(await page.getByRole('button', { name: /continue/i }).count(), 0);
  await page.close();
});

// ======================= fake-form.html: form destinations =======================

test('forms: metadata is right and no typed value is collected', async env => {
  const page = await open(env, 'fake-form.html', 1500);
  const e = await evidenceOf(page);
  assert.ok(!JSON.stringify(e).includes('LOOSE-SECRET'));
  const own = e.forms.find(f => /\/login$/.test(f.action));
  const search = e.forms.find(f => /search\.example/.test(f.action));
  const pay = e.forms.find(f => /pay-now\.example/.test(f.action));
  const loose = e.forms.find(f => f.action === page.url());
  assert.ok(own.hasPassword && !own.hasPaymentField);
  assert.strictEqual(search, undefined, 'a search form is not sensitive, so it is not reported at all');
  assert.ok(pay.hasPaymentField);
  assert.ok(loose && loose.hasPassword, 'a password box outside any form is still noticed');
  await page.close();
});

test('forms: what the engine makes of those forms, over https and over plain http', async env => {
  const secure = await open(env, 'fake-form.html', 1200);
  const s = engineSays(await evidenceOf(secure));
  assert.ok(s.codes.includes('CREDENTIALS_SENT_ELSEWHERE'), JSON.stringify(s));
  assert.ok(!s.codes.includes('INSECURE_FORM'));
  assert.strictEqual(s.action, 'VERIFY_INDEPENDENTLY', 'a card form that goes to a payment site is weak on its own');
  await secure.close();
  const plain = await open(env, 'fake-form.html', 1200, true);
  const p = engineSays(await evidenceOf(plain));
  assert.ok(p.codes.includes('INSECURE_FORM'), `plain http must add the "no secure connection" sign: ${JSON.stringify(p)}`);
  await plain.close();
});

test('forms: a fake sign-in page that sends the password elsewhere covers the page with "do not type" (fake-login)', async env => {
  const page = await open(env, 'fake-login.html', 1500);
  const c = await card(page);
  assert.match(c, /Do not type anything on this page/);
  assert.match(c, /looks like a PayPal sign-in page/);
  await page.close();
});

// ======================= fake-legitimate.html: false positives =======================

test('legitimate page: scary words one at a time and well-known links cause no warning and stop no link', async env => {
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

test('KNOWN FALSE POSITIVE (engine): an anti-scam newsletter with urgency, a contest winner, and a login is wrongly told "do not type"', async env => {
  const page = await open(env, 'fake-legitimate-advice.html', 1800);
  const c = await card(page);
  assert.ok(c && /Do not type anything on this page/.test(c), 'documented false positive: when the engine is fixed this page should show no card; flip this test');
  await page.close();
});

test('dynamic: a look-alike link added to the page after it loaded is stopped', async env => {
  const page = await open(env, 'fake-webpage.html');
  await page.evaluate(() => {
    const a = document.createElement('a');
    a.id = 'late'; a.href = 'https://paypa1-secure.example/late'; a.textContent = 'Log in to PayPal';
    document.body.append(a);
  });
  await page.click('#late');
  await page.waitForURL(WARNING);
  assert.ok(!env.reached('paypa1-secure.example'));
  await page.close();
});

test('frames: a click on a risky link inside an ad frame is stopped, and the warning opens for the whole tab', async env => {
  for (const frame of ['#same-origin', '#srcdoc']) {
    const page = await open(env, 'fake-iframes.html', 1500);
    await page.frameLocator(frame).locator('#frame-link').click();
    await page.waitForURL(WARNING);
    assert.ok(!env.reached('claim-gift.example'), `${frame}: the destination was requested`);
    await page.close();
  }
});

test('frames: a cross-origin frame is not read by the page scanner (its words never reach the evidence)', async env => {
  const page = await open(env, 'fake-iframes.html', 1500);
  const e = await evidenceOf(page);
  assert.ok(!e.visibleText.includes('Destination reached'), 'the cross-origin frame content must not appear in the page text');
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
