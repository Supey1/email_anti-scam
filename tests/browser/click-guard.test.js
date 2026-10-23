// Real-browser tests for pre-click protection (Phase 2) and the warning interface (Phase 3).
// Run with:  node tests/browser/click-guard.test.js
// Each "stopped" test checks that the ORIGINAL NAVIGATION NEVER HAPPENED: the browser never
// requested the destination, not just that a warning appeared.

const assert = require('assert');
const { launch, run } = require('./harness');

const WARNING = /\/ui\/warning\.html/;
const tests = [];
const test = (name, fn) => tests.push({ name, fn });

const open = async ({ context, base }, file = 'click-guard.html') => {
  const page = await context.newPage();
  await page.goto(base + file);
  await page.waitForFunction(() => !!document.getElementById('shadow-host') || true);
  await page.waitForTimeout(300); // let the content scripts finish starting
  return page;
};
const text = page => page.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));

// ---------- Phase 2: stopping the click ----------

test('suspicious link: navigation is cancelled and a useful warning is shown', async env => {
  const page = await open(env);
  await page.click('#bad');
  await page.waitForURL(WARNING);
  assert.ok(!env.reached('other-site.example'), 'the browser still asked for the suspicious site');
  const body = await text(page);
  assert.match(body, /Stop and check this first/);
  assert.match(body, /says it goes to mybank\.example, but it really goes to other-site\.example/);
  assert.ok(await page.locator('text=I understand the risk').count(), 'warn should offer a way to continue');
  await page.close();
});

test('Go back to safety returns to the original page', async env => {
  const page = await open(env);
  await page.click('#bad');
  await page.waitForURL(WARNING);
  await page.click('text=Go back to safety');
  await page.waitForURL(/click-guard\.html/);
  assert.ok(!env.reached('other-site.example'));
  await page.close();
});

test('legitimate link still works normally', async env => {
  const page = await open(env);
  await page.click('#fine');
  await page.waitForURL(/recipes\.example\/soup/);
  assert.match(await text(page), /Destination reached/);
  await page.close();
});

test('suspicious target=_blank link: warning opens in a new tab, no request, original page stays', async env => {
  const page = await open(env);
  const [popup] = await Promise.all([env.context.waitForEvent('page'), page.click('#bad-blank')]);
  await popup.waitForURL(WARNING);
  assert.ok(!env.reached('other-site.example'));
  assert.match(page.url(), /click-guard\.html/);
  await popup.close();
  await page.close();
});

test('Go back in a warning tab closes that tab', async env => {
  const page = await open(env);
  const [popup] = await Promise.all([env.context.waitForEvent('page'), page.click('#bad-blank')]);
  await popup.waitForURL(WARNING);
  await Promise.all([popup.waitForEvent('close'), popup.click('text=Go back to safety')]);
  await page.close();
});

test('Ctrl-click, Shift-click, and middle-click are stopped too', async env => {
  const page = await open(env);
  for (const options of [{ modifiers: ['Control'] }, { modifiers: ['Shift'] }, { button: 'middle' }]) {
    const [popup] = await Promise.all([env.context.waitForEvent('page'), page.click('#bad', options)]);
    await popup.waitForURL(WARNING);
    await popup.close();
  }
  assert.ok(!env.reached('other-site.example'));
  assert.match(page.url(), /click-guard\.html/);
  await page.close();
});

test('keyboard: Enter on a focused suspicious link is stopped', async env => {
  const page = await open(env);
  await page.focus('#bad');
  await page.keyboard.press('Enter');
  await page.waitForURL(WARNING);
  assert.ok(!env.reached('other-site.example'));
  await page.close();
});

test('unusual links are stopped: nested element, SVG, shadow DOM, odd attributes', async env => {
  for (const selector of ['#nested-inner', '#svg', '#shadow-link', '#unusual']) {
    const page = await open(env);
    await page.click(selector);
    await page.waitForURL(WARNING, { timeout: 5000 }).catch(() => { throw new Error(`${selector} was not stopped`); });
    await page.close();
  }
  assert.ok(!env.reached('other-site.example'));
});

test("the page's own click handler does not run for a stopped link", async env => {
  const page = await open(env);
  await page.click('#onclick-pass');
  await page.waitForURL(WARNING);
  assert.ok(!env.reached('other-site.example'));
  await page.close();
});

test('known dangerous link: stopped, shown as DANGER, with no way to continue', async env => {
  const page = await open(env);
  await page.click('#known');
  await page.waitForURL(WARNING);
  assert.ok(!env.reached('known-phish.example'), 'the browser still asked for the dangerous site');
  const body = await text(page);
  assert.match(body, /DANGER/);
  assert.match(body, /Stop\. This is dangerous\./);
  assert.strictEqual(await page.locator('text=Continue anyway').count(), 0);
  assert.strictEqual(await page.locator('text=I understand the risk').count(), 0);
  await page.close();
});

test('Continue (warn only) goes on to the destination after the warning', async env => {
  const page = await open(env);
  await page.click('#bad');
  await page.waitForURL(WARNING);
  await page.click('text=I understand the risk');
  await page.waitForURL(/other-site\.example\/x/);
  assert.match(await text(page), /Destination reached/);
  await page.close();
});

test('a "block" cannot be continued even if the warning page is asked to', async env => {
  const page = await open(env);
  await page.click('#known');
  await page.waitForURL(WARNING);
  const reply = await page.evaluate(() => chrome.runtime.sendMessage({ type: 'CONTINUE', url: 'https://known-phish.example/login', text: '' }));
  assert.strictEqual(reply.ok, false);
  assert.match(page.url(), WARNING);
  await page.close();
});

test('normal behavior is not broken: new tab, same site, page anchor, mailto, page scripts', async env => {
  const page = await open(env);
  const [popup] = await Promise.all([env.context.waitForEvent('page'), page.click('#fine-blank')]);
  await popup.waitForURL(/recipes\.example\/blank/);
  await popup.close();

  await page.click('#hash');
  assert.match(page.url(), /#fine$/);
  await page.click('#mail').catch(() => {});
  assert.match(page.url(), /click-guard\.html#fine/, 'mailto must not navigate the page or show a warning');

  await page.click('#fine-js');
  await page.waitForURL(/recipes\.example\/js/);
  await page.goBack();
  await page.waitForURL(/click-guard\.html/);
  await page.click('#same');
  await page.waitForURL(/legit-shop\.html/);
  await page.close();
});

test('KNOWN LIMIT (documented): navigation done by the page\'s own script is not intercepted', async env => {
  const page = await open(env);
  await page.click('#bad-js');
  await page.waitForURL(/other-site\.example\/js/);
  await page.close();
});

// ---------- Phase 3: the warning interface ----------

test('a local fake webpage is analyzed automatically and shows the expected card', async env => {
  const page = await open(env, 'fake-login.html');
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 5000 });
  const card = await page.evaluate(() => {
    const root = document.getElementById('email-anti-scam-warning').shadowRoot;
    const c = root.querySelector('.card');
    return {
      role: c.getAttribute('role'),
      label: root.querySelector('.label').textContent,
      headline: root.querySelector('h1').textContent,
      reasons: root.querySelectorAll('ul > li').length,
      topReasons: root.querySelectorAll('.section > ul > li').length,
      hasMore: !!root.querySelector('details.more'),
      primary: root.querySelector('.primary').textContent,
      hasRead: [...root.querySelectorAll('button')].some(b => /Read to me/.test(b.textContent)),
      hasReport: [...root.querySelectorAll('button')].some(b => /false alarm/.test(b.textContent)),
      live: !!root.querySelector('[aria-live]'),
    };
  });
  assert.strictEqual(card.role, 'alertdialog');
  assert.strictEqual(card.label, 'CAUTION');
  assert.strictEqual(card.headline, 'Stop and check this first');
  assert.ok(card.topReasons >= 1 && card.topReasons <= 3, `shows ${card.topReasons} top reasons`);
  assert.ok(card.hasMore, 'extra reasons should be behind "Show more"');
  assert.strictEqual(card.primary, 'Go back to safety');
  assert.ok(card.hasRead && card.hasReport && card.live);
  await page.close();
});

test('false-alarm report is saved locally with no page content', async env => {
  const page = await open(env, 'fake-login.html');
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 5000 });
  await page.evaluate(() => [...document.getElementById('email-anti-scam-warning').shadowRoot.querySelectorAll('button')].find(b => /false alarm/.test(b.textContent)).click());
  const worker = env.context.serviceWorkers()[0];
  await page.waitForTimeout(500);
  const { falseAlarms } = await worker.evaluate(() => chrome.storage.local.get('falseAlarms'));
  assert.ok(falseAlarms && falseAlarms.length >= 1);
  const last = falseAlarms[falseAlarms.length - 1];
  assert.deepStrictEqual(Object.keys(last).sort(), ['at', 'host', 'reasons', 'source', 'verdict']);
  assert.strictEqual(last.host, 'localhost');
  await page.close();
});

test('suspicious link on the fake page gets the correct intervention', async env => {
  const page = await open(env, 'fake-login.html');
  await page.click('#verify');
  await page.waitForURL(WARNING);
  assert.ok(!env.reached('paypa1-secure.example'));
  assert.match(await text(page), /pretends to be PayPal/);
  await page.close();
});

test('warning page: focus starts on the safe action, Tab stays in the card, Escape-free keyboard use works', async env => {
  const page = await open(env);
  await page.click('#bad');
  await page.waitForURL(WARNING);
  assert.strictEqual(await page.evaluate(() => document.activeElement.textContent), 'Go back to safety');
  const seen = new Set();
  for (let i = 0; i < 8; i++) { await page.keyboard.press('Tab'); seen.add(await page.evaluate(() => document.activeElement.textContent)); }
  assert.ok(seen.has('Go back to safety') && seen.has('🔊 Read to me'), `Tab visited: ${[...seen]}`);
  assert.ok([...seen].every(t => t), 'focus should always be on a labelled control');
  const outline = await page.evaluate(() => { document.querySelector('.primary').focus(); return getComputedStyle(document.activeElement).outlineStyle; });
  assert.notStrictEqual(outline, 'none', 'focus must be visible');
  assert.strictEqual(await page.evaluate(() => document.querySelector('[role=alertdialog]').getAttribute('aria-labelledby')), 'warning-headline');
  await page.close();
});

test('warning page: severity is shown by icon and word, not colour alone', async env => {
  const page = await open(env);
  await page.click('#known');
  await page.waitForURL(WARNING);
  const verdict = await page.evaluate(() => document.querySelector('.verdict').innerText.replace(/\s+/g, ' '));
  assert.match(verdict, /🛑/);
  assert.match(verdict, /DANGER/);
  await page.close();
});


(async () => { await run(tests, await launch()); })();
