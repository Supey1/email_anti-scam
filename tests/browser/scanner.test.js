// Browser tests for extension/content/page-scanner.js, run in real Chromium with Playwright.
// Run with:  node tests/browser/scanner.test.js
// Needs Playwright (npm i playwright). Uses the Chromium that Playwright finds, or CHROMIUM_PATH.
// The addresses are made-up ".example" domains and are never contacted.

const assert = require('assert');
const path = require('path');
let chromium;
try { ({ chromium } = require('playwright')); } catch (e) { console.log('SKIP  Playwright is not installed (npm i playwright)'); process.exit(0); }

const SCANNER = path.join(__dirname, '..', '..', 'extension', 'content', 'page-scanner.js');
const URL = 'http://scanner.test/page';

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

// Loads `html`, installs the scanner, and collects every evidence object it emits.
async function open(browser, html, limits = { debounceMs: 100 }) {
  const page = await browser.newPage();
  await page.route('http://scanner.test/**', route => route.fulfill({ contentType: 'text/html', body: html }));
  await page.goto(URL);
  await page.addScriptTag({ path: SCANNER });
  await page.evaluate(limits => {
    window.__evidence = [];
    window.__scanner = PageScanner.start({ limits, onEvidence: e => window.__evidence.push(e) });
  }, limits);
  return page;
}
const evidence = page => page.evaluate(() => window.__evidence);
const wait = (page, ms) => page.waitForTimeout(ms);

test('initial scan collects url, title, text, links, and form metadata', async browser => {
  const page = await open(browser, `<title>Win big</title><body>
    <p>Claim your reward now</p>
    <a href="https://claim.example/go"> Claim   reward </a>
    <a href="/local">Local page</a>
    <a href="#top">Jump</a>
    <a href="mailto:a@b.example">Mail</a>
    <form action="https://collect.example/post" method="POST"><input type="password"><input name="who"></form>`);
  const [e] = await evidence(page);
  assert.strictEqual(e.source, 'webpage');
  assert.strictEqual(e.pageUrl, URL);
  assert.strictEqual(e.pageTitle, 'Win big');
  assert.ok(e.visibleText.includes('Claim your reward now'));
  assert.deepStrictEqual(e.links, [
    { text: 'Claim reward', url: 'https://claim.example/go' },
    { text: 'Local page', url: 'http://scanner.test/local' },
  ], 'other-site links first; fragment and mailto links left out');
  assert.deepStrictEqual(e.forms, [{ action: 'https://collect.example/post', method: 'post', fieldCount: 2, hasPassword: true, hasPayment: false }]);
  assert.strictEqual(e.context.scan, 'initial');
  await page.close();
});

test('never collects typed or sensitive values', async browser => {
  const page = await browser.newPage();
  await page.route('http://scanner.test/**', route => route.fulfill({ contentType: 'text/html', body: `<body>
    <input id="pw" type="password"><input id="t" type="text"><input id="c" autocomplete="cc-number">
    <textarea id="ta">TEXTAREA-SECRET</textarea><div contenteditable>EDITABLE-SECRET</div>
    <select><option>OPTION-SECRET</option></select><p>visible text</p>` }));
  await page.goto(URL);
  await page.evaluate(() => {
    for (const id of ['pw', 't', 'c']) document.getElementById(id).value = 'TYPED-SECRET';
  });
  await page.addScriptTag({ path: SCANNER });
  await page.evaluate(() => { window.__evidence = []; PageScanner.start({ onEvidence: e => window.__evidence.push(e) }); });
  const json = JSON.stringify(await evidence(page));
  assert.ok(!/SECRET/.test(json), 'a secret value was collected');
  assert.ok(json.includes('visible text'));
  const [e] = await evidence(page);
  assert.strictEqual(e.forms[0].hasPassword, true);
  assert.strictEqual(e.forms[0].hasPayment, true);
  await page.close();
});

test('skips hidden text and our own warning card', async browser => {
  const page = await open(browser, `<body><p>shown</p><p style="display:none">HIDDEN-TEXT</p>
    <div style="visibility:hidden">INVISIBLE-TEXT</div><script>var x = 'SCRIPT-TEXT'</script>
    <div id="email-anti-scam-warning">OWN-CARD</div>`);
  const text = (await evidence(page))[0].visibleText;
  assert.ok(text.includes('shown'));
  for (const bad of ['HIDDEN-TEXT', 'INVISIBLE-TEXT', 'SCRIPT-TEXT', 'OWN-CARD']) assert.ok(!text.includes(bad), `${bad} was collected`);
  await page.close();
});

test('limits text and links on huge pages', async browser => {
  const links = Array.from({ length: 5000 }, (_, i) => `<a href="https://site${i}.example/">link ${i}</a>`).join('');
  const page = await open(browser, `<body><p>${'word '.repeat(50000)}</p>${links}`, { debounceMs: 100 });
  const [e] = await evidence(page);
  assert.ok(e.visibleText.length <= 20000, `text was ${e.visibleText.length}`);
  assert.strictEqual(e.links.length, 100);
  assert.strictEqual(e.context.truncated.text, true);
  assert.strictEqual(e.context.truncated.links, true);
  await page.close();
});

test('dynamic scan reports only new content and does not repeat it', async browser => {
  const page = await open(browser, `<body><p>original text</p><a href="https://old.example/">old</a><div id="slot"></div>`);
  await page.evaluate(() => {
    document.getElementById('slot').innerHTML = '<div class="ad"><p>Congratulations winner</p><a href="https://ad.example/win">Claim prize</a></div>';
  });
  await wait(page, 400);
  let all = await evidence(page);
  assert.strictEqual(all.length, 2);
  assert.strictEqual(all[1].context.scan, 'dynamic');
  assert.deepStrictEqual(all[1].links, [{ text: 'Claim prize', url: 'https://ad.example/win' }]);
  assert.ok(all[1].visibleText.includes('Congratulations winner') && !all[1].visibleText.includes('original text'));

  // The same ad is swapped in again: nothing new, so nothing is sent.
  await page.evaluate(() => {
    document.getElementById('slot').innerHTML = '<div class="ad"><p>Congratulations winner</p><a href="https://ad.example/win">Claim prize</a></div>';
  });
  await wait(page, 400);
  assert.strictEqual((await evidence(page)).length, 2, 'repeat content was scanned again');
  await page.close();
});

test('many quick changes cause one scan, not one per change', async browser => {
  const page = await open(browser, `<body><div id="slot"></div>`, { debounceMs: 300 });
  await page.evaluate(() => {
    for (let i = 0; i < 100; i++) {
      const p = document.createElement('p');
      p.textContent = `ad number ${i}`;
      document.getElementById('slot').append(p);
    }
  });
  await wait(page, 700);
  const all = await evidence(page);
  assert.strictEqual(all.length, 2, `expected initial + 1 dynamic scan, got ${all.length}`);
  assert.ok(all[1].visibleText.includes('ad number 99'));
  await page.close();
});

test('changed link destinations are noticed, and changes to our own card are ignored', async browser => {
  const page = await open(browser, `<body><a id="a" href="https://good.example/">Offer</a>`);
  await page.evaluate(() => {
    document.getElementById('a').href = 'https://other.example/';
    const own = document.createElement('div'); own.id = 'email-anti-scam-warning'; own.textContent = 'warning card text';
    document.body.append(own);
  });
  await wait(page, 400);
  const all = await evidence(page);
  assert.strictEqual(all.length, 2);
  assert.deepStrictEqual(all[1].links, [{ text: 'Offer', url: 'https://other.example/' }]);
  assert.ok(!JSON.stringify(all[1]).includes('warning card text'));
  await page.close();
});

test('stop() ends scanning', async browser => {
  const page = await open(browser, `<body><div id="slot"></div>`);
  await page.evaluate(() => { window.__scanner.stop(); document.getElementById('slot').textContent = 'late ad'; });
  await wait(page, 400);
  assert.strictEqual((await evidence(page)).length, 1);
  await page.close();
});

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || undefined, args: ['--no-sandbox'] });
  let failed = 0;
  for (const t of tests) {
    try { await t.fn(browser); console.log(`PASS  ${t.name}`); }
    catch (err) { failed++; console.log(`FAIL  ${t.name}: ${err.message}`); }
  }
  await browser.close();
  console.log(failed ? `\n${failed} test(s) failed` : '\nAll tests passed');
  process.exit(failed ? 1 : 0);
})();
