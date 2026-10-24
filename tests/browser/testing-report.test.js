// Tests for the bugs the team found while testing (the second testing report), in real Chromium with the real extension.
// Run with:  node tests/browser/testing-report.test.js
//   1. the settings page stays at the Large size; only the sample line changes; "Extra Large" is capitalized
//   2. "Read warnings out loud on their own" really tries to read (no click needed), and at the chosen speed
//   3. slow, normal, and fast are far enough apart to hear
//   4. warnings with reasons show on ordinary websites, not only in Gmail
//   5. the selected website-access choice is marked with a check mark
//   6. the Gmail "Safety check" button can be moved by pressing on it and dragging

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { launch, run } = require('./harness');

const FAKE_GMAIL = fs.readFileSync(path.join(__dirname, '..', 'fake-gmail.html'), 'utf8')
  .replace(/<!-- standalone:start -->[\s\S]*?<!-- standalone:end -->/, '');
const tests = [];
const test = (name, fn) => tests.push({ name, fn });

const setSettings = (env, partial) => env.worker.evaluate(p => Settings.save(p), partial);
const resetSettings = env => env.worker.evaluate(() => Settings.reset());
const openOptions = async env => {
  const page = await env.context.newPage();
  await page.goto(`chrome-extension://${env.extensionId}/ui/options.html`);
  await page.waitForTimeout(500);
  return page;
};
const readCard = page => page.evaluate(() => {
  const host = document.getElementById('email-anti-scam-warning');
  if (!host) return null;
  const root = host.shadowRoot;
  const reasonText = li => [...li.childNodes].filter(n => n.nodeName !== 'STRONG').map(n => n.textContent).join('');
  return {
    label: root.querySelector('.label').textContent,
    headline: root.querySelector('h1').textContent,
    reasons: [...root.querySelectorAll('.section > ul > li')].map(reasonText),
    modal: !!root.querySelector('.backdrop'),
    readButton: [...root.querySelectorAll('button')].map(b => b.textContent).find(t => /Read to me|Stop reading|aloud/.test(t)),
    focusedInsideCard: root.activeElement !== null,
  };
});

// Every test starts from the default settings.
const wrap = fn => async env => { await resetSettings(env); await new Promise(r => setTimeout(r, 300)); return fn(env); };

// ---------- 1. text size on the settings page ----------

test('settings page: its own text stays Large whatever size is chosen; only the sample line changes', wrap(async env => {
  const page = await openOptions(env);
  const sizes = {};
  for (const [label, key] of [['Normal', 'normal'], ['Extra Large', 'xlarge'], ['Large (recommended)', 'large']]) {
    await page.getByLabel(label).check();
    await page.waitForTimeout(300);
    sizes[key] = await page.evaluate(() => ({ page: getComputedStyle(document.body).fontSize, rootSize: document.documentElement.style.fontSize, sample: getComputedStyle(document.getElementById('size-sample')).fontSize }));
  }
  for (const key of Object.keys(sizes)) assert.strictEqual(sizes[key].rootSize, '24px', `page text changed at ${key}`);
  assert.deepStrictEqual([sizes.normal.sample, sizes.large.sample, sizes.xlarge.sample], ['20px', '24px', '28px']);
  assert.strictEqual(await page.getByLabel('Extra Large').count(), 1);
  assert.match((await page.locator('label', { hasText: 'Extra' }).innerText()).trim(), /^Extra Large$/);
  await page.close();
}));

// ---------- 2 and 3. reading aloud ----------

test('"Read warnings out loud on their own" starts reading by itself, using Chrome\'s speech and the chosen speed', wrap(async env => {
  await env.context.addInitScript(() => {
    if (location.protocol !== 'chrome-extension:' || !window.chrome || !chrome.tts) return;
    window.__asked = [];
    const speak = chrome.tts.speak.bind(chrome.tts);
    chrome.tts.speak = (text, options, callback) => { window.__asked.push({ text, rate: options && options.rate }); return speak(text, options, callback); };
  });
  await setSettings(env, { readAloud: 'auto', speechSpeed: 'fast' });
  const page = await env.context.newPage();
  await page.goto(env.base + 'click-guard.html');
  await page.waitForTimeout(600);
  await page.click('#bad');
  await page.waitForURL(/\/ui\/warning\.html/);
  await page.waitForTimeout(700);
  const asked = await page.evaluate(() => window.__asked);
  assert.strictEqual(asked.length, 1, JSON.stringify(asked));
  assert.match(asked[0].text, /Stop and check this first/);
  assert.strictEqual(asked[0].rate, 1.5);
  await page.close();
}));

test('on the page itself (the in-page card), automatic reading also starts without a click', wrap(async env => {
  await setSettings(env, { readAloud: 'auto' });
  const page = await env.context.newPage();
  await page.goto(env.secure + 'fake-login.html');
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 6000 });
  // No voice in the test browser, so it can't actually speak: the button must have moved on from "Read to me",
  // which only happens if reading was really attempted. (Before the fix it never was.)
  await page.waitForFunction(() => {
    const t = [...document.getElementById('email-anti-scam-warning').shadowRoot.querySelectorAll('button')].map(b => b.textContent).join('|');
    return !/Read to me/.test(t);
  }, null, { timeout: 6000 });
  const card = await readCard(page);
  assert.match(card.readButton, /Couldn't read aloud|Stop reading/);
  await page.close();
}));

test('with "button" (the default) nothing reads until the button is pressed', wrap(async env => {
  const page = await env.context.newPage();
  await page.goto(env.secure + 'fake-login.html');
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 6000 });
  await page.waitForTimeout(1500);
  assert.match((await readCard(page)).readButton, /Read to me/);
  await page.close();
}));

test('the three speeds are far apart, and the settings page and "Test the voice" use them', wrap(async env => {
  const rates = await env.worker.evaluate(() => Settings.SPEECH_RATE);
  assert.ok(rates.fast / rates.normal >= 1.5 && rates.normal / rates.slow >= 1.5, JSON.stringify(rates));
  const page = await openOptions(env);
  await page.evaluate(() => { window.__asked = []; });
  const heard = [];
  for (const choice of ['slow', 'normal', 'fast']) {
    await page.selectOption('#speechSpeed', choice);
    await page.waitForTimeout(250);
    await page.getByRole('button', { name: /Test the voice/ }).click();
    await page.waitForTimeout(250);
    heard.push((await page.evaluate(() => window.__asked)).pop().rate);
  }
  assert.deepStrictEqual(heard, [rates.slow, rates.normal, rates.fast], JSON.stringify({ heard, rates }));
  await page.close();
}));

// ---------- 4. warnings with reasons on ordinary websites ----------

test('ordinary websites show a card with reasons, not only Gmail: a gentle one for weak signs, a stop for strong ones', wrap(async env => {
  const weak = await env.context.newPage();
  await weak.goto(env.secure + 'fake-webpage.html');
  await weak.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 6000 });
  const gentle = await readCard(weak);
  assert.strictEqual(gentle.label, 'BE CAREFUL');
  assert.ok(gentle.reasons.length >= 1 && gentle.reasons.every(r => r.length > 10), 'the reasons are listed');
  assert.ok(!gentle.modal, 'a weak warning does not cover the page');
  await weak.close();

  const strong = await env.context.newPage();
  await strong.goto(env.secure + 'fake-login.html');
  await strong.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 6000 });
  const stop = await readCard(strong);
  assert.strictEqual(stop.label, 'CAUTION');
  assert.ok(stop.reasons.length >= 1);
  await strong.close();

  const calm = await env.context.newPage();
  await calm.goto(env.secure + 'fake-legitimate.html');
  await calm.waitForTimeout(2500);
  assert.strictEqual(await readCard(calm), null, 'an ordinary page shows nothing');
  await calm.close();
}));

// ---------- 5. website access: which one is selected ----------

test('website access: the selected choice has a check mark and the others do not', wrap(async env => {
  const page = await openOptions(env);
  const marks = await page.evaluate(() => Object.fromEntries(['all', 'gmail', 'none'].map(c => { const b = document.getElementById(`access-${c}`); return [c, { text: b.textContent, pressed: b.getAttribute('aria-pressed'), selected: b.classList.contains('selected') }]; })));
  assert.deepStrictEqual([marks.all.pressed, marks.gmail.pressed, marks.none.pressed], ['true', 'false', 'false']);
  assert.match(marks.all.text, /^✓ Check all websites and Gmail/);
  assert.ok(marks.all.selected);
  assert.ok(!/✓/.test(marks.gmail.text) && !/✓/.test(marks.none.text));
  assert.ok(!marks.gmail.selected && !marks.none.selected);
  await page.close();
}));

test('website access with none given: the "don\'t check" choice gets the check mark instead', async () => {
  const env = await launch({ withAccess: false });
  try {
    const page = await openOptions(env);
    const text = await page.evaluate(() => ['all', 'gmail', 'none'].map(c => document.getElementById(`access-${c}`).textContent));
    assert.ok(/^✓ Don't check websites/.test(text[2]) && !/✓/.test(text[0]) && !/✓/.test(text[1]), text.join(' | '));
  } finally { await env.close(); }
});

// ---------- 6. the movable Safety check button ----------

async function openFakeGmailWithChip(env) {
  const page = await env.context.newPage();
  await page.route('https://mail.google.com/**', route => route.fulfill({ contentType: 'text/html', body: FAKE_GMAIL }));
  await page.goto('https://mail.google.com/mail/u/0/');
  await page.waitForTimeout(600);
  await page.click('#buttons button:has-text("Normal email")');
  await page.waitForTimeout(900);
  await page.evaluate(() => [...document.getElementById('email-anti-scam-warning').shadowRoot.querySelectorAll('button')].find(b => b.textContent === 'Got it').click());
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-chip'));
  return page;
}
const chipBox = page => page.evaluate(() => { const r = document.getElementById('email-anti-scam-chip').shadowRoot.querySelector('button').getBoundingClientRect(); return { x: r.left, y: r.top, w: r.width, h: r.height }; });
const panelOpen = page => page.evaluate(() => !!document.getElementById('email-anti-scam-warning'));

test('Gmail: pressing on the Safety check button and dragging moves it, without opening the panel', wrap(async env => {
  await env.worker.evaluate(() => chrome.storage.local.remove('chipPosition'));
  const page = await openFakeGmailWithChip(env);
  const before = await chipBox(page);
  // Press near its top-left corner, drag left and down, let go.
  await page.mouse.move(before.x + 6, before.y + 6);
  await page.mouse.down();
  await page.mouse.move(before.x - 120, before.y + 150, { steps: 8 });
  await page.mouse.up();
  const after = await chipBox(page);
  assert.ok(Math.abs(after.x - (before.x - 126)) < 4 && Math.abs(after.y - (before.y + 144)) < 4, `moved from ${JSON.stringify(before)} to ${JSON.stringify(after)}`);
  assert.strictEqual(await panelOpen(page), false, 'dragging must not open the panel');
  await page.close();
}));

test('Gmail: a plain click on the Safety check button still opens the panel', wrap(async env => {
  await env.worker.evaluate(() => chrome.storage.local.remove('chipPosition'));
  const page = await openFakeGmailWithChip(env);
  const box = await chipBox(page);
  await page.mouse.click(box.x + box.w / 2, box.y + box.h / 2);
  await page.waitForTimeout(400);
  assert.strictEqual(await panelOpen(page), true);
  await page.close();
}));

test('Gmail: the chosen place is remembered, and the button cannot be dragged off the screen', wrap(async env => {
  await env.worker.evaluate(() => chrome.storage.local.remove('chipPosition'));
  let page = await openFakeGmailWithChip(env);
  const before = await chipBox(page);
  await page.mouse.move(before.x + 6, before.y + 6);
  await page.mouse.down();
  await page.mouse.move(before.x - 200, before.y + 120, { steps: 6 });
  await page.mouse.up();
  const moved = await chipBox(page);
  await page.close();

  page = await openFakeGmailWithChip(env);
  const again = await chipBox(page);
  assert.ok(Math.abs(again.x - moved.x) < 4 && Math.abs(again.y - moved.y) < 4, `not remembered: ${JSON.stringify(moved)} then ${JSON.stringify(again)}`);

  await page.mouse.move(again.x + 6, again.y + 6);
  await page.mouse.down();
  await page.mouse.move(-500, -500, { steps: 6 });
  await page.mouse.up();
  const clamped = await chipBox(page);
  assert.ok(clamped.x >= 0 && clamped.y >= 0, `off the screen: ${JSON.stringify(clamped)}`);
  await env.worker.evaluate(() => chrome.storage.local.remove('chipPosition'));
  await page.close();
}));

(async () => { await run(tests, await launch()); })();
