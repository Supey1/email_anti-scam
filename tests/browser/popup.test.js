// The toolbar popup, in real Chromium with the real extension (website access granted, as after the welcome page).
// Run with:  node tests/browser/popup.test.js
const assert = require('assert');
const { launch, run } = require('./harness');

const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const tabIdFor = (env, page) => env.worker.evaluate(url => chrome.tabs.query({}).then(tabs => (tabs.find(t => t.url === url) || {}).id), page.url());

async function openPage(env, file) {
  const page = await env.context.newPage();
  await page.goto(env.secure + file);
  await page.waitForTimeout(700);
  return page;
}
async function openPopup(env, page) {
  const popup = await env.context.newPage();
  await popup.goto(`chrome-extension://${env.extensionId}/ui/popup.html${page ? `?tab=${await tabIdFor(env, page)}` : ''}`);
  await popup.waitForTimeout(600);
  return popup;
}
const words = popup => popup.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
const setProtection = (env, on) => env.worker.evaluate(on => GranblockBackground.instance.handleMessage({ schemaVersion: 1, type: 'SET_SETTINGS', settings: { protectionEnabled: on } }, { url: chrome.runtime.getURL('settings.html') }), on);

test('popup answers: protection is on, this page is being checked, and help is available', async env => {
  const page = await openPage(env, 'click-guard.html');
  const popup = await openPopup(env, page);
  const text = await words(popup);
  assert.match(text, /Is protection on\?\s*✅?\s*Yes, protection is on/);
  assert.match(text, /Is this page being checked\?\s*✅?\s*Yes, this page is being checked/);
  assert.match(text, /Need help\?/);
  assert.match(text, /Call someone you trust/);
  for (const name of ['Turn protection off', 'Hear this advice', 'Check this page again', 'Settings']) assert.ok(await popup.getByRole('button', { name }).isVisible(), name);
  await popup.close(); await page.close();
});

test('popup on a page Chrome does not allow: says so instead of claiming protection', async env => {
  const page = await env.context.newPage();
  await page.goto('about:blank');
  const popup = await openPopup(env, page);
  assert.match(await words(popup), /This page cannot be checked/);
  await popup.close(); await page.close();
});

test('turning protection off from the popup really stops warnings, blocking, and click guarding; turning it on brings them back', async env => {
  const page = await openPage(env, 'fake-login.html');
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 5000 });
  const popup = await openPopup(env, page);
  await popup.getByRole('button', { name: 'Turn protection off' }).click();
  await popup.waitForTimeout(1200);
  assert.match(await words(popup), /No, protection is off/);
  assert.match(await words(popup), /No, this page is not being checked/);

  const fresh = await openPage(env, 'fake-login.html');
  await fresh.waitForTimeout(2000);
  assert.ok(!(await fresh.evaluate(() => !!document.getElementById('email-anti-scam-warning'))), 'a new page is not checked');
  await fresh.click('#verify');
  await fresh.waitForURL(/paypa1-secure\.example/);
  assert.ok(!/blocked\.html/.test(fresh.url()), 'the risky link was not stopped while protection is off');
  assert.deepStrictEqual(await env.worker.evaluate(() => chrome.declarativeNetRequest.getDynamicRules().then(r => r.length)), 0, 'Chrome blocking rules are removed');

  await popup.getByRole('button', { name: 'Turn protection on' }).click();
  await popup.waitForTimeout(1200);
  assert.match(await words(popup), /Yes, protection is on/);
  const again = await openPage(env, 'fake-login.html');
  await again.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 5000 });
  assert.ok((await env.worker.evaluate(() => chrome.declarativeNetRequest.getDynamicRules().then(r => r.length))) > 0, 'blocking rules are back');
  for (const p of [popup, page, fresh, again]) await p.close();
});

test('"Check this page again" brings a hidden warning back', async env => {
  const page = await openPage(env, 'fake-login.html');
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 5000 });
  await page.evaluate(() => [...document.getElementById('email-anti-scam-warning').shadowRoot.querySelectorAll('button')].find(b => b.textContent === 'Hide').click());
  assert.ok(!(await page.evaluate(() => !!document.getElementById('email-anti-scam-warning'))));
  const popup = await openPopup(env, page);
  await popup.getByRole('button', { name: 'Check this page again' }).click();
  await popup.waitForTimeout(600);
  assert.match(await words(popup), /Checked again/);
  assert.ok(await page.evaluate(() => !!document.getElementById('email-anti-scam-warning')), 'the warning should be back');
  await popup.close(); await page.close();
});

test('Gmail: the popup says emails are being checked', async env => {
  const page = await env.context.newPage();
  await page.route('https://mail.google.com/**', route => route.fulfill({ contentType: 'text/html', body: '<title>Inbox</title><body>inbox</body>' }));
  await page.goto('https://mail.google.com/mail/u/0/');
  await page.waitForTimeout(800);
  const popup = await openPopup(env, page);
  assert.match(await words(popup), /Yes\. Emails you open in Gmail are being checked/);
  await popup.close(); await page.close();
});

test('without website access the popup says why and offers the Settings button', async () => {
  const env = await launch({ access: false });
  try {
    const page = await env.context.newPage();
    await page.goto(env.secure + 'click-guard.html');
    await page.waitForTimeout(800);
    const popup = await openPopup(env, page);
    const text = await words(popup);
    assert.match(text, /No, this website is not being checked/);
    assert.match(text, /not allowed website access yet/);
    assert.ok(await popup.getByRole('button', { name: 'Open Settings' }).first().isVisible());
  } finally { await env.close(); }
});

test('popup text follows the person\'s text size', async env => {
  const popup = await openPopup(env, null);
  const normal = await popup.evaluate(() => getComputedStyle(document.documentElement).fontSize);
  await env.worker.evaluate(() => GranblockBackground.instance.handleMessage({ schemaVersion: 1, type: 'SET_SETTINGS', settings: { textSize: 'largest' } }, { url: chrome.runtime.getURL('settings.html') }));
  await popup.reload(); await popup.waitForTimeout(500);
  const big = await popup.evaluate(() => getComputedStyle(document.documentElement).fontSize);
  assert.ok(parseFloat(big) > parseFloat(normal), `${normal} -> ${big}`);
  await env.worker.evaluate(() => GranblockBackground.instance.handleMessage({ schemaVersion: 1, type: 'SET_SETTINGS', settings: { textSize: 'large' } }, { url: chrome.runtime.getURL('settings.html') }));
  await popup.close();
});

(async () => { await run(tests, await launch()); })();
