// Popup and settings page, in real Chromium with the real extension.
// Run with:  node tests/browser/settings.test.js
// Checks that each choice really changes what the extension does, not just what the page shows.

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { launch, run } = require('./harness');

const ROOT = path.join(__dirname, '..', '..');
const FAKE_GMAIL = fs.readFileSync(path.join(ROOT, 'tests', 'fake-gmail.html'), 'utf8')
  .replace(/<!-- standalone:start -->[\s\S]*?<!-- standalone:end -->/, '');
const WARNING = /\/ui\/warning\.html/;

const tests = [];
const test = (name, fn) => tests.push({ name, fn });
const settle = page => page.waitForTimeout(700); // settings reach every page a moment after they change

async function worker(env) {
  return env.context.serviceWorkers()[0] || env.context.waitForEvent('serviceworker');
}
async function extensionId(env) { return new URL((await worker(env)).url()).host; }
async function setSettings(env, partial) { await (await worker(env)).evaluate(p => Settings.save(p), partial); await env.context.pages()[0]?.waitForTimeout(100); }
async function resetSettings(env) { await (await worker(env)).evaluate(() => Settings.reset()); }
async function getSettings(env) { return (await worker(env)).evaluate(() => Settings.load()); }
async function tabIdFor(env, page) { return (await worker(env)).evaluate(url => chrome.tabs.query({}).then(tabs => (tabs.find(t => t.url === url) || {}).id), page.url()); }

async function openPage(env, file) {
  const page = await env.context.newPage();
  await page.goto(env.base + file);
  await page.waitForTimeout(500);
  return page;
}
async function openPopup(env, page) {
  const popup = await env.context.newPage();
  const tab = page ? await tabIdFor(env, page) : '';
  await popup.goto(`chrome-extension://${await extensionId(env)}/ui/popup.html${tab ? `?tab=${tab}` : ''}`);
  await popup.waitForTimeout(500);
  return popup;
}
const cardOf = page => page.evaluate(() => {
  const host = document.getElementById('email-anti-scam-warning');
  return host ? host.shadowRoot.querySelector('.card').innerText.replace(/\s+/g, ' ') : null;
});
const popupText = popup => popup.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));

// Every test starts from the default settings.
const original = tests.push.bind(tests);
tests.push = (...items) => original(...items.map(t => ({ ...t, fn: async env => { await resetSettings(env); await env.context.pages()[0].waitForTimeout(200); return t.fn(env); } })));

// ---------- popup: three questions ----------

test('popup answers: protection is on, this page is being checked, and help is available', async env => {
  const page = await openPage(env, 'click-guard.html');
  const popup = await openPopup(env, page);
  const text = await popupText(popup);
  assert.match(text, /Is protection on\?\s*✅?\s*Yes, protection is on/);
  assert.match(text, /Is this page being checked\?\s*✅?\s*Yes, this page is being checked/);
  assert.match(text, /Need help\?/);
  assert.match(text, /Call someone you trust/);
  for (const name of ['Turn protection off', 'Turn off for this website', 'Hear this advice', 'Check this page again', 'Settings']) {
    assert.ok(await popup.getByRole('button', { name }).isVisible(), `missing button: ${name}`);
  }
  await popup.close(); await page.close();
});

test('popup on a page Chrome does not allow: says so instead of claiming protection', async env => {
  const page = await env.context.newPage();
  await page.goto('about:blank');
  const popup = await openPopup(env, page);
  assert.match(await popupText(popup), /This page cannot be checked/);
  await popup.close(); await page.close();
});

test('turning protection off from the popup really stops checking, blocking, and click guarding', async env => {
  const page = await openPage(env, 'fake-login.html');
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 5000 });
  const popup = await openPopup(env, page);
  await popup.getByRole('button', { name: 'Turn protection off' }).click();
  await settle(popup);
  assert.match(await popupText(popup), /No, protection is off/);
  assert.match(await popupText(popup), /No, this page is not being checked/);
  assert.strictEqual((await getSettings(env)).enabled, false);

  assert.strictEqual(await cardOf(page), null, 'the open warning card goes away');
  assert.strictEqual(await (await worker(env)).evaluate(() => chrome.action.getBadgeText({})), 'OFF');
  assert.deepStrictEqual(await (await worker(env)).evaluate(() => chrome.declarativeNetRequest.getDynamicRules()), [], 'blocking rules are removed');

  const fresh = await openPage(env, 'fake-login.html');
  await fresh.waitForTimeout(2500);
  assert.strictEqual(await cardOf(fresh), null, 'a new page is not checked');
  await fresh.click('#verify');
  await fresh.waitForURL(/paypa1-secure\.example/);
  assert.ok(!WARNING.test(fresh.url()), 'the suspicious link was not stopped while protection is off');

  await popup.getByRole('button', { name: 'Turn protection on' }).click();
  await settle(popup);
  assert.match(await popupText(popup), /Yes, protection is on/);
  const again = await openPage(env, 'fake-login.html');
  await again.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 5000 });
  assert.strictEqual(await (await worker(env)).evaluate(() => chrome.action.getBadgeText({})), '');
  assert.ok((await (await worker(env)).evaluate(() => chrome.declarativeNetRequest.getDynamicRules())).length > 0, 'blocking rules are back');
  for (const p of [popup, page, fresh, again]) await p.close();
});

test('"Turn off for this website" stops checking that site right away, and can be turned back on', async env => {
  const page = await openPage(env, 'fake-login.html');
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 5000 });
  const popup = await openPopup(env, page);
  await popup.getByRole('button', { name: 'Turn off for this website' }).click();
  await settle(popup);
  assert.deepStrictEqual((await getSettings(env)).offSites, ['localhost']);
  assert.match(await popupText(popup), /No, this website is not being checked/);
  assert.match(await popupText(popup), /turned protection off for this website/);
  assert.strictEqual(await cardOf(page), null);
  await page.click('#verify');
  await page.waitForURL(/paypa1-secure\.example/);
  assert.ok(!WARNING.test(page.url()));

  await popup.getByRole('button', { name: 'Turn on for this website' }).click();
  await settle(popup);
  assert.deepStrictEqual((await getSettings(env)).offSites, []);
  assert.match(await popupText(popup), /Yes, this page is being checked/);
  await popup.close(); await page.close();
});

test('"only websites I choose": nothing is checked until a site is chosen', async env => {
  await setSettings(env, { siteMode: 'chosen' });
  const page = await openPage(env, 'fake-login.html');
  await page.waitForTimeout(2500);
  assert.strictEqual(await cardOf(page), null);
  const popup = await openPopup(env, page);
  assert.match(await popupText(popup), /only some websites/);
  await popup.getByRole('button', { name: 'Check this website' }).click();
  await settle(popup);
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 5000 });
  assert.deepStrictEqual((await getSettings(env)).onSites, ['localhost']);
  await popup.close(); await page.close();
});

test('"Check this page again" brings a hidden warning back', async env => {
  const page = await openPage(env, 'fake-login.html');
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 5000 });
  await page.evaluate(() => [...document.getElementById('email-anti-scam-warning').shadowRoot.querySelectorAll('button')].find(b => b.textContent === 'Hide').click());
  assert.strictEqual(await cardOf(page), null);
  const popup = await openPopup(env, page);
  await popup.getByRole('button', { name: 'Check this page again' }).click();
  await popup.waitForTimeout(500);
  assert.match(await popupText(popup), /Checked again/);
  assert.ok(await cardOf(page), 'the warning should be back');
  await popup.close(); await page.close();
});

// ---------- Gmail ----------

async function openFakeGmail(env) {
  const page = await env.context.newPage();
  await page.route('https://mail.google.com/**', route => route.fulfill({ contentType: 'text/html', body: FAKE_GMAIL }));
  await page.goto('https://mail.google.com/mail/u/0/');
  await page.waitForTimeout(500);
  return page;
}
const gmailPanel = page => page.evaluate(() => !!document.getElementById('email-anti-scam-warning'));

test('Gmail switch: off means emails are not checked and the popup says so; on brings it back', async env => {
  await setSettings(env, { checkEmail: false });
  const page = await openFakeGmail(env);
  await page.click('#buttons button:has-text("Fake PayPal")');
  await page.waitForTimeout(900);
  assert.strictEqual(await gmailPanel(page), false);
  const popup = await openPopup(env, page);
  assert.match(await popupText(popup), /No, Gmail emails are not being checked/);

  await setSettings(env, { checkEmail: true });
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 5000 });
  await popup.reload(); await popup.waitForTimeout(500);
  assert.match(await popupText(popup), /Yes\. Emails you open in Gmail are being checked/);
  await popup.close(); await page.close();
});

// ---------- text size and reading aloud ----------

for (const [size, px] of [['normal', 20], ['large', 24], ['xlarge', 28]]) {
  test(`text size "${size}" makes the warning ${px}px`, async env => {
    await setSettings(env, { textSize: size });
    const page = await openPage(env, 'fake-login.html');
    await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 5000 });
    const fontSize = await page.evaluate(() => getComputedStyle(document.getElementById('email-anti-scam-warning').shadowRoot.querySelector('.card')).fontSize);
    assert.strictEqual(fontSize, `${px}px`);
    await page.close();
  });
}

test('read aloud "off" hides the Read to me button; the default shows it', async env => {
  let page = await openPage(env, 'fake-login.html');
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 5000 });
  const has = p => p.evaluate(() => [...document.getElementById('email-anti-scam-warning').shadowRoot.querySelectorAll('button')].some(b => /Read to me/.test(b.textContent)));
  assert.strictEqual(await has(page), true);
  await page.close();
  await setSettings(env, { readAloud: 'off' });
  page = await openPage(env, 'fake-login.html');
  await page.waitForFunction(() => !!document.getElementById('email-anti-scam-warning'), null, { timeout: 5000 });
  assert.strictEqual(await has(page), false);
  await page.close();
});

// The warning page runs in the page's own world, so the test can watch it speak.
const SPY = () => { window.__spoken = []; const speak = SpeechSynthesis.prototype.speak; SpeechSynthesis.prototype.speak = function (u) { window.__spoken.push({ text: u.text, rate: u.rate }); return speak.call(this, u); }; };

test('read aloud "auto" speaks the warning on its own at the chosen speed; "button" does not', async env => {
  await env.context.addInitScript(SPY);
  await setSettings(env, { readAloud: 'auto', speechSpeed: 'fast' });
  let page = await openPage(env, 'click-guard.html');
  await page.click('#bad');
  await page.waitForURL(WARNING);
  await page.waitForTimeout(400);
  const spoken = await page.evaluate(() => window.__spoken);
  assert.strictEqual(spoken.length, 1, JSON.stringify(spoken));
  assert.match(spoken[0].text, /Stop and check this first/);
  assert.ok(Math.abs(spoken[0].rate - 1.1) < 0.001, `rate was ${spoken[0].rate}`);
  await page.close();

  await setSettings(env, { readAloud: 'button' });
  page = await openPage(env, 'click-guard.html');
  await page.click('#bad');
  await page.waitForURL(WARNING);
  await page.waitForTimeout(400);
  assert.deepStrictEqual(await page.evaluate(() => window.__spoken), []);
  await page.close();
});

// ---------- settings page ----------

async function openOptions(env) {
  const page = await env.context.newPage();
  await page.goto(`chrome-extension://${await extensionId(env)}/ui/options.html`);
  await page.waitForTimeout(400);
  return page;
}

test('settings page: every choice is saved at once and survives a reload', async env => {
  const page = await openOptions(env);
  await page.getByLabel('Protection is on').uncheck();
  await page.getByLabel('Extra large').check();
  await page.getByLabel('Read warnings out loud on their own').check();
  await page.selectOption('#speechSpeed', 'slow');
  await page.getByLabel('Only the websites I choose').check();
  await page.waitForTimeout(300);
  assert.match(await page.textContent('#saved'), /Saved/);
  assert.deepStrictEqual(await getSettings(env), { ...(await getSettings(env)), enabled: false, textSize: 'xlarge', readAloud: 'auto', speechSpeed: 'slow', siteMode: 'chosen' });
  await page.reload();
  await page.waitForTimeout(300);
  assert.strictEqual(await page.getByLabel('Protection is on').isChecked(), false);
  assert.strictEqual(await page.getByLabel('Extra large').isChecked(), true);
  assert.strictEqual(await page.evaluate(() => document.documentElement.style.fontSize), '28px');
  assert.strictEqual(await page.locator('#speechSpeed').inputValue(), 'slow');
  await page.close();
});

test('settings page: websites are added in plain words, bad entries are explained, and entries can be removed', async env => {
  const page = await openOptions(env);
  assert.match(await page.textContent('#sites-empty'), /Every website is being checked/);
  await page.fill('#site-input', 'HTTPS://www.Example.com/some/page?x=1');
  await page.click('#add-site');
  await page.waitForTimeout(300);
  assert.deepStrictEqual((await getSettings(env)).offSites, ['example.com']);
  assert.match(await page.textContent('#sites'), /example\.com/);
  await page.fill('#site-input', 'not a website');
  await page.click('#add-site');
  assert.match(await page.textContent('#site-error'), /does not look like a website name/);
  assert.deepStrictEqual((await getSettings(env)).offSites, ['example.com']);
  await page.getByRole('button', { name: 'Remove example.com' }).click();
  await page.waitForTimeout(300);
  assert.deepStrictEqual((await getSettings(env)).offSites, []);

  await page.getByLabel('Only the websites I choose').check();
  await page.waitForTimeout(300);
  assert.match(await page.textContent('#sites-heading'), /Websites I chose to check/);
  await page.fill('#site-input', 'news.example');
  await page.keyboard.press('Enter');
  await page.waitForTimeout(300);
  assert.deepStrictEqual((await getSettings(env)).onSites, ['news.example']);
  await page.close();
});

test('settings page: explains what is and is not checked, in plain words', async env => {
  const page = await openOptions(env);
  const text = await page.evaluate(() => document.body.innerText.replace(/\s+/g, ' '));
  assert.match(text, /What Email Anti-Scam checks/);
  assert.match(text, /What it cannot check/);
  assert.match(text, /text messages, phone calls/);
  assert.match(text, /does not mean something is safe/);
  assert.match(text, /Nothing you read is sent anywhere/);
  assert.ok(!/risk score|rule weight|json|config/i.test(text), 'no jargon about scores or configuration');
  await page.close();
});

test('settings page: accessible controls (labels, headings, keyboard)', async env => {
  const page = await openOptions(env);
  const unlabeled = await page.evaluate(() => [...document.querySelectorAll('input, select')].filter(i => !i.labels.length && !i.getAttribute('aria-label')).map(i => i.id || i.name));
  assert.deepStrictEqual(unlabeled, []);
  assert.strictEqual(await page.locator('h1').count(), 1);
  assert.ok(await page.locator('[role=status][aria-live=polite]').count() >= 1, 'changes are announced');
  await page.focus('#enabled');
  await page.keyboard.press('Space');
  await page.waitForTimeout(300);
  assert.strictEqual((await getSettings(env)).enabled, false, 'a setting can be changed with the keyboard alone');
  const outline = await page.evaluate(() => { document.getElementById('add-site').focus(); return getComputedStyle(document.activeElement).outlineStyle; });
  assert.notStrictEqual(outline, 'none');
  await page.close();
});

test('settings page: saved false-alarm reports can be counted, saved, and deleted; reset needs two clicks', async env => {
  await (await worker(env)).evaluate(() => chrome.storage.local.set({ falseAlarms: [{ at: 'x', host: 'a.example', verdict: 'warn', source: 'test', reasons: [] }] }));
  const page = await openOptions(env);
  assert.match(await page.textContent('#report-count'), /1 saved report\./);
  const [download] = await Promise.all([page.waitForEvent('download'), page.click('#export-reports')]);
  assert.strictEqual(download.suggestedFilename(), 'false-alarm-reports.json');
  await page.click('#clear-reports');
  await page.waitForTimeout(300);
  assert.match(await page.textContent('#report-count'), /No saved reports/);

  await setSettings(env, { textSize: 'xlarge' });
  await page.click('#reset');
  assert.strictEqual((await getSettings(env)).textSize, 'xlarge', 'one click must not reset');
  await page.click('#reset');
  await page.waitForTimeout(300);
  assert.strictEqual((await getSettings(env)).textSize, 'large');
  await page.close();
});

(async () => { await run(tests, await launch()); })();
