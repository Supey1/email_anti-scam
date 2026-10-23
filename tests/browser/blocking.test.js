// Real-browser tests for what happens before and around the page scripts:
//   - known dangerous websites are blocked by Chrome itself, however you get there
//   - a fresh install (no website access yet): the welcome page, no page scripts, blocking still on
//   - a browser restart keeps the person's choices, the rules, and the page scripts
// Run with:  node tests/browser/blocking.test.js
// Needs Playwright (npm i playwright). Made-up .example addresses only: never real dangerous links.
//
// (The click guard, warning page, ads, Gmail, and settings are in the other tests in this folder.)

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { launch } = require('./harness');

const WARNING = /\/ui\/warning\.html\?kind=dnr/;

// Types an address into the address bar (well, navigates straight to it) and says what happened.
async function typeAddress(context, url) {
  const page = await context.newPage();
  let error = '';
  await page.goto(url).catch(e => { error = e.message; });
  await page.waitForTimeout(300);
  const where = WARNING.test(page.url()) ? 'blocked'
    : /ERR_BLOCKED_BY_CLIENT/.test(error) ? 'blocked by Chrome'
      : page.url() === url ? 'loaded' : `other: ${page.url()} ${error}`;
  const text = where === 'blocked' ? await page.evaluate(() => document.body.innerText.replace(/\s+/g, ' ')) : '';
  await page.close();
  return { where, text };
}

const card = page => page.evaluate(() => {
  const host = document.getElementById('email-anti-scam-warning');
  return host ? host.shadowRoot.textContent.replace(/\s+/g, ' ') : null;
});
const openFakeLogin = async env => {
  const page = await env.context.newPage();
  await page.goto(env.secure + 'fake-login.html');
  await page.waitForTimeout(1500);
  return page;
};

const groups = [];
const group = (title, options, tests) => groups.push({ title, options, tests });

group('with website access', {}, [
  ['a typed known dangerous address goes to OUR warning page: DANGER, the website named, no way through', async env => {
    for (const url of ['https://known-phish.example/', 'https://login.known-phish.example/x']) {
      const { where, text } = await typeAddress(env.context, url);
      assert.strictEqual(where, 'blocked', url);
      assert.match(text, /DANGER/);
      assert.match(text, /known-phish\.example/);
      assert.doesNotMatch(text, /Continue anyway|I understand the risk/);
    }
    assert.ok(!env.served('known-phish.example'), 'the dangerous website was loaded');
  }],
  ['addresses that only look like listed ones load normally', async env => {
    for (const url of ['https://known-phish-news.example/', 'https://other-news.example/lottery']) {
      assert.strictEqual((await typeAddress(env.context, url)).where, 'loaded', url);
    }
  }],
]);

group('fresh install, no website access yet', { withAccess: false }, [
  ['the welcome page opens by itself and says websites aren\'t checked yet', async env => {
    let welcome = null;
    for (let i = 0; !welcome && i < 30; i++) {
      welcome = env.context.pages().find(p => /options\.html\?welcome=1/.test(p.url()));
      if (!welcome) await new Promise(r => setTimeout(r, 100));
    }
    assert.ok(welcome, 'no welcome page');
    await welcome.waitForFunction(() => !/Checking/.test(document.getElementById('access-status').textContent));
    assert.strictEqual(await welcome.isVisible('#welcome'), true);
    assert.match(await welcome.textContent('#access-status'), /Not checking websites yet/);
    assert.strictEqual(await welcome.getAttribute('#access-none', 'aria-pressed'), 'true');
    assert.match(await welcome.textContent('#permissions'), /Block content on any page/);
  }],
  ['no website access means no page scripts at all', async env => {
    assert.deepStrictEqual(await env.worker.evaluate(() => chrome.scripting.getRegisteredContentScripts()), []);
    const page = await openFakeLogin(env);
    assert.strictEqual(await card(page), null);
    await page.close();
  }],
  ['known dangerous websites are STILL blocked (by Chrome itself), normal ones load', async env => {
    assert.strictEqual((await typeAddress(env.context, 'https://known-phish.example/')).where, 'blocked by Chrome');
    assert.ok(!env.served('known-phish.example'), 'the dangerous website was loaded');
    assert.strictEqual((await typeAddress(env.context, 'https://other-news.example/lottery')).where, 'loaded');
  }],
]);

async function restartTest() {
  const name = 'a browser restart keeps the person\'s choices, the rules, and the page scripts';
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'anti-scam-restart-'));
  let first = null;
  let second = null;
  let extension = null;
  try {
    first = await launch({ profile, keep: true });
    extension = first.extension;
    await first.worker.evaluate(async () => {
      const { settings = {} } = await chrome.storage.local.get('settings');
      await chrome.storage.local.set({ settings: { ...settings, textSize: 'xlarge' } });
      await GranblockBackground.instance.handleMessage(
        { schemaVersion: 1, type: 'UPDATE_THREAT_RULES', add: [{ type: 'domain', value: 'kept-after-restart.example', source: 'test', trusted: true }] },
        { url: chrome.runtime.getURL('ui/options.html') });
    });
    await first.close();
    first = null;

    second = await launch({ profile, extension }); // the same extension copy: the same extension id
    const textSize = await second.worker.evaluate(async () => (await chrome.storage.local.get('settings')).settings.textSize);
    assert.strictEqual(textSize, 'xlarge');
    assert.strictEqual((await typeAddress(second.context, 'https://kept-after-restart.example/')).where, 'blocked');
    assert.strictEqual((await typeAddress(second.context, 'https://known-phish.example/')).where, 'blocked');
    const page = await openFakeLogin(second);
    assert.ok(await card(page), 'page scripts not running after the restart');
    await page.close();
    console.log(`PASS  ${name}`);
    return true;
  } catch (err) {
    console.log(`FAIL  ${name}: ${err.message.split('\n')[0]}`);
    return false;
  } finally {
    if (first) await first.close();
    if (second) await second.close();
    fs.rmSync(profile, { recursive: true, force: true });
    if (extension) fs.rmSync(extension, { recursive: true, force: true });
  }
}

(async () => {
  let failed = 0;
  for (const g of groups) {
    console.log(`\n--- ${g.title} ---`);
    const env = await launch(g.options);
    for (const [name, fn] of g.tests) {
      try { await fn(env); console.log(`PASS  ${name}`); } catch (err) { failed++; console.log(`FAIL  ${name}: ${err.message.split('\n')[0]}`); }
    }
    await env.close();
  }
  console.log('\n--- browser restart ---');
  if (!await restartTest()) failed++;
  console.log(failed ? `\n${failed} test(s) failed` : '\nAll tests passed');
  process.exit(failed ? 1 : 0);
})();
