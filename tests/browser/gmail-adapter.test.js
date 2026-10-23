// Gmail adapter tests, in real Chromium. Run with:  node tests/browser/gmail-adapter.test.js
//   1. extraction against Gmail-shaped markup (and markup Gmail might change to)
//   2. the whole extension on tests/fake-gmail.html, served as https://mail.google.com/
// All addresses are made-up ".example" names.

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { launch, run } = require('./harness');

const ROOT = path.join(__dirname, '..', '..');
const ADAPTER = path.join(ROOT, 'extension', 'content', 'gmail-adapter.js');
const FAKE_GMAIL = fs.readFileSync(path.join(ROOT, 'tests', 'fake-gmail.html'), 'utf8')
  .replace(/<!-- standalone:start -->[\s\S]*?<!-- standalone:end -->/, ''); // the extension injects these

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

const MAIL = (inner, subject = 'Hello') => `<body><h2 class="hP">${subject}</h2>${inner}</body>`;

// Loads `html` as Gmail's address, adds the adapter, and returns what readOpenEmail() finds.
async function extract({ context }, html) {
  const page = await context.newPage();
  await page.route('https://mail.google.com/**', route => route.fulfill({ contentType: 'text/html', body: html }));
  await page.goto('https://mail.google.com/mail/u/0/#inbox/FMfcgzSecretMessageId');
  await page.addScriptTag({ path: ADAPTER });
  const found = await page.evaluate(() => ({ evidence: GmailAdapter.readOpenEmail(), diagnosis: GmailAdapter.diagnose() }));
  await page.close();
  return found;
}

test('extracts sender, subject, text, and displayed link text with real destinations', async env => {
  const { evidence: e } = await extract(env, MAIL(`
    <span class="gD" name="PayPal Security" email="alerts@paypa1-secure.xyz">PayPal Security &lt;alerts@paypa1-secure.xyz&gt;</span>
    <div class="a3s"><p>We noticed   unusual activity.</p><a href="http://paypa1-secure.xyz/login">www.paypal.com</a>
      <a href="mailto:x@y.example">mail me</a><a href="https://pics.example/p"><img alt="Photo link"></a></div>`, 'Your account has been suspended'));
  assert.strictEqual(e.source, 'email');
  assert.strictEqual(e.pageTitle, 'Your account has been suspended');
  assert.deepStrictEqual(e.context, { senderName: 'PayPal Security', senderEmail: 'alerts@paypa1-secure.xyz', subject: 'Your account has been suspended' });
  assert.ok(e.visibleText.includes('We noticed unusual activity.'));
  assert.deepStrictEqual(e.links, [
    { text: 'www.paypal.com', url: 'http://paypa1-secure.xyz/login' },
    { text: 'Photo link', url: 'https://pics.example/p' },
  ]);
  assert.deepStrictEqual(e.forms, []);
});

test('drops the message id from the address, for privacy', async env => {
  const { evidence: e } = await extract(env, MAIL('<span class="gD" email="a@b.example">A</span><div class="a3s">Hi</div>'));
  assert.strictEqual(e.pageUrl, 'https://mail.google.com/mail/u/0/');
  assert.ok(!JSON.stringify(e).includes('FMfcgzSecretMessageId'));
});

test('uses the newest message in a thread and ignores hidden ones', async env => {
  const { evidence: e } = await extract(env, MAIL(`
    <span class="gD" email="old@b.example" name="Old">Old</span><div class="a3s">first message</div>
    <span class="gD" email="new@b.example" name="New">New</span><div class="a3s">second message</div>
    <div style="display:none"><span class="gD" email="hidden@b.example">H</span><div class="a3s">hidden message</div></div>`));
  assert.strictEqual(e.context.senderEmail, 'new@b.example');
  assert.strictEqual(e.visibleText, 'second message');
});

test('never reads the compose box, search box, or typed text', async env => {
  const { evidence: e } = await extract(env, MAIL(`
    <input id="search" value="TYPED-SEARCH"><div class="Am" contenteditable="true">DRAFT-SECRET</div><textarea>TEXTAREA-SECRET</textarea>
    <span class="gD" email="a@b.example">A</span><div class="a3s">only this</div>`));
  assert.ok(!/SECRET|TYPED/.test(JSON.stringify(e)));
  assert.strictEqual(e.visibleText, 'only this');
});

test('no email open: returns null instead of guessing', async env => {
  const { evidence, diagnosis } = await extract(env, '<body><div class="inbox-row">An inbox row</div></body>');
  assert.strictEqual(evidence, null);
  assert.deepStrictEqual(diagnosis, { subject: 0, sender: 0, body: 0 });
});

test('if Gmail renames its markup, extraction fails cleanly and diagnose() shows which parts broke', async env => {
  const { evidence, diagnosis } = await extract(env, '<body><h2 class="newSubject">Hi</h2><span class="newSender" email="a@b.example">A</span><div class="newBody">text</div></body>');
  assert.strictEqual(evidence, null);
  assert.deepStrictEqual(diagnosis, { subject: 0, sender: 0, body: 0 });
});

test('if only the sender selector breaks, the email is still checked (without a sender)', async env => {
  const { evidence: e, diagnosis } = await extract(env, MAIL('<span class="renamed" email="a@b.example">A</span><div class="a3s">Buy gift cards now</div>'));
  assert.strictEqual(diagnosis.sender, 0);
  assert.strictEqual(e.context.senderEmail, '');
  assert.ok(e.visibleText.includes('gift cards'));
});

// ---------- the whole extension on the fake Gmail page ----------

async function openFakeGmail({ context }) {
  const page = await context.newPage();
  await page.route('https://mail.google.com/**', route => route.fulfill({ contentType: 'text/html', body: FAKE_GMAIL }));
  await page.goto('https://mail.google.com/mail/u/0/');
  await page.waitForTimeout(400);
  return page;
}
const panel = page => page.evaluate(() => {
  const host = document.getElementById('email-anti-scam-warning');
  if (!host) return null;
  const root = host.shadowRoot;
  return { label: root.querySelector('.label').textContent, headline: root.querySelector('h1').textContent, text: root.querySelector('.card').innerText.replace(/\s+/g, ' ') };
});
async function pick(page, label) {
  await page.click(`#buttons button:has-text("${label}")`);
  await page.waitForTimeout(900);
  return panel(page);
}

test('fake Gmail: scam emails get DANGER, a borderline email gets CAUTION, a normal email gets no warning signs', async env => {
  const page = await openFakeGmail(env);
  assert.strictEqual(await panel(page), null, 'nothing shows before an email is opened');
  assert.strictEqual((await pick(page, 'Fake PayPal')).label, 'DANGER');
  assert.strictEqual((await pick(page, 'Grandparent scam')).label, 'DANGER');
  const shipping = await pick(page, 'Shipping');
  assert.strictEqual(shipping.label, 'CAUTION');
  const normal = await pick(page, 'Normal email');
  assert.strictEqual(normal.label, 'NO WARNING SIGNS');
  assert.ok(!/safe/i.test(normal.headline), 'headline must not claim the email is safe');
  assert.match(normal.text, /does not prove it is safe/);
  await page.close();
});

test('fake Gmail: the panel explains why, shows the sender, and where links really go', async env => {
  const page = await openFakeGmail(env);
  const p = await pick(page, 'Fake PayPal');
  assert.match(p.text, /Why we stopped you/);
  assert.match(p.text, /paypa1-secure\.xyz/);
  assert.match(p.text, /Really goes to: paypa1-secure\.xyz/);
  assert.match(p.text, /Who sent this PayPal Security/);
  assert.match(p.text, /Do not click any links in this email/);
  await page.close();
});

test('fake Gmail: a hidden-destination link is stopped by the click guard, and the email stays open', async env => {
  const page = await openFakeGmail(env);
  await pick(page, 'Fake bank');
  await page.evaluate(() => document.getElementById('email-anti-scam-warning').remove());
  const [popup] = await Promise.all([env.context.waitForEvent('page'), page.click('div.a3s a')]);
  await popup.waitForURL(/\/ui\/warning\.html/);
  assert.ok(!env.reached('secure-review.example'));
  assert.match(page.url(), /mail\.google\.com/, 'the mailbox page is not navigated away');
  await popup.close();
  await page.close();
});

test('fake Gmail: closing the email removes the panel; "Got it" leaves a button to bring it back', async env => {
  const page = await openFakeGmail(env);
  await pick(page, 'Normal email');
  await page.evaluate(() => [...document.getElementById('email-anti-scam-warning').shadowRoot.querySelectorAll('button')].find(b => b.textContent === 'Got it').click());
  assert.strictEqual(await panel(page), null);
  assert.ok(await page.evaluate(() => !!document.getElementById('email-anti-scam-chip')), 'a reopen button should remain');
  await page.evaluate(() => document.getElementById('email-anti-scam-chip').shadowRoot.querySelector('button').click());
  assert.strictEqual((await panel(page)).label, 'NO WARNING SIGNS');
  await page.click('#close');
  await page.waitForTimeout(900);
  assert.strictEqual(await panel(page), null);
  assert.ok(await page.evaluate(() => !document.getElementById('email-anti-scam-chip')));
  await page.close();
});

(async () => { await run(tests, await launch()); })();
