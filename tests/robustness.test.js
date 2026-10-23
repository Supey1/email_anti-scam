// Robustness and security tests for the scam checks (the engine).
// Run with:  node tests/robustness.test.js
//
// Everything the engine reads (page text, link text, sender names, addresses)
// is written by whoever made the page or email, scammers included. These tests
// check that hostile input can't:
//   - slow the checks down (they run on every page, and a frozen check could
//     freeze the person's Gmail tab)
//   - hide a company name or a scam phrase with invisible or look-alike letters
//   - sneak a known dangerous address past the list with address tricks
//   - crash the engine, break the result format, or pollute other objects
// Made-up .example addresses only.
//
// The checks run in a separate thread with a time limit: if a pattern ever
// gets stuck again, this reports which test hung instead of hanging itself.

const { Worker, isMainThread, parentPort } = require('worker_threads');
const HANG_LIMIT_MS = 60000;

if (isMainThread) {
  const worker = new Worker(__filename);
  let current = '(starting)';
  let passed = 0;
  let total = 0;
  const timer = setTimeout(() => {
    console.log(`FAIL  ${current}: still running after ${HANG_LIMIT_MS / 1000} s (a check is stuck)`);
    worker.terminate();
    process.exitCode = 1;
  }, HANG_LIMIT_MS);
  worker.on('message', m => {
    if (m.type === 'start') current = m.name;
    if (m.type === 'line') { console.log(m.line); total++; if (m.ok) passed++; else process.exitCode = 1; }
    if (m.type === 'done') { clearTimeout(timer); console.log(`\n${passed}/${total} robustness tests passed`); }
  });
  worker.on('error', err => { clearTimeout(timer); console.log(`FAIL  ${current}: ${err.message}`); process.exitCode = 1; });
  return;
}

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { analyze } = require(path.join(__dirname, '..', 'extension', 'rules.js'));
const { validateResult } = require('./contract.js');

const SLOW_MS = 250; // generous: real inputs take a few milliseconds

const link = (text, url = 'https://x.example/', nearby = '') => ({ source: 'link', pageUrl: 'https://news.example/', pageTitle: '', visibleText: '', links: [{ text, url }], forms: [], context: { nearbyText: nearby } });
const page = text => ({ source: 'webpage', pageUrl: 'https://p.example/', pageTitle: 't', visibleText: text, links: [], forms: [], context: {} });
const email = (senderName, text, links = [], subject = 's') => ({ source: 'email', pageUrl: '', pageTitle: '', visibleText: text, links, forms: [], context: { senderName, senderEmail: 'alerts@mail.example', subject } });

function timed(input, options) {
  const start = process.hrtime.bigint();
  const result = analyze(input, options);
  return { result, ms: Number(process.hrtime.bigint() - start) / 1e6 };
}

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

// ---------- speed ----------

const HOSTILE = [
  ['link text "a.a.a.a..." (50 KB: the old pattern took seconds here, half an hour at 1 MB)', link('a.'.repeat(25000))],
  ['link text, one 1 MB word', link('x'.repeat(1_000_000))],
  ['words around a link, 1 MB of "pay "', link('x', 'https://x.example/', 'pay '.repeat(250000))],
  ['page, 1 MB of "your account "', page('your account '.repeat(80000))],
  ['page, "$1.1.1.1" repeated', page('pay $1.1.1.1 '.repeat(20000))],
  ['page, "call" then 1 MB of digits', page('call ' + '1'.repeat(1_000_000))],
  ['page, scam phrases repeated', page('You have won! Pay a fee to claim your prize before midnight. Call 1-800-555-0100. '.repeat(5000))],
  ['email with 5,000 links', email('x', 'hi', Array.from({ length: 5000 }, (_, i) => ({ text: `www.site${i}.example`, url: `https://other${i}.example/` })))],
  ['address with 120 parts', link('x', 'https://' + 'a.'.repeat(120) + 'example/')],
  ['address 100 KB long', link('x', 'https://x.example/' + 'a'.repeat(100000))],
  ['sender name 1 MB', email('PayPal '.repeat(150000), 'hi')],
];
for (const [name, input] of HOSTILE) {
  test(`fast with hostile input: ${name}`, () => {
    const { result, ms } = timed(input);
    assert.ok(ms < SLOW_MS, `took ${ms.toFixed(0)} ms`);
    assert.deepStrictEqual(validateResult(result), []);
  });
}

// ---------- invisible and look-alike letters ----------

const DISGUISED_NAMES = [['zero-width space', 'Pay\u200bPal'], ['soft hyphen', 'Pay\u00adPal'], ['word joiner', 'Pay\u2060Pal'], ['full-width letters', 'ＰａｙＰａｌ'], ['right-to-left override', '\u202ePayPal']];
for (const [how, name] of DISGUISED_NAMES) {
  test(`a company name disguised with ${how} is still recognized`, () => {
    const r = analyze(email(name, 'Your account is locked.', [], 'Account locked'));
    assert.ok(r.reasons.some(x => x.code === 'SENDER_NAME_MISMATCH'), r.reasons.map(x => x.code).join(','));
  });
}
for (const [how, text] of [['zero-width spaces', 'You have w\u200bon! Claim your pri\u200bze before midnight.'], ['full-width letters', 'Ｙｏｕ ｈａｖｅ ｗｏｎ! Claim your prize before midnight.']]) {
  test(`a scam phrase disguised with ${how} is still recognized`, () => {
    assert.strictEqual(analyze(link('Claim', 'https://claim.example/', text)).recommendedAction, 'GO_BACK');
  });
}
test('a link text showing a website, disguised with a hidden character, is still compared', () => {
  const r = analyze(link('www.pay\u200bpal.com', 'https://elsewhere.example/'));
  assert.ok(r.reasons.some(x => x.code === 'HIDDEN_DESTINATION'));
});

// ---------- known dangerous addresses: tricks don't get past the list ----------

for (const url of ['https://KNOWN-PHISH.example/', 'https://known-phish.example./', 'https://known-phish.example:8443/',
  'https://user@known-phish.example/', 'https://known-phish.example\\@evil.example/', 'https://%6Bnown-phish.example/',
  'https://www.google.com/url?q=https://known-phish.example/', 'HTTPS://LOGIN.KNOWN-PHISH.EXAMPLE/X']) {
  test(`known dangerous address still blocked when written as ${url}`, () => assert.strictEqual(analyze(link('x', url)).verdict, 'block'));
}

// ---------- malformed input ----------

const MALFORMED = [
  null, undefined, 42, 'text', [], {}, { source: 'fax' }, { source: 'link' }, { source: 'link', links: [null] },
  { source: 'link', links: [{ text: 5, url: {} }] }, { source: 'email', links: 'x', context: { senderName: 7, senderEmail: [] } },
  { source: 'webpage', pageUrl: {}, visibleText: ['x'], forms: [{ action: null }, null, 5] }, { source: 'webpage', pageUrl: 'file:///C:/page.html' },
  { source: 'link', links: [{ text: 'x', url: 'javascript:alert(1)' }] }, { source: 'link', links: [{ text: 'x', url: 'mailto:a@b.example' }] },
  { source: 'email', context: { surroundingResult: 'yes' }, links: [{ text: 'x', url: 'https://a.example/' }] },
];
MALFORMED.forEach((input, i) => {
  test(`malformed input never crashes and always follows the contract (${i + 1}: ${JSON.stringify(input) || String(input)})`, () => {
    assert.deepStrictEqual(validateResult(analyze(input)), []);
  });
});
test('nothing to check (no link, not a web page) is "unknown", never "no warning signs"', () => {
  for (const input of [{ source: 'link' }, { source: 'link', links: [{ text: 'x', url: 'mailto:a@b.example' }] }, { source: 'webpage', pageUrl: 'file:///C:/page.html' }]) {
    assert.strictEqual(analyze(input).verdict, 'unknown', JSON.stringify(input));
  }
});
test('hostile keys like "__proto__" don\'t pollute other objects', () => {
  analyze(JSON.parse('{"source":"email","links":[],"visibleText":"hi","context":{"__proto__":{"polluted":"yes"},"senderName":"x"}}'));
  analyze(JSON.parse('{"source":"webpage","pageUrl":"https://a.example/","forms":[{"__proto__":{"polluted":"yes"}}],"context":{}}'));
  assert.strictEqual(({}).polluted, undefined);
  assert.strictEqual(Object.prototype.polluted, undefined);
});
test('page text and names are returned as text, never interpreted (the screens must show them as text)', () => {
  const r = analyze({ ...email('<img src=x onerror=alert(1)> PayPal', 'Account locked'), context: { senderName: '<img src=x onerror=alert(1)> PayPal', senderEmail: 'alerts@mail.example', subject: 'Account locked' } });
  assert.ok(r.reasons.every(x => typeof x.explanation === 'string'));
});

// ---------- fuzzing: the regression cases, mangled ----------

// The same mangling every run (a fixed seed), so a failure can be repeated.
let seed = 12345;
const random = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
const pick = list => list[Math.floor(random() * list.length)];
const WEIRD = [null, 0, -1, 1e308, '', ' ', '\u0000', '\u202e', '\ud800', '💥'.repeat(1000), 'a.'.repeat(5000), {}, [], [null], true,
  'https://known-phish.example/', 'javascript:alert(1)', '<script>alert(1)</script>', 'x'.repeat(200000)];
function mangle(value, depth = 0) {
  if (depth > 3 || random() < 0.15) return pick(WEIRD);
  if (Array.isArray(value)) return value.map(v => (random() < 0.3 ? mangle(v, depth + 1) : v));
  if (value && typeof value === 'object') {
    const copy = {};
    for (const [k, v] of Object.entries(value)) if (random() > 0.1) copy[k] = random() < 0.3 ? mangle(v, depth + 1) : v;
    return copy;
  }
  return typeof value === 'string' && random() < 0.5 ? value + pick(['\u200b', '.'.repeat(500), ' pay now', '\u202e', '$1.99']) : pick(WEIRD);
}
const regressionInputs = fs.readdirSync(path.join(__dirname, 'fixtures', 'regression'))
  .flatMap(f => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'regression', f), 'utf8')).cases.map(c => c.input));
test(`fuzzing: 2,000 mangled versions of the ${regressionInputs.length} regression inputs never crash, break the contract, or slow down`, () => {
  let slowest = 0;
  for (let i = 0; i < 2000; i++) {
    const input = mangle(regressionInputs[i % regressionInputs.length]);
    const { result, ms } = timed(input);
    slowest = Math.max(slowest, ms);
    const problems = validateResult(result);
    assert.deepStrictEqual(problems, [], `case ${i}: ${JSON.stringify(input).slice(0, 200)}`);
  }
  assert.ok(slowest < SLOW_MS, `slowest took ${slowest.toFixed(0)} ms`);
});

// ---------- run (in the worker thread) ----------

for (const t of tests) {
  parentPort.postMessage({ type: 'start', name: t.name });
  try {
    t.fn();
    parentPort.postMessage({ type: 'line', ok: true, line: `PASS  ${t.name}` });
  } catch (err) {
    parentPort.postMessage({ type: 'line', ok: false, line: `FAIL  ${t.name}: ${err.message.split('\n')[0]}` });
  }
}
parentPort.postMessage({ type: 'done' });
