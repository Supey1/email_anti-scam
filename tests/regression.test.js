// Regression tests: scam AND legitimate examples, with the answer each should get.
// Run with:  node tests/regression.test.js
//
// The cases are in tests/fixtures/regression/, one file per category. Each case says:
//   kind       "scam" or "legitimate"
//   input      the evidence, exactly as docs/interfaces.md describes it
//   expected   verdict and recommendedAction: written by hand, the answer we WANT.
//              reasons: the exact { code, explanation } list the person reads.
//   why        why that's the right answer
//   knownGap   (optional) the engine doesn't get this right yet, and why.
//              Reported on every run; the test FAILS once it's fixed, so the
//              note gets removed instead of going stale.
//
// Explanations change when wording improves. To re-record them after a
// deliberate change, run:
//   node tests/regression.test.js --update
// then READ the differences (git diff) before committing. --update never
// changes an expected verdict: if a verdict changes, that's a real failure.
// docs/regression-cases.md is written from these files by --update too,
// and this test fails if it's out of date.
//
// Only made-up .example addresses for links and websites. Never real scam links.

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { analyze } = require(path.join(__dirname, '..', 'extension', 'rules.js'));
const { validateInput, validateResult } = require('./contract.js');

const DIR = path.join(__dirname, 'fixtures', 'regression');
const DOC = path.join(__dirname, '..', 'docs', 'regression-cases.md');
const UPDATE = process.argv.includes('--update');

const STOPS = ['GO_BACK', 'DO_NOT_ENTER_INFO'];
const files = fs.readdirSync(DIR).filter(f => f.endsWith('.json')).sort();
const suites = files.map(file => ({ file, ...JSON.parse(fs.readFileSync(path.join(DIR, file), 'utf8')) }));

let passed = 0;
let total = 0;
const gaps = [];
const stats = {};
const seenIds = new Set();

function check(name, fn) {
  total++;
  try {
    fn();
    passed++;
    console.log(`PASS  ${name}`);
  } catch (err) {
    console.log(`FAIL  ${name}: ${err.message.split('\n')[0]}`);
    process.exitCode = 1;
  }
}

const what = r => (r.verdict === 'block' ? 'blocked' : r.verdict === 'warn' ? (STOPS.includes(r.recommendedAction) ? 'stopped' : 'noted') : r.verdict === 'unknown' ? 'unknown' : 'clean');

for (const suite of suites) {
  console.log(`\n--- ${suite.category} ---`);
  const s = stats[suite.category] = { scam: { stopped: 0, noted: 0, missed: 0 }, legitimate: { clean: 0, noted: 0, stopped: 0 } };
  let changed = false;
  for (const c of suite.cases) {
    const name = `[${suite.category}] ${c.id}: ${c.summary}`;
    check(`${name} (well-formed)`, () => {
      assert.ok(!seenIds.has(`${suite.category}/${c.id}`), 'duplicate id');
      seenIds.add(`${suite.category}/${c.id}`);
      assert.ok(['scam', 'legitimate'].includes(c.kind), 'kind must be "scam" or "legitimate"');
      assert.ok(c.why, 'say why the expected answer is right');
      assert.deepStrictEqual(validateInput(c.input), [], 'input breaks the contract');
    });

    const result = analyze(c.input);
    const outcome = what(result);
    if (c.kind === 'scam') s.scam[outcome === 'blocked' || outcome === 'stopped' ? 'stopped' : outcome === 'noted' ? 'noted' : 'missed']++;
    else s.legitimate[outcome === 'clean' ? 'clean' : outcome === 'noted' ? 'noted' : 'stopped']++;

    const actual = [result.verdict, result.recommendedAction];
    const expected = [c.expected.verdict, c.expected.recommendedAction];
    const matches = actual[0] === expected[0] && actual[1] === expected[1];
    if (c.knownGap) {
      check(`${name} (known gap still open)`, () => assert.ok(!matches, 'this now works: remove "knownGap" from the case'));
      gaps.push(`${suite.category}/${c.id}: wanted ${expected.join(' + ')}, got ${actual.join(' + ')}. ${c.knownGap}`);
      continue;
    }
    check(`${name} -> ${expected.join(' + ')}`, () => {
      assert.deepStrictEqual(validateResult(result), [], 'result breaks the contract');
      assert.deepStrictEqual(actual, expected, `got ${actual.join(' + ')} (${result.reasons.map(r => r.code).join(', ') || 'no reasons'})`);
    });

    const reasons = result.reasons.map(r => ({ code: r.code, explanation: r.explanation }));
    if (UPDATE || c.expected.reasons === 'RECORD') {
      if (JSON.stringify(c.expected.reasons) !== JSON.stringify(reasons)) {
        c.expected.reasons = reasons;
        changed = true;
      }
    } else {
      check(`${name} (explanations)`, () => assert.deepStrictEqual(reasons, c.expected.reasons,
        'the explanation changed: if on purpose, run with --update and read the diff'));
    }
  }
  if (changed) {
    fs.writeFileSync(path.join(DIR, suite.file), JSON.stringify({ category: suite.category, cases: suite.cases }, null, 2) + '\n');
    console.log(`(recorded explanations in ${suite.file})`);
  }
}

// ---------- the readable version: docs/regression-cases.md ----------

function renderDoc() {
  const lines = [
    '# Regression cases',
    '',
    'Scam and legitimate examples, the answer each should get, and the exact explanation the person reads.',
    'Written from `tests/fixtures/regression/` by `node tests/regression.test.js --update`; don\'t edit by hand.',
    '',
    'These examples were written by the people who wrote the rules, so passing them shows the rules work as',
    'designed. They are NOT a measure of how many real scams the extension catches: that needs examples',
    'nobody tuned the rules on.',
    '',
    '| Verdict | Means |',
    '|---|---|',
    '| `warn` + `GO_BACK` / `DO_NOT_ENTER_INFO` | stopped: the person sees "Stop and check" before going on |',
    '| `warn` + `VERIFY_INDEPENDENTLY` | noted: shown, never interrupts |',
    '| `no_warning_signs` + `NONE` | nothing shown (which never means "safe") |',
    '| `block` | known dangerous: no way through |',
    '',
  ];
  for (const suite of suites) {
    lines.push(`## ${suite.category}`, '');
    for (const c of suite.cases) {
      lines.push(`### ${c.kind === 'scam' ? '🛑 Scam' : '✅ Legitimate'}: ${c.summary}`, '');
      lines.push(`\`${suite.category}/${c.id}\`, ${c.input.source}. **Expected:** \`${c.expected.verdict}\` + \`${c.expected.recommendedAction}\`. ${c.why}`, '');
      if (c.knownGap) lines.push(`> **Known gap:** ${c.knownGap}`, '');
      if (Array.isArray(c.expected.reasons) && c.expected.reasons.length) {
        lines.push('What the person reads:', '');
        for (const r of c.expected.reasons) lines.push(`- ${r.explanation} *(${r.code})*`);
        lines.push('');
      }
    }
  }
  return lines.join('\n');
}

const doc = renderDoc();
if (UPDATE || !fs.existsSync(DOC)) {
  fs.writeFileSync(DOC, doc);
} else {
  check('docs/regression-cases.md is up to date', () => assert.ok(fs.readFileSync(DOC, 'utf8') === doc, 'run: node tests/regression.test.js --update'));
}

// ---------- summary ----------

console.log('\n--- results by category (these are our own examples, not a real-world accuracy figure) ---');
const pad = (t, n) => String(t).padEnd(n);
console.log(`${pad('category', 26)}${pad('scams stopped', 15)}${pad('noted', 7)}${pad('missed', 8)}| ${pad('legit clean', 13)}${pad('noted', 7)}stopped`);
for (const [category, s] of Object.entries(stats)) {
  console.log(`${pad(category, 26)}${pad(s.scam.stopped, 15)}${pad(s.scam.noted, 7)}${pad(s.scam.missed, 8)}| ${pad(s.legitimate.clean, 13)}${pad(s.legitimate.noted, 7)}${s.legitimate.stopped}`);
}
for (const gap of gaps) console.log(`KNOWN GAP  ${gap}`);
console.log(`\n${passed}/${total} regression checks passed`);
