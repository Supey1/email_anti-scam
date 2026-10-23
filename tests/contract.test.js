// Checks every fixture against the contract in docs/interfaces.md.
// Run with:  node tests/contract.test.js
//
// tests/fixtures/inputs/   fixed inputs  (Person A builds the engine against these)
// tests/fixtures/results/  fixed results (Person B builds the interface against these)
// The last part makes sure the checker itself catches broken objects.

const fs = require('fs');
const path = require('path');
const { validateInput, validateResult, REASON_CODES } = require('./contract.js');

let passed = 0;
let total = 0;

function report(name, problems, expectProblems = false) {
  total++;
  const ok = expectProblems ? problems.length > 0 : problems.length === 0;
  if (ok) {
    passed++;
    console.log(`PASS  ${name}`);
  } else {
    console.log(`FAIL  ${name}`);
    for (const p of expectProblems ? ['the checker should have found a problem'] : problems) console.log(`      ${p}`);
    process.exitCode = 1;
  }
}

function eachFixture(folder, check) {
  const dir = path.join(__dirname, 'fixtures', folder);
  for (const file of fs.readdirSync(dir).filter(f => f.endsWith('.json')).sort()) {
    report(`${folder}/${file}`, check(JSON.parse(fs.readFileSync(path.join(dir, file), 'utf8'))));
  }
}

console.log(`${REASON_CODES.size} reason codes in docs/interfaces.md\n`);
eachFixture('inputs', validateInput);
eachFixture('results', validateResult);

// Broken objects the checker must reject.
const goodInput = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'inputs', 'webpage-fake-sign-in.json'), 'utf8'));
const goodResult = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'results', 'warn-go-back-prize-ad.json'), 'utf8'));
const copy = x => JSON.parse(JSON.stringify(x));
const broken = [
  ['input with a typed password', () => { const x = copy(goodInput); x.forms[0].value = 'hunter2'; return validateInput(x); }],
  ['input with an extra field', () => { const x = copy(goodInput); x.cookies = 'a=b'; return validateInput(x); }],
  ['input with an unknown source', () => { const x = copy(goodInput); x.source = 'screenshot'; return validateInput(x); }],
  ['link input with two links', () => { const x = copy(goodInput); x.source = 'link'; x.context = {}; x.links = [{ text: 'a', url: 'https://a.example' }, { text: 'b', url: 'https://b.example' }]; return validateInput(x); }],
  ['result with a score instead of reasons', () => { const x = copy(goodResult); x.reasons = []; x.score = 7; return validateResult(x); }],
  ['result with plain-string reasons', () => { const x = copy(goodResult); x.reasons = ['It promises a prize.']; return validateResult(x); }],
  ['result with a code missing from the table', () => { const x = copy(goodResult); x.reasons[0].code = 'MADE_UP_CODE'; return validateResult(x); }],
  ['"block" that lets you continue', () => { const x = copy(goodResult); x.verdict = 'block'; x.recommendedAction = 'VERIFY_INDEPENDENTLY'; return validateResult(x); }],
  ['"no_warning_signs" with reasons', () => { const x = copy(goodResult); x.verdict = 'no_warning_signs'; x.recommendedAction = 'NONE'; return validateResult(x); }],
  ['the old "allow" verdict', () => { const x = copy(goodResult); x.verdict = 'allow'; return validateResult(x); }],
];
console.log('');
for (const [name, run] of broken) report(`rejects: ${name}`, run(), true);

console.log(`\n${passed}/${total} contract checks passed`);
