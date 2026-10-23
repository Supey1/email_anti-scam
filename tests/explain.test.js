// Tests for extension/ui/explain.js: the same analyzer result must read the same
// whichever adapter (webpage, link click, email) supplied the evidence.
// Run with:  node tests/explain.test.js

const assert = require('assert');
const path = require('path');
const Explain = require(path.join(__dirname, '..', 'extension', 'ui', 'explain.js'));

const reason = (n) => ({ code: `R${n}`, title: `Title ${n}`, explanation: `Explanation ${n}.` });
const base = { schemaVersion: 1, verdict: 'warn', reasons: [1, 2, 3, 4, 5].map(reason), recommendedAction: 'VERIFY_INDEPENDENTLY', evidence: [] };

// 1. Evidence source does not change the wording.
const fromWebpage = Explain.describe({ ...base, evidence: [{ kind: 'form', detail: 'https://x.example/' }] });
const fromEmail = Explain.describe({ ...base, evidence: [{ kind: 'sender', detail: 'a@b.example' }] });
assert.deepStrictEqual(fromWebpage, fromEmail);

// 2. Only the top three reasons lead; the rest wait behind "show more".
assert.strictEqual(fromWebpage.top.length, 3);
assert.strictEqual(fromWebpage.more.length, 2);
assert.deepStrictEqual(fromWebpage.top.map(r => r.code), ['R1', 'R2', 'R3'], 'order from the analyzer is kept');

// 3. Verdict wording, icon + word (never colour alone), and when "continue" is allowed.
const block = Explain.describe({ ...base, verdict: 'block', recommendedAction: 'GO_BACK' });
assert.deepStrictEqual([block.icon, block.label, block.canContinue], ['🛑', 'DANGER', false]);
const warn = Explain.describe({ ...base, recommendedAction: 'GO_BACK' });
assert.deepStrictEqual([warn.icon, warn.label, warn.headline, warn.canContinue], ['⚠️', 'CAUTION', 'Stop and check this first', true]);
// "warn" + VERIFY_INDEPENDENTLY: weaker signs that never stop a click, so it doesn't say "Stop".
const check = fromWebpage;
assert.deepStrictEqual([check.icon, check.label, check.canContinue], ['⚠️', 'BE CAREFUL', true]);
assert.ok(!/stop/i.test(check.headline), check.headline);
assert.strictEqual(Explain.describe({ ...base, verdict: 'unknown', reasons: [] }).canContinue, false);

// 4. "No warning signs" never claims safety.
const none = Explain.describe({ ...base, verdict: 'no_warning_signs', reasons: [], recommendedAction: 'NONE' });
assert.match(none.headline, /No warning signs/);
assert.match(none.advice, /does not prove it is safe/);
assert.ok(!/\bsafe\b/i.test(none.headline));

// 5. Only the contract's shape: the old "allow" verdict and plain-string reasons are gone.
assert.strictEqual(Explain.describe({ verdict: 'allow', reasons: [], recommendedAction: '' }).verdict, 'unknown');
assert.deepStrictEqual(Explain.describe({ ...base, reasons: ['a plain sentence', null, reason(1)] }).top.map(r => r.code), ['R1']);

// 6. In Gmail the advice is about the email, not "close this page"; an unknown action code says nothing.
assert.match(Explain.describe({ ...base, recommendedAction: 'GO_BACK' }, 3, 'email').advice, /Do not click any links in this email/);
assert.match(Explain.describe({ ...base, recommendedAction: 'GO_BACK' }).advice, /Close this page/);
assert.strictEqual(Explain.describe({ ...base, recommendedAction: 'SEND_US_MONEY' }).advice, '');

// 7. Bad input degrades to "unknown" instead of throwing.
for (const bad of [null, undefined, 'x', { verdict: 'nonsense' }]) assert.strictEqual(Explain.describe(bad).verdict, 'unknown');

// 8. Read-aloud text: headline, top reasons, advice, and nothing from the hidden extras.
const spoken = Explain.spokenText(warn); // a GO_BACK warning
assert.ok(spoken.includes('Stop and check this first.') && spoken.includes('Explanation 3.') && !spoken.includes('Explanation 4.'));

console.log('PASS  explanations are consistent across adapters, limited to 3, honest about "no warning signs"\n\nAll tests passed');
