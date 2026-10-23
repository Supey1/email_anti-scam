// Tests for extension/ui/explain.js: the same engine result must read the same way for every adapter,
// and the interface must follow the engine's verdict and recommendedAction (docs/interfaces.md).
// Run with:  node tests/explain.test.js

const assert = require('assert');
const path = require('path');
const Explain = require(path.join(__dirname, '..', 'extension', 'ui', 'explain.js'));
const { validateResult } = require(path.join(__dirname, 'contract.js'));

const reason = (n, code = 'PRESSURE_TACTICS') => ({ code, title: `Title ${n}`, explanation: `Explanation ${n}.` });
const result = (verdict, recommendedAction, reasons, evidence = []) => ({ schemaVersion: 1, verdict, reasons, recommendedAction, evidence });
const five = [1, 2, 3, 4, 5].map(n => reason(n));
const warnGoBack = result('warn', 'GO_BACK', five);

// 1. Evidence source does not change the wording.
const fromWebpage = Explain.describe(result('warn', 'GO_BACK', five, [{ kind: 'form', value: 'https://x.example/', reasonCode: 'PRESSURE_TACTICS' }]));
const fromEmail = Explain.describe(result('warn', 'GO_BACK', five, [{ kind: 'sender', value: 'a@b.example', reasonCode: 'PRESSURE_TACTICS' }]));
assert.deepStrictEqual(fromWebpage, fromEmail);

// 2. Only the top three reasons lead; the rest wait behind "show more", in the engine's order.
assert.strictEqual(fromWebpage.top.length, 3);
assert.strictEqual(fromWebpage.more.length, 2);
assert.deepStrictEqual(fromWebpage.top.map(r => r.title), ['Title 1', 'Title 2', 'Title 3']);

// 3. Verdict wording, icon + word (never colour alone), and when "continue" is allowed.
const block = Explain.describe(result('block', 'GO_BACK', [reason(1, 'KNOWN_THREAT')]));
assert.deepStrictEqual([block.icon, block.label, block.canContinue, block.interrupts], ['🛑', 'DANGER', false, true]);
const warn = Explain.describe(warnGoBack);
assert.deepStrictEqual([warn.icon, warn.label, warn.canContinue, warn.interrupts], ['⚠️', 'CAUTION', true, true]);
assert.strictEqual(Explain.describe(result('unknown', 'NONE', [])).canContinue, false);

// 4. The engine's recommendedAction, not the interface, decides how strongly to speak and whether to interrupt.
const noType = Explain.describe(result('warn', 'DO_NOT_ENTER_INFO', [reason(1)]));
assert.strictEqual(noType.headline, 'Do not type anything on this page');
assert.strictEqual(noType.primaryLabel, 'Leave this page');
assert.strictEqual(noType.interrupts, true);
const verify = Explain.describe(result('warn', 'VERIFY_INDEPENDENTLY', [reason(1)]));
assert.strictEqual(verify.headline, 'Be careful: check this first');
assert.strictEqual(verify.interrupts, false, 'a weak warning never interrupts');
assert.ok(!/Stop/.test(verify.headline), 'a non-interrupting warning must not sound like a stop');
assert.strictEqual(Explain.interrupts(result('warn', 'VERIFY_INDEPENDENTLY', [reason(1)])), false);
assert.strictEqual(Explain.interrupts(result('block', 'GO_BACK', [reason(1)])), true);
assert.strictEqual(Explain.interrupts(result('no_warning_signs', 'NONE', [])), false);
assert.strictEqual(Explain.interrupts(null), false);

// 5. "No warning signs" never claims safety, and "unknown" is never shown as no warning signs.
const none = Explain.describe(result('no_warning_signs', 'NONE', []));
assert.match(none.headline, /No warning signs/);
assert.match(none.advice, /does not prove it is safe/);
assert.ok(!/\bsafe\b/i.test(none.headline));
const unknown = Explain.describe(result('unknown', 'NONE', []));
assert.notStrictEqual(unknown.headline, none.headline);
assert.strictEqual(unknown.label, 'NOT CHECKED');

// 6. Anything that is not a well-formed result degrades to "unknown", never to "no warning signs".
for (const bad of [null, undefined, 'x', {}, { verdict: 'nonsense' }, { verdict: 'allow', reasons: [] }]) {
  assert.strictEqual(Explain.describe(bad).verdict, 'unknown', JSON.stringify(bad));
}
assert.strictEqual(Explain.describe({ verdict: 'warn', reasons: 'oops' }).top.length, 0, 'bad reasons do not throw');

// 7. Read-aloud text: headline, top reasons, advice, and nothing from the hidden extras.
const spoken = Explain.spokenParts(warn).join(' ');
assert.ok(spoken.includes('Stop and check this first.') && spoken.includes('Explanation 3.') && !spoken.includes('Explanation 4.'));

// 8. Real engine output reads sensibly through the interface (the engine and the words stay in step).
const { analyze } = require(path.join(__dirname, '..', 'extension', 'rules.js'));
const real = analyze({
  source: 'email', pageUrl: 'https://mail.google.com/mail/u/0/', pageTitle: 'Your account has been suspended',
  visibleText: 'We noticed unusual activity. Verify your account within 24 hours or it will be closed.',
  links: [{ text: 'www.paypal.com', url: 'http://paypa1-secure.example/login' }], forms: [],
  context: { senderName: 'PayPal Security', senderEmail: 'alerts@paypa1-secure.example', subject: 'Your account has been suspended' },
});
assert.deepStrictEqual(validateResult(real), []);
const shown = Explain.describe(real);
assert.ok(shown.top.length >= 1 && shown.top.every(r => r.explanation));
assert.ok(shown.interrupts, 'a fake PayPal email is an interrupting warning');
assert.ok(shown.top.map(r => r.explanation).join(' ').includes('PayPal'), 'the real reasons name the company');

console.log('PASS  explanations follow the engine, are consistent across adapters, limited to 3, honest about "no warning signs"\n\nAll tests passed');
