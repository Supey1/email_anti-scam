// Node tests for the pure parts of extension/content/page-scanner.js (merge).
// The scanner's page-reading parts are tested in a real browser: node tests/browser/scanner.test.js
// Run with:  node tests/scanner-merge.test.js

const assert = require('assert');
const path = require('path');
const PageScanner = require(path.join(__dirname, '..', 'extension', 'content', 'page-scanner.js'));
const { validateInput } = require(path.join(__dirname, 'contract.js'));

const base = {
  source: 'webpage', pageUrl: 'https://a.example/', pageTitle: 'A', visibleText: 'hello',
  links: [{ text: 'one', url: 'https://x.example/1' }],
  forms: [{ action: 'https://a.example/login', hasPassword: true, hasPaymentField: false }],
  context: { mainHeadings: ['Welcome'] },
};
const delta = {
  ...base, pageTitle: 'B', visibleText: 'world',
  links: [{ text: 'one', url: 'https://x.example/1' }, { text: 'two', url: 'https://x.example/2' }],
  forms: [{ action: 'https://a.example/login', hasPassword: true, hasPaymentField: false }, { action: 'https://pay.example/', hasPassword: false, hasPaymentField: true }],
  context: { mainHeadings: [] },
};

const merged = PageScanner.merge(base, delta);
assert.strictEqual(merged.visibleText, 'hello world');
assert.strictEqual(merged.pageTitle, 'B');
assert.deepStrictEqual(merged.links.map(l => l.text), ['one', 'two'], 'duplicate links are not added twice');
assert.strictEqual(merged.forms.length, 2, 'duplicate forms are not added twice');
assert.deepStrictEqual(merged.context.mainHeadings, ['Welcome']);
assert.deepStrictEqual(validateInput(merged), [], 'merged evidence still follows the contract');
assert.strictEqual(base.links.length, 1, 'merge does not change its input');

// Too much text: the START of the old text is trimmed, never the newest text (a pop-up added late sits at the end).
const limits = { ...PageScanner.DEFAULT_LIMITS, maxMergedText: 100, keepHeadChars: 20 };
const long = PageScanner.merge({ ...base, visibleText: 'A'.repeat(500) }, { ...delta, visibleText: 'LATE-SCAM-POPUP' }, limits);
assert.ok(long.visibleText.length <= 100);
assert.ok(long.visibleText.endsWith('LATE-SCAM-POPUP'), 'the newest text survives');
assert.ok(long.visibleText.startsWith('A'.repeat(20)), 'a little of the beginning is kept');

const capped = PageScanner.merge(base, delta, { ...PageScanner.DEFAULT_LIMITS, maxMergedLinks: 1 });
assert.strictEqual(capped.links.length, 1);

assert.ok(PageScanner.DEFAULT_LIMITS.maxMergedText <= 50000, "the contract's text limit");

console.log('PASS  merge combines, dedupes, keeps the newest text, and stays within the contract\n\nAll tests passed');
