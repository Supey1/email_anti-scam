// Node tests for the pure parts of extension/content/page-scanner.js (merge).
// The scanner's page-reading parts are tested in a real browser: node tests/browser/scanner.test.js
// Run with:  node tests/scanner-merge.test.js

const assert = require('assert');
const path = require('path');
const PageScanner = require(path.join(__dirname, '..', 'extension', 'content', 'page-scanner.js'));

const base = {
  source: 'webpage', pageUrl: 'https://a.example/', pageTitle: 'A', visibleText: 'hello',
  links: [{ text: 'one', url: 'https://x.example/1' }], forms: [],
  context: { scan: 'initial', truncated: { text: false, links: false } },
};
const delta = {
  ...base, visibleText: 'world', pageTitle: 'B',
  links: [{ text: 'one', url: 'https://x.example/1' }, { text: 'two', url: 'https://x.example/2' }],
  context: { scan: 'dynamic', truncated: { text: false, links: true } },
};

const merged = PageScanner.merge(base, delta);
assert.strictEqual(merged.visibleText, 'hello world');
assert.strictEqual(merged.pageTitle, 'B');
assert.deepStrictEqual(merged.links.map(l => l.text), ['one', 'two'], 'duplicate links are not added twice');
assert.strictEqual(merged.context.truncated.links, true);
assert.strictEqual(base.links.length, 1, 'merge does not change its input');

const small = { ...PageScanner.DEFAULT_LIMITS, maxMergedText: 8, maxMergedLinks: 1 };
const capped = PageScanner.merge(base, delta, small);
assert.strictEqual(capped.visibleText.length, 8);
assert.strictEqual(capped.links.length, 1);

const withAds = (ads, unreadable) => ({ ...base, context: { ...base.context, ads, adFrames: { readable: 0, unreadable } } });
const adA = { signals: ['class:ad'], text: 'A', link: { text: 'a', url: 'https://a.example/' } };
const adB = { signals: ['class:ad'], text: 'B', link: { text: 'b', url: 'https://b.example/' } };
const mergedAds = PageScanner.merge(withAds([adA], 1), { ...withAds([adB], 2), context: { ...withAds([adB], 2).context, scan: 'dynamic' } });
assert.deepStrictEqual(mergedAds.context.ads, [adA, adB], 'ads from later scans are added');
assert.strictEqual(mergedAds.context.adFrames.unreadable, 3);
assert.strictEqual(PageScanner.merge(withAds([adA, adB], 0), withAds([], 0), { ...PageScanner.DEFAULT_LIMITS, maxMergedAds: 1 }).context.ads.length, 1);

console.log('PASS  merge combines, dedupes, and caps evidence\n\nAll tests passed');
