// Tests for advertisements and the common analyze() entry point in extension/analyzer.js.
// Run with:  node tests/ads-analyzer.test.js
// Advertisements use the same analyzer as everything else; the ad context just says "this is an ad".
// All addresses are made-up ".example" names.

const assert = require('assert');
const path = require('path');
const { analyze, analyzeAd, analyzeLink } = require(path.join(__dirname, '..', 'extension', 'analyzer.js'));

const ad = (text, link, linkText = 'Learn more') => ({ signals: ['class:ad-slot'], text, link: link ? { text: linkText, url: link } : null });
const stats = { scams: 0, caught: 0, safe: 0, falseAlarms: 0 };
let failed = 0;
function check(name, actual, expected, scam) {
  try { assert.strictEqual(actual, expected); console.log(`PASS  ${name}  (${actual})`); }
  catch (e) { failed++; console.log(`FAIL  ${name}: expected ${expected}, got ${actual}`); }
  if (scam === true) { stats.scams++; if (actual !== 'allow') stats.caught++; }
  if (scam === false) { stats.safe++; if (actual !== 'allow') stats.falseAlarms++; }
}

const PAGE = 'https://news.example/story';

// ---- advertisements ----
check('ad: prize + urgency + unverified claim button', analyzeAd(ad('Congratulations! You have won a $2,000 gift card. Claim your reward before midnight. Act now!', 'https://claim-gift.example/x', 'Claim reward'), PAGE).verdict, 'warn', true);
check('ad: link text names one site, goes to another', analyzeAd(ad('Your bank', 'https://other-site.example/o', 'www.mybank.example/offer'), PAGE).verdict, 'warn', true);
check('ad: fake brand destination', analyzeAd(ad('Log in to review', 'https://paypa1-secure.example/x', 'Review'), PAGE).verdict, 'warn', true);
check('ad: known dangerous destination', analyzeAd(ad('Great deal', 'https://known-phish.example/x'), PAGE).verdict, 'block', true);
check('ad: ordinary sale', analyzeAd(ad('Summer sale: 50% off garden furniture.', 'https://garden-store.example/sale', 'Shop the sale'), PAGE).verdict, 'allow', false);
check('ad: urgency alone ("act now")', analyzeAd(ad('Act now! Sale ends today.', 'https://shop.example/s', 'Shop'), PAGE).verdict, 'allow', false);
check('ad: "congratulations" without a claim step', analyzeAd(ad('Congratulations to our customer of the year!', 'https://garden-store.example/award', 'Read more'), PAGE).verdict, 'allow', false);
check('ad: gift-card wording only, no claim button', analyzeAd(ad('Buy a gift card for someone you love', 'https://gifts.example/cards', 'Browse'), PAGE).verdict, 'allow', false);
check('ad: image-only ad with no text', analyzeAd(ad('', 'https://shoes.example/new', 'Walking shoes'), PAGE).verdict, 'allow', false);
check('ad: no destination to judge', analyzeAd(ad('You have won! Claim now', null), PAGE).verdict, 'allow');
check('ad: prize ad that belongs to a known brand', analyzeAd(ad('You have won a gift card! Claim your reward.', 'https://www.amazon.com/gp/x', 'Claim reward'), PAGE).verdict, 'allow', false);
check('ad: claim button staying on the same site', analyzeAd(ad('You have won a coupon! Claim your reward.', 'https://news.example/coupons', 'Claim reward'), PAGE).verdict, 'allow', false);

// ---- link click inside an ad ----
check('click in ad: prize claim', analyzeLink({ text: 'Claim reward', href: 'https://claim-gift.example/x' }, { ad: { text: 'You have won a gift card! Claim your reward now. Act now!', signals: [] } }).verdict, 'warn', true);
check('same link outside an ad has nothing to go on', analyzeLink({ text: 'Claim reward', href: 'https://claim-gift.example/x' }).verdict, 'allow');

// ---- page with ads: only the ad is reported; an ordinary page stays allowed ----
const pageEvidence = (ads, extra = {}) => ({
  source: 'webpage', pageUrl: PAGE, pageTitle: 'Local news', visibleText: 'Council meets on Tuesday.',
  links: [], forms: [], context: { scan: 'initial', truncated: { text: false, links: false }, ads, adFrames: { readable: 0, unreadable: 0 } }, ...extra,
});
const badAd = ad('Congratulations! You have won a gift card. Claim your reward. Act now!', 'https://claim-gift.example/x', 'Claim reward');
const okAd = ad('Summer sale', 'https://garden-store.example/sale', 'Shop');
const withBad = analyze(pageEvidence([okAd, badAd]));
check('page with a bad ad: warn', withBad.verdict, 'warn', true);
assert.ok(withBad.reasons.every(r => !/garden-store/.test(r)), 'the ordinary ad must not be named');
assert.ok(withBad.reasons.some(r => /advertisement promises a prize/.test(r)));
assert.ok(!/dangerous/.test(withBad.reasons.join(' ')), 'the page is not called dangerous');
check('page with only ordinary ads: allow', analyze(pageEvidence([okAd])).verdict, 'allow', false);
check('page with no ads: allow', analyze(pageEvidence([])).verdict, 'allow', false);
check('page whose ad leads to a known threat: warn (not block) for the page', analyze(pageEvidence([ad('Deal', 'https://known-phish.example/x')])).verdict, 'warn', true);

// ---- the common entry point treats webpages and emails alike ----
const email = (senderName, senderEmail, subject, text, links = []) => ({
  source: 'email', pageUrl: 'https://mail.google.com/mail/u/0/', pageTitle: subject, visibleText: text, links, forms: [], context: { senderName, senderEmail, subject },
});
check('email: fake PayPal', analyze(email('PayPal Security', 'alerts@paypa1-secure.xyz', 'Your account has been suspended', 'Verify your account within 24 hours or it will be closed.', [{ text: 'www.paypal.com', url: 'http://paypa1-secure.xyz/login' }])).verdict, 'block', true);
check('email: shipping notice', analyze(email('Delivery Notice', 'notice@parcel-update.example', 'Package on hold', 'Your package could not be delivered. Click below to reschedule.', [{ text: 'Reschedule delivery', url: 'https://bit.ly/fake-test-link' }])).verdict, 'warn', true);
check('email: normal email', analyze(email('Linda', 'linda.m@gmail.com', 'Lunch Saturday?', 'Are you free for lunch on Saturday?')).verdict, 'allow', false);
const mailResult = analyze(email('PayPal Security', 'alerts@paypa1-secure.xyz', 'x', 'y', [{ text: 'a', url: 'http://paypa1-secure.xyz/login' }]));
assert.ok(mailResult.links.length === 1 && mailResult.recommendedAction, 'email result keeps link details and advice');
check('webpage through analyze(): fake login', analyze({ source: 'webpage', pageUrl: 'https://account-check.example/signin', pageTitle: 'PayPal - Log in', visibleText: 'Verify your account to avoid it being locked.', links: [], forms: [{ action: 'https://collect-login.example/post', hasPassword: true }], context: {} }).verdict, 'warn', true);
check('bad input degrades to unknown', analyze(null).verdict, 'unknown');
check('missing fields degrade without throwing', analyze({ source: 'webpage' }).verdict, 'allow');

console.log(`\nCaught ${stats.caught} of ${stats.scams} scam examples`);
console.log(`Wrongly flagged ${stats.falseAlarms} of ${stats.safe} safe examples`);
console.log(failed ? `${failed} test(s) failed` : 'All tests passed');
if (failed) process.exitCode = 1;
