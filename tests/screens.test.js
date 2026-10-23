// What the screens (Person B's page.js, click-guard.js, gmail.js, warning page) get
// from the scam checks: rules.js checkWebpage, checkLinkClick, checkEmail, stopsPerson.
// Run with:  node tests/screens.test.js
//
// These are Person B's examples from the old tests/analyzer.test.js and
// tests/ads-analyzer.test.js, now answered by the shared engine. What each screen does:
//   STOP   stopsPerson(): the click is cancelled / the page card appears
//   BLOCK  a known dangerous website: no way through
//   NOTE   "warn" + VERIFY_INDEPENDENTLY: shown in the Gmail panel, never interrupts
//   NONE   nothing (no_warning_signs)
// Made-up .example addresses only.

const assert = require('assert');
const path = require('path');
const { checkWebpage, checkLinkClick, checkEmail, stopsPerson } = require(path.join(__dirname, '..', 'extension', 'rules.js'));
const { validateResult } = require('./contract.js');

let passed = 0;
let total = 0;
function check(name, fn) {
  total++;
  try { fn(); passed++; console.log(`PASS  ${name}`); } catch (err) { console.log(`FAIL  ${name}: ${err.message.split('\n')[0]}`); process.exitCode = 1; }
}
const outcome = r => (r.verdict === 'block' ? 'BLOCK' : stopsPerson(r) ? 'STOP' : r.verdict === 'warn' ? 'NOTE' : 'NONE');
const contractOnly = r => { const { host, links, ...rest } = r; return rest; };
function expect(name, result, wanted) {
  check(`${name} -> ${wanted}`, () => {
    assert.deepStrictEqual(validateResult(contractOnly(result)), [], 'result breaks the contract');
    assert.strictEqual(outcome(result), wanted, `got ${outcome(result)} (${result.reasons.map(r => r.code).join(', ') || 'no reasons'})`);
  });
}

const PAGE = 'https://news.example/story';

// ---------- advertisements on an ordinary page ----------
const ad = (text, link, linkText = 'Learn more') => ({ signals: ['class:ad-slot'], text, link: link ? { text: linkText, url: link } : null });
const withAds = ads => checkWebpage({
  source: 'webpage', pageUrl: PAGE, pageTitle: 'Local news', visibleText: 'Council meets on Tuesday.', links: [], forms: [],
  context: { scan: 'initial', truncated: { text: false, links: false }, ads, adFrames: { readable: 0, unreadable: 0 } },
});
const PRIZE_AD = ad('Congratulations! You have won a $2,000 gift card. Claim your reward before midnight. Act now!', 'https://claim-gift.example/x', 'Claim reward');
const SALE_AD = ad('Summer sale: 50% off garden furniture.', 'https://garden-store.example/sale', 'Shop the sale');
for (const [name, a, wanted] of [
  ['prize + urgency + unverified claim button', PRIZE_AD, 'STOP'],
  ['leads to a known dangerous website (the page is warned, not "blocked")', ad('Great deal', 'https://known-phish.example/x'), 'STOP'],
  ['"You\'ve won! Claim your prize" with a claim button to an unverified website', ad("You've won! Claim your prize now.", 'https://claim-gift.example/a2', 'Claim your prize'), 'STOP'],
  // One moderate sign alone is "check first" in the engine's policy (docs/interfaces.md).
  ['look-alike company address alone', ad('Log in to review', 'https://paypa1-secure.example/x', 'Review'), 'NOTE'],
  ['link text names one website, goes to another', ad('Your bank', 'https://other-site.example/o', 'www.mybank.example/offer'), 'NOTE'],
  ['ordinary sale', SALE_AD, 'NONE'],
  ['urgency alone ("act now")', ad('Act now! Sale ends today.', 'https://shop.example/s', 'Shop'), 'NONE'],
  ['"congratulations" without a claim step', ad('Congratulations to our customer of the year!', 'https://garden-store.example/award', 'Read more'), 'NONE'],
  ['gift-card wording, no claim', ad('Buy a gift card for someone you love', 'https://gifts.example/cards', 'Browse'), 'NONE'],
  ['picture-only ad, no text', ad('', 'https://shoes.example/new', 'Walking shoes'), 'NONE'],
  ['no destination to judge', ad('You have won! Claim now', null), 'NONE'],
  ['prize ad that goes to the company\'s real website', ad('You have won a gift card! Claim your reward.', 'https://www.amazon.com/gp/x', 'Claim reward'), 'NONE'],
  ['claim button staying on the same website', ad('You have won a coupon! Claim your reward.', 'https://news.example/coupons', 'Claim reward'), 'NONE'],
]) expect(`[ad] ${name}`, withAds([a]), wanted);

check('[ad] a bad ad next to an ordinary one: only the bad one is explained, and the page isn\'t called dangerous', () => {
  const r = withAds([SALE_AD, PRIZE_AD]);
  assert.ok(stopsPerson(r));
  assert.ok(!JSON.stringify(r).includes('garden-store'), 'the ordinary ad must not be named');
  assert.ok(r.reasons.some(x => x.code === 'PRIZE_CLAIM'));
  assert.ok(!r.reasons.some(x => x.code === 'KNOWN_THREAT'));
});
check('[ad] the page\'s own reasons come first', () => {
  const r = checkWebpage({
    source: 'webpage', pageUrl: 'https://account-check.example/signin', pageTitle: 'PayPal - Log in', visibleText: 'Verify your account.', links: [],
    forms: [{ action: 'https://collect-login.example/post', hasPassword: true }], context: { ads: [PRIZE_AD] },
  });
  assert.strictEqual(r.reasons[0].code, 'FAKE_SIGN_IN_PAGE');
  assert.strictEqual(r.recommendedAction, 'DO_NOT_ENTER_INFO');
  assert.ok(r.reasons.some(x => x.code === 'PRIZE_CLAIM'));
});
check('[ad] at most 20 ads are checked, and broken ones are skipped', () => {
  const r = withAds([null, 5, { link: null }, ...Array(30).fill(SALE_AD), PRIZE_AD]);
  assert.strictEqual(outcome(r), 'NONE', 'the 32nd ad should not be checked');
});

// ---------- webpages ----------
const page = (url, title, visibleText, links = [], forms = []) => checkWebpage({ source: 'webpage', pageUrl: url, pageTitle: title, visibleText, links, forms, context: {} });
for (const [name, r, wanted] of [
  ['known dangerous website', page('https://known-phish.example/login', 'Sign in', 'Welcome'), 'BLOCK'],
  ['fake PayPal sign-in sending the password elsewhere', page('https://account-check.example/signin', 'PayPal - Log in', 'Verify your account to avoid it being locked.', [], [{ action: 'https://collect-login.example/post', hasPassword: true }]), 'STOP'],
  ['prize page with a claim button to another website', page('https://daily-deals.example/win', 'Congratulations!', 'You have won a $2,000 gift card. Claim your reward before midnight. Act now!', [{ text: 'Claim reward', url: 'https://claim-gift.example/start' }]), 'STOP'],
  ['card form without a secure connection, sent elsewhere', page('http://cheap-watches.example/checkout', 'Checkout', 'Pay now to unlock your free gift card prize winner', [], [{ action: 'http://pay-now.example/charge', hasPayment: true }]), 'STOP'],
  ['look-alike bank address with its own sign-in form', page('https://chase-secure-login.example/', 'Sign in', 'Enter your details', [], [{ action: 'https://chase-secure-login.example/go', hasPassword: true }]), 'NOTE'],
  ['a club whose sign-in goes to another website', page('https://club.example/login', 'Club members', 'Log in to continue.', [], [{ action: 'https://auth.club-sso.example/login', hasPassword: true }]), 'NOTE'],
  ['real PayPal sign-in', page('https://www.paypal.com/signin', 'PayPal - Log in', 'Verify your account', [], [{ action: 'https://www.paypal.com/signin', hasPassword: true }]), 'NONE'],
  ['ordinary shop with a sale', page('https://corner-shop.example/sale', 'Summer sale', 'Act now! Sale ends today. Free shipping.', [{ text: 'Shop now', url: 'https://corner-shop.example/shop' }]), 'NONE'],
  ['news article about gift card scams', page('https://daily-news.example/scams', 'How to spot gift card scams', 'Scammers ask you to pay with gift cards or wire transfer. Never tell anyone your password. Urgent: be careful.'), 'NONE'],
  ['own-site sign-in form', page('https://library.example/login', 'Library login', 'Enter your library card number and password.', [], [{ action: 'https://library.example/login', hasPassword: true }]), 'NONE'],
  ['government website', page('https://www.ssa.gov/', 'Social Security', 'Claim your benefits. Verify your identity.', [], [{ action: 'https://secure.login.gov/', hasPassword: true }]), 'NONE'],
  ['contest page with a claim link on the same website', page('https://grocer.example/contest', "Congratulations to last month's winner", 'Our winner was announced.', [{ text: 'Claim your coupon', url: 'https://grocer.example/coupons' }]), 'NONE'],
]) expect(`[page] ${name}`, r, wanted);

// ---------- link clicks ----------
const click = (text, url, extra = {}) => checkLinkClick({ text, url, pageUrl: PAGE, ...extra });
for (const [name, r, wanted] of [
  ['known dangerous website', click('Open', 'https://sub.fake-bank-login.example/'), 'BLOCK'],
  ['look-alike company address, named in the link', click('Log in to PayPal', 'https://paypa1-secure.example/login'), 'STOP'],
  ['prize claim inside an ad', click('Claim reward', 'https://claim-gift.example/x', { inAd: true, adText: 'You have won a gift card! Claim your reward now. Act now!' }), 'STOP'],
  ['the same link outside an ad has nothing to go on', click('Claim reward', 'https://claim-gift.example/x'), 'NONE'],
  ['prize words in a recognized ad, even without rushing', click('Claim your prize', 'https://claim-gift.example/a2', { inAd: true, adText: "You've won! Claim your prize now." }), 'STOP'],
  ['a link inside an email that looked like a scam', click('Read more', 'https://recipes.example/soup', { surroundingResult: { verdict: 'warn', recommendedAction: 'GO_BACK' } }), 'STOP'],
  ['link text shows another website', click('www.mybank.example/statement', 'https://other-site.example/x'), 'NOTE'],
  ['number address', click('Open', 'http://192.168.4.20/login'), 'NOTE'],
  ['shortened link', click('See photos', 'https://bit.ly/abc'), 'NOTE'],
  ['ordinary website', click('Read the recipe', 'https://recipes.example/soup'), 'NONE'],
  ['real PayPal', click('View activity', 'https://www.paypal.com/myaccount'), 'NONE'],
]) expect(`[click] ${name}`, r, wanted);
check('[click] the result says where the link really goes (shown on the warning page)', () => {
  assert.strictEqual(click('www.paypal.com', 'https://www.google.com/url?q=https://paypa1-secure.example/x').host, 'paypa1-secure.example');
  assert.strictEqual(click('x', 'javascript:alert(1)').host, '');
  assert.strictEqual(checkLinkClick(null).verdict, 'unknown');
});

// ---------- email ----------
const email = (senderName, senderEmail, subject, text, links = []) => checkEmail({
  source: 'email', pageUrl: 'https://mail.google.com/mail/u/0/', pageTitle: subject, visibleText: text, links, forms: [], context: { senderName, senderEmail, subject },
});
const FAKE_PAYPAL = email('PayPal Security', 'alerts@paypa1-secure.xyz', 'Your account has been suspended', 'Verify your account within 24 hours or it will be closed.', [{ text: 'www.paypal.com', url: 'http://paypa1-secure.xyz/login' }]);
for (const [name, r, wanted] of [
  // An email is "block" only for a known dangerous website; strong signs stop.
  ['fake PayPal', FAKE_PAYPAL, 'STOP'],
  ['delivery notice through a shortened link', email('Delivery Notice', 'notice@parcel-update.example', 'Package on hold', 'Your package could not be delivered. Click below to reschedule.', [{ text: 'Reschedule delivery', url: 'https://bit.ly/fake-test-link' }]), 'NOTE'],
  ['ordinary email', email('Linda', 'linda.m@gmail.com', 'Lunch Saturday?', 'Are you free for lunch on Saturday?'), 'NONE'],
]) expect(`[email] ${name}`, r, wanted);
check('[email] each link says where it really goes, with short flags for the Gmail panel', () => {
  assert.deepStrictEqual(FAKE_PAYPAL.links.map(l => [l.text, l.host]), [['www.paypal.com', 'paypa1-secure.xyz']]);
  assert.ok(FAKE_PAYPAL.links[0].flags.includes('hidden destination'), FAKE_PAYPAL.links[0].flags.join(', '));
});
check('[email] bad input is "unknown", with no links, and never throws', () => {
  for (const bad of [null, 'x', { source: 'email' }]) {
    const r = checkEmail(bad);
    assert.ok(Array.isArray(r.links));
  }
  assert.strictEqual(checkEmail(null).verdict, 'unknown');
});

// ---------- stopsPerson ----------
check('[stops] only block, GO_BACK, and DO_NOT_ENTER_INFO stop the person', () => {
  assert.strictEqual(stopsPerson({ verdict: 'block', recommendedAction: 'GO_BACK' }), true);
  assert.strictEqual(stopsPerson({ verdict: 'warn', recommendedAction: 'GO_BACK' }), true);
  assert.strictEqual(stopsPerson({ verdict: 'warn', recommendedAction: 'DO_NOT_ENTER_INFO' }), true);
  assert.strictEqual(stopsPerson({ verdict: 'warn', recommendedAction: 'VERIFY_INDEPENDENTLY' }), false);
  for (const r of [{ verdict: 'no_warning_signs', recommendedAction: 'NONE' }, { verdict: 'unknown', recommendedAction: 'NONE' }, null, undefined, { verdict: 'allow' }]) assert.strictEqual(stopsPerson(r), false);
});

console.log(`\n${passed}/${total} screen tests passed`);
