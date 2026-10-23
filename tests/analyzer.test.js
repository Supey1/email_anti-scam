// Tests for extension/analyzer.js (webpages and links).
// Run with:  node tests/analyzer.test.js
// All addresses use ".example", which can never be a real website.
// At the end it prints how many scams were caught and how many safe pages were wrongly flagged.

const assert = require('assert');
const path = require('path');
const { analyzePage, analyzeLink } = require(path.join(__dirname, '..', 'extension', 'analyzer.js'));

const page = (url, title, visibleText, links = [], forms = []) => ({ url, title, visibleText, links, forms });

const pages = [
  { name: 'Known dangerous site', expect: 'block', scam: true,
    evidence: page('https://known-phish.example/login', 'Sign in', 'Welcome') },
  { name: 'Fake PayPal login sending the password elsewhere', expect: 'warn', scam: true,
    evidence: page('https://account-check.example/signin', 'PayPal - Log in', 'Verify your account to avoid it being locked.',
      [], [{ action: 'https://collect-login.example/post', hasPassword: true }]) },
  { name: 'Lookalike bank address with a login form', expect: 'warn', scam: true,
    evidence: page('https://chase-secure-login.example/', 'Sign in', 'Enter your details',
      [], [{ action: 'https://chase-secure-login.example/go', hasPassword: true }]) },
  { name: 'Prize advertisement with an off-site claim button', expect: 'warn', scam: true,
    evidence: page('https://daily-deals.example/win', 'Congratulations!', 'You have won a $2,000 gift card. Claim your reward before midnight. Act now!',
      [{ text: 'Claim reward', href: 'https://claim-gift.example/start' }]) },
  { name: 'Card form with no secure connection, sent elsewhere', expect: 'warn', scam: true,
    evidence: page('http://cheap-watches.example/checkout', 'Checkout', 'Pay now to unlock your free gift card prize winner',
      [], [{ action: 'http://pay-now.example/charge', hasPayment: true }]) },

  { name: 'Real PayPal login', expect: 'allow',
    evidence: page('https://www.paypal.com/signin', 'PayPal - Log in', 'Verify your account', [], [{ action: 'https://www.paypal.com/signin', hasPassword: true }]) },
  { name: 'Ordinary shop with a sale', expect: 'allow',
    evidence: page('https://corner-shop.example/sale', 'Summer sale', 'Act now! Sale ends today. Free shipping.',
      [{ text: 'Shop now', href: 'https://corner-shop.example/shop' }]) },
  { name: 'News article about gift card scams', expect: 'allow',
    evidence: page('https://daily-news.example/scams', 'How to spot gift card scams', 'Scammers ask you to pay with gift cards or wire transfer. Never tell anyone your password. Urgent: be careful.') },
  { name: 'Own-site login form', expect: 'allow',
    evidence: page('https://library.example/login', 'Library login', 'Enter your library card number and password.', [], [{ action: 'https://library.example/login', hasPassword: true }]) },
  { name: 'Single sign-in provider on another domain', expect: 'allow',
    evidence: page('https://club.example/login', 'Club members', 'Log in to continue.', [], [{ action: 'https://auth.club-sso.example/login', hasPassword: true }]) },
  { name: 'Government page', expect: 'allow',
    evidence: page('https://www.ssa.gov/', 'Social Security', 'Claim your benefits. Verify your identity.', [], [{ action: 'https://secure.login.gov/', hasPassword: true }]) },
  { name: 'Sweepstakes terms page with an on-site claim link', expect: 'allow',
    evidence: page('https://grocer.example/contest', 'Congratulations to last month\'s winner', 'Our winner was announced.',
      [{ text: 'Claim your coupon', href: 'https://grocer.example/coupons' }]) },
];

const links = [
  { name: 'Link: fake brand site', expect: 'warn', scam: true, link: { text: 'Log in to PayPal', href: 'https://paypa1-secure.example/login' } },
  { name: 'Link: hidden destination', expect: 'warn', scam: true, link: { text: 'www.mybank.example/statement', href: 'https://other-site.example/x' } },
  { name: 'Link: number address', expect: 'warn', scam: true, link: { text: 'Open', href: 'http://192.168.4.20/login' } },
  { name: 'Link: known dangerous site', expect: 'block', scam: true, link: { text: 'Open', href: 'https://sub.fake-bank-login.example/' } },
  { name: 'Link: ordinary site', expect: 'allow', link: { text: 'Read the recipe', href: 'https://recipes.example/soup' } },
  { name: 'Link: real PayPal', expect: 'allow', link: { text: 'View activity', href: 'https://www.paypal.com/myaccount' } },
  { name: 'Link: shortened only', expect: 'allow', link: { text: 'See photos', href: 'https://bit.ly/abc' } },
];

let failed = 0;
const stats = { scams: 0, caught: 0, safe: 0, falseAlarms: 0 };

function run(c, result) {
  try {
    assert.strictEqual(result.verdict, c.expect, `expected ${c.expect}, got ${result.verdict}`);
    console.log(`PASS  ${c.name}  (${result.verdict})`);
  } catch (err) {
    failed++;
    console.log(`FAIL  ${c.name}: ${err.message}`);
    console.log('      reasons:', result.reasons, 'notes:', result.notes);
  }
  if (c.scam) { stats.scams++; if (result.verdict !== 'allow') stats.caught++; }
  else { stats.safe++; if (result.verdict !== 'allow') stats.falseAlarms++; }
}

for (const c of pages) run(c, analyzePage(c.evidence));
for (const c of links) run(c, analyzeLink(c.link));

console.log(`\nCaught ${stats.caught} of ${stats.scams} scam examples`);
console.log(`Wrongly flagged ${stats.falseAlarms} of ${stats.safe} safe examples`);
console.log(failed ? `${failed} test(s) failed` : 'All tests passed');
if (failed) process.exitCode = 1;
