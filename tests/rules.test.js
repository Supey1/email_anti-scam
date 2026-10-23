// Tests for extension/rules.js.
// Run with:  node tests/rules.test.js
// (You only need Node to run these tests. The extension itself doesn't need it.)
//
// The links below are never opened. They only test the checks.
// When you add a new rule, add a test here that should trigger it, AND a
// normal example that should NOT trigger it.
//
// Every test is marked scam: true (should be caught) or scam: false (normal,
// should be left alone). At the end we print how many scams were caught and
// how many normal examples got a false alarm. Those two numbers go in our
// submission. A small test set shows the extension works; it can't prove it
// catches scams in general.

const assert = require('assert');
const path = require('path');
const { analyzeEmail, analyzeLink, analyzePage } = require(path.join(__dirname, '..', 'extension', 'rules.js'));

// ---------- emails (Gmail panel) ----------
// "Caught" means the panel says high or medium. "False alarm" means it isn't low.
const emailCases = [
  {
    name: 'Fake PayPal "account suspended" email',
    scam: true,
    expect: 'high',
    email: {
      senderName: 'PayPal Security',
      senderEmail: 'alerts@paypa1-secure.xyz',
      subject: 'Your account has been suspended',
      bodyText: 'We noticed unusual activity. Verify your account within 24 hours or it will be closed.',
      links: [{ text: 'www.paypal.com', href: 'http://paypa1-secure.xyz/login' }],
    },
  },
  {
    name: 'Real PayPal receipt',
    scam: false,
    expect: 'low',
    email: {
      senderName: 'PayPal',
      senderEmail: 'service@paypal.com',
      subject: 'Your receipt from Coffee Shop',
      bodyText: 'You sent a payment of $4.50. View your activity anytime.',
      links: [{ text: 'View activity', href: 'https://www.paypal.com/myaccount/activity' }],
    },
  },
  {
    name: 'Grandparent scam',
    scam: true,
    expect: 'high',
    email: {
      senderName: 'Tommy',
      senderEmail: 'tommy83920@gmail.com',
      subject: 'Grandma please help',
      bodyText: "Grandma, I was in an accident and need bail money. Please buy gift cards and don't tell mom.",
      links: [],
    },
  },
  {
    name: 'Normal email from a friend',
    scam: false,
    expect: 'low',
    email: {
      senderName: 'Linda',
      senderEmail: 'linda.m@gmail.com',
      subject: 'Lunch Saturday?',
      bodyText: 'Are you free for lunch on Saturday? The new diner opened on Main Street.',
      links: [],
    },
  },
  {
    name: 'Fake Microsoft support from a free email account',
    scam: true,
    expect: 'high',
    email: {
      senderName: 'Microsoft Support',
      senderEmail: 'ms.helpdesk@outlook.com',
      subject: 'Your computer has been infected',
      bodyText: 'Your computer is infected with a virus. Call tech support immediately.',
      links: [],
    },
  },
  {
    name: 'Fake delivery notice with a shortened link',
    scam: true,
    expect: 'medium',
    email: {
      senderName: 'Delivery Notice',
      senderEmail: 'notice@parcel-update.example',
      subject: 'Package on hold',
      bodyText: 'Your package could not be delivered. Click below to reschedule.',
      links: [{ text: 'Reschedule delivery', href: 'https://bit.ly/fake-test-link' }],
    },
  },
  {
    name: 'Number-address link hidden inside a Google redirect',
    scam: true,
    expectReason: /number address/,
    email: {
      senderName: 'Bank Alerts',
      senderEmail: 'alerts@bank-alerts.example',
      subject: 'Statement ready',
      bodyText: 'Your statement is ready.',
      links: [{ text: 'Open statement', href: 'https://www.google.com/url?q=http://192.168.4.20/login' }],
    },
  },
  {
    name: '"purchase" in a web address should NOT be mistaken for Chase',
    scam: false,
    expectNoReason: /Chase/,
    email: {
      senderName: 'Shop',
      senderEmail: 'orders@purchase-confirm.example',
      subject: 'Order shipped',
      bodyText: 'Your order has shipped.',
      links: [{ text: 'Track order', href: 'https://purchase-confirm.example/track' }],
    },
  },
  {
    name: 'Email linking to a known dangerous website',
    scam: true,
    expect: 'high',
    expectAction: 'block',
    email: {
      senderName: 'Account Team',
      senderEmail: 'team@notices.example',
      subject: 'Please review',
      bodyText: 'Please review the document.',
      links: [{ text: 'Open document', href: 'https://login.known-phish.example/doc' }],
    },
  },
];

// ---------- links (click guard) ----------
// "Caught" means the click is stopped (warn or block). "False alarm" means a
// normal link got stopped. Weak signs alone must NOT stop a click.
const PAGE = 'https://news.example/today';
const linkCases = [
  {
    name: 'Prize ad: "you have won a gift card, claim before midnight"',
    scam: true,
    expectAction: 'warn',
    expectReason: /prize AND rushes you/,
    link: { text: 'Claim now', href: 'https://claim-reward-now.example/claim' },
    context: { pageUrl: PAGE, nearbyText: 'Congratulations! You have won a $2,000 gift card. Claim your reward before midnight.' },
  },
  {
    name: 'Ad promising an Amazon prize that goes somewhere else',
    scam: true,
    expectAction: 'warn',
    expectReason: /mentions Amazon/,
    link: { text: 'Get my gift card', href: 'https://reward-center.example/amzn' },
    context: { pageUrl: PAGE, nearbyText: 'You have been selected to receive a free Amazon gift card. Just pay $1.99 shipping to claim your prize.' },
  },
  {
    name: 'Link that says chase.com but goes to a different website',
    scam: true,
    expectAction: 'warn',
    link: { text: 'www.chase.com', href: 'https://chase-secure-login.example/verify' },
    context: { pageUrl: PAGE },
  },
  {
    name: 'Link to a known dangerous website is blocked',
    scam: true,
    expectAction: 'block',
    link: { text: 'Read more', href: 'https://known-phish.example/start' },
    context: { pageUrl: PAGE },
  },
  {
    name: 'Fake tech-support pop-up ad',
    scam: true,
    expectAction: 'warn',
    link: { text: 'Get help now', href: 'https://pc-repair-help.example/' },
    context: { pageUrl: PAGE, nearbyText: 'WARNING! Your computer is infected. Call Microsoft support at 1-800-555-0199 now. Do not close this window.' },
  },
  {
    name: 'Any link inside a scam email is stopped',
    scam: true,
    expectAction: 'warn',
    link: { text: 'Click here', href: 'https://plain-site.example/' },
    context: { pageUrl: 'https://mail.google.com/mail/u/0/', surroundingLevel: 'high' },
  },
  {
    name: 'News headline about a lottery winner',
    scam: false,
    expectAction: 'allow',
    link: { text: 'Local woman wins lottery jackpot', href: 'https://other-news.example/lottery' },
    context: { pageUrl: PAGE, nearbyText: 'Local woman wins lottery jackpot. Officials say the winner will collect next week.' },
  },
  {
    name: 'Normal store ad with "limited time" sale',
    scam: false,
    expectAction: 'allow',
    link: { text: 'Shop the sale', href: 'https://garden-store.example/sale' },
    context: { pageUrl: PAGE, nearbyText: 'Spring sale: 20% off garden tools. Limited time only. Shop the sale.' },
  },
  {
    name: 'Real bank link next to a "card blocked" message',
    scam: false,
    expectAction: 'allow',
    link: { text: 'Sign in to Chase', href: 'https://secure.chase.com/web/auth' },
    context: { pageUrl: PAGE, nearbyText: 'Your card is blocked for your protection. Sign in to Chase to review.' },
  },
  {
    name: 'Shortened link alone is not enough to stop a click',
    scam: false,
    expectAction: 'allow',
    link: { text: 'Recipe', href: 'https://bit.ly/fake-test-recipe' },
    context: { pageUrl: PAGE },
  },
  {
    name: 'Link to another page on the same website',
    scam: false,
    expectAction: 'allow',
    link: { text: 'You have won! (a same-site quiz)', href: 'https://news.example/quiz' },
    context: { pageUrl: PAGE, nearbyText: 'Claim your prize before midnight' },
  },
  {
    name: 'Real USPS tracking link',
    scam: false,
    expectAction: 'allow',
    link: { text: 'USPS Tracking', href: 'https://tools.usps.com/go/TrackConfirmAction' },
    context: { pageUrl: PAGE },
  },
];

// ---------- whole pages (page warning) ----------
// "Caught" means a page warning is shown (warn or block).
const pageCases = [
  {
    name: 'Fake PayPal sign-in page on a look-alike address',
    scam: true,
    expectAction: 'warn',
    page: { url: 'https://paypa1-login.example/signin', title: 'Log in to your PayPal account', headings: 'PayPal', text: 'Email or mobile number. Password.', hasPassword: true, formActions: ['https://collect.example/p.php'] },
  },
  {
    name: 'Bank sign-in page on an unrelated address',
    scam: true,
    expectAction: 'warn',
    page: { url: 'https://secure-update-center.example/', title: 'Wells Fargo Sign On', headings: 'Wells Fargo', text: 'Username. Password. Sign On.', hasPassword: true, formActions: [] },
  },
  {
    name: 'Fake virus warning page',
    scam: true,
    expectAction: 'warn',
    page: { url: 'https://security-alert-x.example/', title: 'Security Alert', headings: 'Your computer has been blocked', text: 'Virus detected! Your computer is infected. Call support at (800) 555-0142. Do not close this page.', hasPassword: false, formActions: [] },
  },
  {
    name: 'Prize page asking for a fee',
    scam: true,
    expectAction: 'warn',
    page: { url: 'https://winner-today.example/', title: 'Congratulations!', headings: 'You have won!', text: 'You are our lucky winner. Pay a small processing fee to claim your prize. Offer expires today.', hasPassword: false, formActions: [] },
  },
  {
    name: 'Known dangerous website',
    scam: true,
    expectAction: 'block',
    page: { url: 'https://fake-bank-login.example/', title: 'Welcome', headings: '', text: '', hasPassword: false, formActions: [] },
  },
  {
    name: 'Real PayPal sign-in page',
    scam: false,
    expectAction: 'allow',
    page: { url: 'https://www.paypal.com/signin', title: 'Log in to your PayPal account', headings: 'PayPal', text: 'Email or mobile number. Password.', hasPassword: true, formActions: ['https://www.paypal.com/signin'] },
  },
  {
    name: 'News article about scams',
    scam: false,
    expectAction: 'allow',
    page: { url: 'https://news.example/scams', title: 'How to spot a lottery scam', headings: 'How to spot a lottery scam', text: 'Scammers often say a person has won a lottery. Police urge people to hang up. Experts say real lotteries never charge fees.', hasPassword: false, formActions: [] },
  },
  {
    name: 'Ordinary website sign-in page',
    scam: false,
    expectAction: 'allow',
    page: { url: 'https://library.example/login', title: 'Library account sign in', headings: 'Sign in to your library account', text: 'Card number. PIN.', hasPassword: true, formActions: ['https://library.example/session'] },
  },
  {
    name: 'Store page with a sale countdown',
    scam: false,
    expectAction: 'allow',
    page: { url: 'https://garden-store.example/', title: 'Garden Store', headings: 'Spring sale', text: 'Sale ends tonight. Act fast: only 3 left in stock. Free shipping over $50.', hasPassword: false, formActions: [] },
  },
];

// ---------- run everything ----------

let passed = 0;
let total = 0;
const tally = { scams: 0, caught: 0, normal: 0, falseAlarms: 0 };

function run(group, c, result, flagged) {
  total++;
  if (c.scam) { tally.scams++; if (flagged) tally.caught++; } else { tally.normal++; if (flagged) tally.falseAlarms++; }
  try {
    if (c.expect) assert.strictEqual(result.level, c.expect, `expected ${c.expect}, got ${result.level}`);
    if (c.expectAction) assert.strictEqual(result.action, c.expectAction, `expected action ${c.expectAction}, got ${result.action}`);
    if (c.expectReason) assert.ok(result.reasons.some(r => c.expectReason.test(r)), `missing reason ${c.expectReason}`);
    if (c.expectNoReason) assert.ok(!result.reasons.some(r => c.expectNoReason.test(r)), `unexpected reason ${c.expectNoReason}`);
    passed++;
    console.log(`PASS  [${group}] ${c.name}  (${result.level}, ${result.action}, ${result.score} points)`);
  } catch (err) {
    console.log(`FAIL  [${group}] ${c.name}: ${err.message}`);
    console.log('      reasons:', result.reasons);
    process.exitCode = 1;
  }
}

for (const c of emailCases) {
  const result = analyzeEmail(c.email);
  run('email', c, result, result.level !== 'low');
}
for (const c of linkCases) {
  const result = analyzeLink(c.link, c.context);
  run('link', c, result, result.action !== 'allow');
}
for (const c of pageCases) {
  const result = analyzePage(c.page);
  run('page', c, result, result.action !== 'allow');
}

console.log(`\n${passed}/${total} tests passed`);
console.log(`Scams caught:          ${tally.caught}/${tally.scams}`);
console.log(`False alarms (normal): ${tally.falseAlarms}/${tally.normal}`);
