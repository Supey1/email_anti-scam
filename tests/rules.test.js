// Tests for extension/rules.js.
// Run with:  node tests/rules.test.js
// (You only need Node to run these tests. The extension itself doesn't need it.)
//
// The links below are never opened. They only test the checks.
// When you add a new rule, add a test email here that should trigger it.

const assert = require('assert');
const path = require('path');
const { analyzeEmail } = require(path.join(__dirname, '..', 'extension', 'rules.js'));

const cases = [
  {
    name: 'Fake PayPal "account suspended" email',
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
    expectNoReason: /Chase/,
    email: {
      senderName: 'Shop',
      senderEmail: 'orders@purchase-confirm.example',
      subject: 'Order shipped',
      bodyText: 'Your order has shipped.',
      links: [{ text: 'Track order', href: 'https://purchase-confirm.example/track' }],
    },
  },
];

let passed = 0;
for (const c of cases) {
  const result = analyzeEmail(c.email);
  try {
    if (c.expect) assert.strictEqual(result.level, c.expect, `expected ${c.expect}, got ${result.level}`);
    if (c.expectReason) assert.ok(result.reasons.some(r => c.expectReason.test(r)), `missing reason ${c.expectReason}`);
    if (c.expectNoReason) assert.ok(!result.reasons.some(r => c.expectNoReason.test(r)), `unexpected reason ${c.expectNoReason}`);
    passed++;
    console.log(`PASS  ${c.name}  (${result.level}, ${result.score} points)`);
  } catch (err) {
    console.log(`FAIL  ${c.name}: ${err.message}`);
    console.log('      reasons:', result.reasons);
    process.exitCode = 1;
  }
}
console.log(`\n${passed}/${cases.length} tests passed`);
