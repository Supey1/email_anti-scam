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
const fs = require('fs');
const path = require('path');
const { analyze, whenToLookUp, analyzeEmail, analyzeLink, analyzePage } = require(path.join(__dirname, '..', 'extension', 'rules.js'));
const norm = require(path.join(__dirname, '..', 'extension', 'core', 'url-normalizer.js'));
const { EXPLANATIONS } = require(path.join(__dirname, '..', 'extension', 'core', 'explanations.js'));
const { RULES, decide } = require(path.join(__dirname, '..', 'extension', 'core', 'risk-policy.js'));
const { validateResult, REASON_CODES } = require('./contract.js');

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
    name: 'Fake bank sign-in page with a look-alike address',
    scam: true,
    expectAction: 'warn',
    page: { url: 'https://chase.com.secure-login.example/', title: 'Chase Online - Sign in', headings: 'Chase', text: 'Username. Password. Your account is locked. Sign in to restore access.', hasPassword: true, formActions: [] },
  },
  {
    name: 'Real article about bank security (mentions passwords and locked accounts)',
    scam: false,
    expectAction: 'allow',
    page: { url: 'https://news.example/bank-safety', title: 'How to keep your Chase account safe', headings: 'How to keep your Chase account safe', text: 'Scammers often send messages saying your account is locked. Banks will never ask for your password by text. If you are worried, call your bank using the number on your card. Report phishing messages to your bank.', hasPassword: false, formActions: [] },
  },
  {
    name: 'Bank safety tips that never mention scams',
    scam: false,
    expectAction: 'allow',
    page: { url: 'https://library.example/tips', title: 'Staying safe with online banking', headings: 'Online banking tips', text: 'If a message says your account is locked, do not panic. Call your bank\'s support line using the number on your card.', hasPassword: false, formActions: [] },
  },
  {
    name: 'Store page with a sale countdown',
    scam: false,
    expectAction: 'allow',
    page: { url: 'https://garden-store.example/', title: 'Garden Store', headings: 'Spring sale', text: 'Sale ends tonight. Act fast: only 3 left in stock. Free shipping over $50.', hasPassword: false, formActions: [] },
  },
];

// ---------- reading addresses (url-normalizer.js) ----------
// [name, actual, expected]
const normalizerChecks = [
  ['capitals and a dot at the end', norm.parseUrl('HTTPS://WWW.PayPal.COM./x').hostname, 'www.paypal.com'],
  ['"www." removed for comparing', norm.parseUrl('https://www.paypal.com/').host, 'paypal.com'],
  ['letters written as codes', norm.parseUrl('https://pay%70al.example/').hostname, 'paypal.example'],
  ['everything before "@" is not the website', norm.parseUrl('https://www.paypal.com@evil.example/').hostname, 'evil.example'],
  ['the part before "@" is kept to check', norm.parseUrl('https://www.paypal.com@evil.example/').username, 'www.paypal.com'],
  ['number address as one big number', norm.parseUrl('http://3232235777/').hostname, '192.168.1.1'],
  ['number address in hexadecimal', norm.parseUrl('http://0xC0A80101/').isIp, true],
  ['IPv6 number address', norm.parseUrl('https://[::1]/').isIp, true],
  ['not an address', norm.parseUrl('not a url').ok, false],
  ['empty', norm.parseUrl('').ok, false],
  ['not a website (javascript:)', norm.parseUrl('javascript:alert(1)').isWeb, false],
  ['relative link with a base', norm.parseUrl('/login', 'https://bank.example/home').hostname, 'bank.example'],
  ['encoded path is decoded', norm.parseUrl('https://evil.example/www%2Epaypal%2Ecom/').pathname, '/www.paypal.com/'],
  ['Google pass-through link', norm.normalizeUrl('https://www.google.com/url?q=http://192.168.4.20/login').hostname, '192.168.4.20'],
  ['pass-through inside pass-through', norm.normalizeUrl('https://www.google.com/url?q=' + encodeURIComponent('https://nam1.safelinks.protection.outlook.com/?url=' + encodeURIComponent('https://final.example/x'))).hostname, 'final.example'],
  ['registrable: subdomain', norm.registrableDomain('login.secure.paypal.com'), 'paypal.com'],
  ['registrable: two-part ending', norm.registrableDomain('news.bbc.co.uk'), 'bbc.co.uk'],
  ['registrable: company website in front', norm.registrableDomain('paypal.com.fake-domain.example'), 'fake-domain.example'],
  ['registrable: free hosting is one owner per site', norm.registrableDomain('someone.github.io'), 'someone.github.io'],
  ['registrable: number address', norm.registrableDomain('192.168.1.1'), '192.168.1.1'],
  ['same site: two pages of one website', norm.sameSite('a.paypal.com', 'www.paypal.com'), true],
  ['same site: two different github.io sites', norm.sameSite('scam.github.io', 'bank.github.io'), false],
  ['same site: two different .co.uk owners', norm.sameSite('bbc.co.uk', 'evil.co.uk'), false],
  ['owner: www.paypal.com is PayPal', norm.isSameOrSubdomain('www.paypal.com', 'paypal.com'), true],
  ['owner: paypal.com.fake-domain.example is NOT PayPal', norm.isSameOrSubdomain('paypal.com.fake-domain.example', 'paypal.com'), false],
  ['owner: notpaypal.com is NOT PayPal', norm.isSameOrSubdomain('notpaypal.com', 'paypal.com'), false],
  ['website named in text', norm.findDomainInText('Visit www.PayPal.com today.'), 'paypal.com'],
  ['email address in text is not a website', norm.findDomainInText('Write to help@paypal.com'), ''],
  ['other-alphabet letters decoded (matches Node)', norm.toUnicodeHost('xn--pypal-4ve.com'), require('url').domainToUnicode('xn--pypal-4ve.com')],
  ['other-alphabet letters decoded (German)', norm.toUnicodeHost('xn--mnchen-3ya.de'), 'münchen.de'],
  ['not followed: a fake Google pass-through', norm.normalizeUrl('https://google.evil.example/url?q=https://www.paypal.com/').hostname, 'google.evil.example'],
  ['not followed: "google" on free hosting', norm.normalizeUrl('https://google.github.io/url?q=https://x.example/').hostname, 'google.github.io'],
  ['followed: Google in another country', norm.normalizeUrl('https://www.google.co.uk/url?q=https://x.example/').hostname, 'x.example'],
  ['followed: YouTube pass-through', norm.normalizeUrl('https://www.youtube.com/redirect?q=https://x.example/').hostname, 'x.example'],
  ['not followed: an unknown website with ?next=', norm.normalizeUrl('https://site.example/go?next=https://x.example/').hostname, 'site.example'],
  ['addresses written inside a link are found', norm.embeddedUrls(norm.parseUrl('https://site.example/go?next=https://x.example/&t=hi')).map(u => u.hostname), ['x.example']],
  ['password before "@" is read', norm.parseUrl('https://user:secret@site.example/').password, 'secret'],
  ['free hosting site', norm.isFreeHosting('bank-login.netlify.app'), true],
  ['the hosting company itself is not "free hosting"', norm.isFreeHosting('github.io'), false],
  ['normal website is not free hosting', norm.isFreeHosting('bank.example'), false],
  ['other-alphabet look-alike made plain', norm.toLookalikeAscii('xn--pypal-4ve.com'), 'paypal.com'],
  ['normal address has no look-alike letters', norm.toLookalikeAscii('paypal.com'), ''],
];

// ---------- every rule: one example that should trigger it, one that should not ----------
// These use analyze() and the contract in docs/interfaces.md directly.

const PAGE_URL = 'https://news.example/today';
const link = (url, text = 'Open', nearbyText = '', extra = {}) => ({
  source: 'link', pageUrl: PAGE_URL, pageTitle: '', visibleText: '', links: [{ text, url }], forms: [],
  context: { nearbyText, insideFrame: false, ...extra },
});
const page = ({ url, title = '', headings = [], text = '', forms = [] }) => ({
  source: 'webpage', pageUrl: url, pageTitle: title, visibleText: text, links: [], forms, context: { mainHeadings: headings },
});
const email = ({ name = 'Linda', address = 'linda@mail.example', subject = 'Hello', text = '', links = [] }) => ({
  source: 'email', pageUrl: 'https://mail.google.com/mail/u/0/', pageTitle: subject, visibleText: text, links, forms: [],
  context: { senderName: name, senderEmail: address, subject },
});
const passwordForm = action => ({ action, hasPassword: true, hasPaymentField: false });

const FAKE_BANK_LOGIN = page({ url: 'https://secure-update-center.example/', title: 'Wells Fargo Sign On', headings: ['Wells Fargo'], text: 'Username. Password.', forms: [passwordForm('https://secure-update-center.example/s')] });
const BANK_SECURITY_ARTICLE = page({ url: 'https://news.example/bank-safety', title: 'How to keep your Wells Fargo account safe', headings: ['Bank security tips'], text: 'Never share your password. Scammers pretend to be your bank. Report phishing to your bank.' });

const RULE_TESTS = [
  { code: 'KNOWN_THREAT',
    triggers: [link('https://login.known-phish.example/x'),
      link('https://hacked-blog.example/wp-content/uploads/secure/login.html'),
      link('https://share.example/go?next=https://known-phish.example/start'),
      page({ url: 'https://library.example/login', title: 'Sign in', forms: [passwordForm('https://fake-bank-login.example/collect')] })],
    doesNot: [link('https://known-phish-news.example/'), link('https://known-phish.example.other.example/'),
      link('https://hacked-blog.example/2024/recipes'), link('https://hacked-blog.example/wp-content/uploads/secure-ish/')] },
  { code: 'LOOKALIKE_DOMAIN',
    triggers: [link('https://paypa1-secure.example/login'), link('https://paypal.com.fake-domain.example/'), link('https://xn--pypal-4ve.example/'), link('https://amazom.example/'), link('https://applesupport.example/')],
    doesNot: [link('https://www.paypal.com/signin'), link('https://www.paypal.co.uk/'), link('https://applebees.example/'), link('https://bucket.s3.amazonaws.com/file'), link('https://purchase-confirm.example/')] },
  { code: 'HIDDEN_DESTINATION',
    triggers: [link('https://u123.ct.sendgrid.net/ls/click?upn=abc', 'www.garden-store.example'), link('https://evil.example/', 'www.chase.com'), link('https://google.evil.example/url?q=https://www.paypal.com/', 'www.paypal.com')],
    doesNot: [link('https://secure.chase.com/x', 'www.chase.com'), link('https://news.bbc.co.uk/x', 'bbc.co.uk'),
      link('https://www.google.com/url?q=https://www.paypal.com/', 'www.paypal.com')] },
  { code: 'MISLEADING_URL',
    triggers: [link('https://www.paypal.com@evil.example/'), link('https://evil.example/www.paypal.com/signin'), link('https://admin:secret@site.example/')],
    doesNot: [link('https://www.paypal.com/signin'), link('https://reviews.example/paypal-review')] },
  { code: 'NUMBER_ADDRESS',
    triggers: [link('http://192.168.4.20/login'), link('http://3232235777/')],
    doesNot: [link('https://route-192.example/')] },
  { code: 'BRAND_NAME_MISMATCH',
    triggers: [link('https://parcel.example/x', 'Track with FedEx'),
      email({ name: 'USPS', address: 'notice@mail.example', subject: 'Package on hold', links: [{ text: 'Track', url: 'https://parcel-help.example/t' }] })],
    doesNot: [link('https://www.fedex.com/track', 'Track with FedEx'),
      email({ name: 'USPS', address: 'notice@usps.com', subject: 'Package on hold', links: [{ text: 'Track', url: 'https://tools.usps.com/t' }, { text: 'Facebook', url: 'https://facebook.example/usps' }] }),
      email({ name: 'USPS', address: 'news@sendgrid.net', subject: 'Informed Delivery', links: [{ text: 'Read more', url: 'https://u1.ct.sendgrid.net/ls/click?upn=x' }] }),
      link('https://www.googleadservices.com/pagead/aclk?sa=L&ai=abc', 'Get my gift card', 'You have won a free Amazon gift card. Claim before midnight.')] },
  { code: 'SHORTENED_LINK',
    triggers: [link('https://bit.ly/abc')],
    doesNot: [link('https://notbit.ly/abc')] },
  { code: 'RISKY_DOMAIN_ENDING',
    triggers: [link('https://deals.xyz/')],
    doesNot: [link('https://xyz.example/')] },
  { code: 'UNVERIFIED_PRIZE_CLAIM',
    triggers: [link('https://claim.example/', 'Claim', 'You have won a prize! Act now.')],
    doesNot: [link('https://claim.example/', 'Read more', 'Local woman wins lottery jackpot.')] },
  { code: 'SENDER_NAME_MISMATCH',
    triggers: [email({ name: 'PayPal', address: 'alerts@mail.example' }), email({ name: 'service@paypal.com', address: 'x@evil.example' }),
      email({ name: 'Apple', address: 'apple.support@icloud.com' }),
      email({ name: 'PayPal', address: 'paypal@sendgrid.net', subject: 'Unusual sign-in activity', text: 'Verify your account.' })],
    doesNot: [email({ name: 'PayPal', address: 'service@paypal.com' }),
      email({ name: 'IRS', address: 'irs@service.govdelivery.com', subject: 'IRS Tax Tips', text: 'Free filing options. Unsubscribe or manage preferences.' }),
      email({ name: 'Amazon Deals', address: 'deals@sendgrid.net', subject: 'Spring sale', text: '20% off. Shop now. Unsubscribe.' })] },
  { code: 'LOOKALIKE_SENDER',
    triggers: [email({ name: 'Alerts', address: 'alerts@paypa1-secure.example' })],
    doesNot: [email({ name: 'Alerts', address: 'alerts@paypal.com' }), email({ name: 'Tommy', address: 'tommy@gmail.com' })] },
  { code: 'COMPANY_ON_FREE_EMAIL',
    triggers: [email({ name: 'Billing Department', address: 'billing.dept@gmail.com' })],
    doesNot: [email({ name: 'Linda', address: 'linda@gmail.com' })] },
  { code: 'FAKE_SIGN_IN_PAGE',
    triggers: [FAKE_BANK_LOGIN],
    doesNot: [BANK_SECURITY_ARTICLE, page({ url: 'https://connect.secure.wellsfargo.com/auth', title: 'Wells Fargo Sign On', forms: [passwordForm('https://connect.secure.wellsfargo.com/auth')] })] },
  { code: 'SIGN_IN_ON_FREE_HOSTING',
    triggers: [page({ url: 'https://secure-account.netlify.app/', title: 'Sign in', forms: [passwordForm('https://secure-account.netlify.app/s')] }),
      link('https://wellsfargo-verify.web.app/login'), link('https://someone.github.io/x', 'Sign in to your account')],
    doesNot: [page({ url: 'https://my-recipes.netlify.app/', title: 'Soup recipes' }), link('https://someone.github.io/recipes', 'Soup recipes'),
      link('https://login.example/x', 'Sign in')] },
  { code: 'INSECURE_FORM',
    triggers: [page({ url: 'http://library.example/login', title: 'Sign in', forms: [passwordForm('http://library.example/session')] })],
    doesNot: [page({ url: 'https://library.example/login', title: 'Sign in', forms: [passwordForm('/session')] }),
      page({ url: 'http://library.example/', title: 'Opening hours' }),
      page({ url: 'http://localhost:8080/login', title: 'Sign in', forms: [passwordForm('/session')] })] },
  { code: 'CREDENTIALS_SENT_ELSEWHERE',
    triggers: [page({ url: 'https://library.example/login', title: 'Sign in', forms: [passwordForm('https://collect.example/p.php')] })],
    doesNot: [page({ url: 'https://library.example/login', title: 'Sign in', forms: [passwordForm('https://library.example/session')] }),
      page({ url: 'https://library.example/login', title: 'Sign in', forms: [passwordForm('/session')] })] },
  { code: 'PRIZE_CLAIM',
    triggers: [page({ url: 'https://winner.example/', text: 'You have won! Pay a small fee to claim your prize.' }), email({ text: "Congratulations, you've won $5,000!" })],
    doesNot: [page({ url: 'https://news.example/x', text: 'Local woman wins lottery jackpot.' }), email({ text: 'Our team won the bowling game!' })] },
  { code: 'PRIZE_WITH_PRESSURE',
    triggers: [link('https://claim.example/', 'Claim', 'You have won a gift card. Claim before midnight.')],
    doesNot: [link('https://bit.ly/claim', 'Claim', 'You have won a gift card.')] },
  { code: 'PAY_TO_CLAIM',
    triggers: [page({ url: 'https://winner.example/', text: 'You have won! Pay a $4.99 processing fee to claim your prize.' }),
      email({ text: 'Pay the $1.99 redelivery fee.' }), link('https://parcel.example/', 'Pay', 'Your package is on hold. Pay the $1.99 redelivery fee now.')],
    doesNot: [page({ url: 'https://garden-store.example/', text: 'Free shipping on orders over $50. Pay at checkout.' })] },
  { code: 'PAYMENT_METHOD_REQUEST',
    triggers: [email({ text: 'Please buy gift cards and send me the numbers.' })],
    doesNot: [email({ text: 'Thanks for the birthday card!' })] },
  { code: 'ACCOUNT_PROBLEM_CLAIM',
    triggers: [email({ subject: 'Your account has been suspended' }), page({ url: 'https://alert.example/', text: 'Your computer is infected. Call 1-800-555-0199 now.' })],
    doesNot: [email({ text: 'I locked myself out of the house again!' }), BANK_SECURITY_ARTICLE] },
  { code: 'CALL_THIS_NUMBER',
    triggers: [page({ url: 'https://alert.example/', text: 'Virus detected! Call (800) 555-0142. Do not close this page.' })],
    doesNot: [page({ url: 'https://library.example/tips', text: "If a message says your account is locked, call your bank's support line using the number on your card." })] },
  { code: 'TECH_SUPPORT_CLAIM',
    triggers: [email({ text: 'Please allow remote access with AnyDesk so we can fix it.' })],
    doesNot: [email({ text: "Hope you're over that flu virus!" })] },
  { code: 'PERSONAL_INFO_REQUEST',
    triggers: [email({ text: 'Reply with your social security number to continue.' })],
    doesNot: [email({ text: 'The Social Security office is closed Monday.' })] },
  { code: 'DELIVERY_PROBLEM_CLAIM',
    triggers: [email({ text: 'Your package could not be delivered.' })],
    doesNot: [email({ text: 'Your package was delivered to the front door.' })] },
  { code: 'SECRECY_REQUEST',
    triggers: [email({ text: "Please don't tell mom about this." })],
    doesNot: [email({ text: 'Tell mom I said hi!' })] },
  { code: 'FAMILY_EMERGENCY',
    triggers: [email({ text: 'Grandma, I was arrested and need bail money.' })],
    doesNot: [email({ text: 'Grandma, the hospital visit went fine. See you Sunday!' })] },
  { code: 'PAYMENT_DEMAND',
    triggers: [email({ text: 'You owe $500. Pay now.' }), page({ url: 'https://bill.example/', text: 'Your outstanding balance must be paid. Pay now, or you will be arrested.' })],
    doesNot: [email({ text: 'Thanks for paying me back for lunch!' }), email({ text: 'Your payment of $45 is due on May 3.' })] },
  { code: 'THREAT_OF_CONSEQUENCES',
    triggers: [email({ text: 'Pay today or you will be arrested.' }), email({ text: 'Your Social Security number has been suspended.' })],
    doesNot: [email({ text: 'The police arrested a man on Main Street.' }), email({ text: 'My license renewal came through!' })] },
  { code: 'URGENT_PAYMENT_REQUEST',
    triggers: [email({ text: 'Pay the overdue invoice immediately.' }), email({ text: 'You owe back taxes. Pay or legal action will be taken against you.' }),
      email({ text: 'Buy gift cards and send the codes within 24 hours.' })],
    doesNot: [email({ text: 'Your payment of $45 is due on May 3.' }), email({ text: 'Urgent: the meeting moved to 3pm.' })] },
  { code: 'AGENCY_DOES_NOT_EMAIL',
    triggers: [email({ name: 'IRS', address: 'refunds@irs-help.example', subject: 'Tax refund', text: 'Confirm your account number to receive your refund.' }),
      email({ name: 'Internal Revenue Service', address: 'no-reply@irs.gov', subject: 'Final notice', text: 'You owe back taxes. Pay now.' })],
    doesNot: [email({ name: 'IRS', address: 'irs@service.govdelivery.com', subject: 'IRS Tax Tips', text: 'Free filing options. Unsubscribe or manage preferences.' }),
      email({ name: 'Linda', subject: 'Taxes', text: 'Did you finish your IRS forms yet?' })] },
  { code: 'PRESSURE_TACTICS',
    triggers: [email({ text: 'Act now, this is urgent.' })],
    doesNot: [email({ text: 'No rush, whenever you have time.' })] },
  { code: 'INSIDE_SCAM_EMAIL',
    triggers: [link('https://plain.example/', 'Click here', '', { surroundingResult: { verdict: 'warn', recommendedAction: 'GO_BACK' } })],
    doesNot: [link('https://plain.example/', 'Click here', '', { surroundingResult: { verdict: 'warn', recommendedAction: 'VERIFY_INDEPENDENTLY' } })] },
];

// ---------- which combinations lead to which verdict (risk-policy.js) ----------
// Made-up findings, so each row tests the policy alone.
const f = (code, data = {}) => ({ code, subject: 'link', data, evidence: null });
const POLICY_TESTS = [
  ['known threat, trusted source', [f('KNOWN_THREAT', { trusted: true })], 'link', ['block', 'GO_BACK']],
  ['known threat, untrusted source: stop, but no block', [f('KNOWN_THREAT', { trusted: false })], 'link', ['warn', 'GO_BACK']],
  ['strange ending alone', [f('RISKY_DOMAIN_ENDING')], 'link', ['warn', 'VERIFY_INDEPENDENTLY']],
  ['urgent wording alone (email)', [f('PRESSURE_TACTICS')], 'email', ['warn', 'VERIFY_INDEPENDENTLY']],
  ['shortened link alone', [f('SHORTENED_LINK')], 'link', ['warn', 'VERIFY_INDEPENDENTLY']],
  ['look-alike company address alone', [f('LOOKALIKE_DOMAIN', { technique: 'character_swap' })], 'link', ['warn', 'VERIFY_INDEPENDENTLY']],
  ['look-alike + strange ending', [f('LOOKALIKE_DOMAIN', { technique: 'character_swap' }), f('RISKY_DOMAIN_ENDING')], 'link', ['warn', 'GO_BACK']],
  ['company website written in front (strong alone)', [f('LOOKALIKE_DOMAIN', { technique: 'official_domain_in_front' })], 'link', ['warn', 'GO_BACK']],
  ['paypal.com@ trick (strong alone)', [f('MISLEADING_URL', { trick: 'before_at' })], 'link', ['warn', 'GO_BACK']],
  ['hidden sign-in name alone', [f('MISLEADING_URL', { trick: 'hidden_login' })], 'link', ['warn', 'VERIFY_INDEPENDENTLY']],
  ['many weak signs (7 points) never stop', [f('SHORTENED_LINK'), f('RISKY_DOMAIN_ENDING'), f('PRESSURE_TACTICS'), f('BRAND_NAME_MISMATCH'), f('INSECURE_FORM')], 'link', ['warn', 'VERIFY_INDEPENDENTLY']],
  ['two moderate signs', [f('HIDDEN_DESTINATION'), f('NUMBER_ADDRESS')], 'link', ['warn', 'GO_BACK']],
  ['fake sign-in page with a password box', [f('FAKE_SIGN_IN_PAGE')], 'webpage', ['warn', 'GO_BACK'], { asksForSecrets: false }],
  ['strong sign on a page with a password box', [f('FAKE_SIGN_IN_PAGE')], 'webpage', ['warn', 'DO_NOT_ENTER_INFO'], { asksForSecrets: true }],
  ['prize + rushing adds the combination', [f('PRIZE_CLAIM'), f('PRESSURE_TACTICS')], 'link', ['warn', 'GO_BACK']],
  ['nothing', [], 'link', ['no_warning_signs', 'NONE']],
];

// ---------- several rules at once: the verdict follows the TYPE of evidence, not the count ----------
// Real inputs, not made-up findings: these run every rule together.
const codes = r => r.reasons.map(x => x.code);
const COMBINED_TESTS = [
  {
    name: 'prize offer on an unfamiliar website with several weak signs: warning, never "confirmed"',
    input: page({ url: 'https://prize-center.xyz/', title: 'Congratulations!', text: 'You have been selected! Claim your reward. Offer expires today.' }),
    expect: r => {
      assert.strictEqual(r.verdict, 'warn');
      assert.ok(!codes(r).includes('KNOWN_THREAT'));
    },
  },
  {
    name: '...the same page on a verified malicious website is blocked',
    input: page({ url: 'https://fake-bank-login.example/', title: 'Congratulations!', text: 'You have been selected! Claim your reward. Offer expires today.' }),
    expect: r => assert.deepStrictEqual([r.verdict, r.reasons[0].code], ['block', 'KNOWN_THREAT']),
  },
  {
    name: 'a verified malicious website with NO other warning signs is still blocked',
    input: link('https://known-phish.example/recipes', "Grandma's soup recipe", 'A lovely soup for cold days.'),
    expect: r => assert.deepStrictEqual([r.verdict, codes(r)], ['block', ['KNOWN_THREAT']]),
  },
  {
    name: 'many weak signs (shortened, .xyz, rushing, company name) trigger more rules than one strong sign, but only get "check first"',
    input: email({ name: 'Billing Team', address: 'billing.team@gmail.com', text: 'Act now.', links: [{ text: 'Amazon order', url: 'https://bit.ly/x' }, { text: 'Details', url: 'https://deals.xyz/' }] }),
    expect: r => {
      assert.deepStrictEqual([r.verdict, r.recommendedAction], ['warn', 'VERIFY_INDEPENDENTLY']);
      assert.ok(r.reasons.length >= 4, `only ${r.reasons.length} reasons`);
    },
  },
  {
    name: '...while ONE strong sign (company website written in front) stops the click',
    input: link('https://paypal.com.secure-login.example/', 'Open'),
    expect: r => {
      assert.deepStrictEqual([r.verdict, r.recommendedAction], ['warn', 'GO_BACK']);
      assert.strictEqual(r.reasons.length, 1);
    },
  },
  {
    name: 'a look-alike address alone: check first; with a hidden destination too: stop',
    input: link('https://paypa1-secure.example/', 'Open'),
    expect: r => {
      assert.strictEqual(r.recommendedAction, 'VERIFY_INDEPENDENTLY');
      const both = analyze(link('https://paypa1-secure.example/', 'www.paypal.com'));
      assert.strictEqual(both.recommendedAction, 'GO_BACK');
    },
  },
  {
    name: 'scary words on the company\'s real website: no warning signs',
    input: page({ url: 'https://www.chase.com/alerts', title: 'Chase alerts', text: 'Your card is blocked. Call 1-800-555-0100 now. Act fast.' }),
    expect: r => assert.strictEqual(r.verdict, 'no_warning_signs'),
  },
  {
    name: 'fake sign-in page + sends password elsewhere + look-alike address: do not enter info',
    input: page({ url: 'https://paypal-verify.example/', title: 'PayPal: Log in', forms: [passwordForm('https://collect.example/p')] }),
    expect: r => {
      assert.deepStrictEqual([r.verdict, r.recommendedAction], ['warn', 'DO_NOT_ENTER_INFO']);
      for (const c of ['FAKE_SIGN_IN_PAGE', 'CREDENTIALS_SENT_ELSEWHERE', 'LOOKALIKE_DOMAIN']) assert.ok(codes(r).includes(c), `missing ${c}`);
    },
  },
  {
    name: 'a page that warns ABOUT prize scams, on an unfamiliar website: no warning signs',
    input: page({ url: 'https://seniors-news.example/', title: 'Prize scams', text: 'Scammers say "you have won, pay a fee to claim your prize." Report scams to the police.' }),
    expect: r => assert.strictEqual(r.verdict, 'no_warning_signs'),
  },
  {
    name: '...but the same words on a website pretending to be Amazon still get a warning',
    input: page({ url: 'https://amazon-rewards.example/', title: 'Prize scams', text: 'Scammers say "you have won, pay a fee to claim your prize." Report scams to the police.' }),
    expect: r => assert.strictEqual(r.verdict, 'warn'),
  },
  {
    name: 'sender name says PayPal, someone else\'s address: check first; as an account alert: stop',
    input: email({ name: 'PayPal', address: 'alerts@mail.example', text: 'Hello.' }),
    expect: r => {
      assert.strictEqual(r.recommendedAction, 'VERIFY_INDEPENDENTLY');
      const alert = analyze(email({ name: 'PayPal', address: 'alerts@mail.example', subject: 'Unusual sign-in activity', text: 'Urgent: reply today.' }));
      assert.strictEqual(alert.recommendedAction, 'GO_BACK');
    },
  },
  {
    name: 'a scam pop-up added at the END of a long page is still read',
    input: page({ url: 'https://recipes.example/soup', title: 'Soup', text: 'Simmer the soup. '.repeat(1000) + 'Virus detected! Your computer is infected. Call (800) 555-0142. Do not close this page.' }),
    expect: r => assert.deepStrictEqual([r.verdict, r.recommendedAction], ['warn', 'GO_BACK']),
  },
  {
    name: 'a card-number form named "hasPayment" (the other branch\'s scanner) counts like "hasPaymentField"',
    input: page({ url: 'https://shop.netlify.app/pay', title: 'Checkout', forms: [{ action: 'https://shop.netlify.app/pay', hasPassword: false, hasPayment: true }] }),
    expect: r => assert.ok(codes(r).includes('SIGN_IN_ON_FREE_HOSTING')),
  },
];

// ---------- context: email services, ad networks, and kinds of message ----------
const CONTEXT_TESTS = [
  ['a store newsletter whose links go through an email-tracking service: never stopped, and the reason says why', () => {
    const r = analyze(email({ name: 'Garden Store', address: 'news@garden-store.example', subject: 'Spring sale', text: '20% off. Unsubscribe.', links: [{ text: 'www.garden-store.example', url: 'https://u123.ct.sendgrid.net/ls/click?upn=abc' }] }));
    assert.notStrictEqual(r.recommendedAction, 'GO_BACK');
    assert.match(explanationOf(r, 'HIDDEN_DESTINATION'), /sendgrid\.net, a service that counts clicks/);
  }],
  ['a real IRS newsletter sent through GovDelivery: no warning signs', () => {
    const r = analyze(email({ name: 'IRS', address: 'irs@service.govdelivery.com', subject: 'IRS Tax Tips', text: 'IRS Tax Tip: free filing options. Unsubscribe or manage preferences.', links: [{ text: 'Read more', url: 'https://www.irs.gov/newsroom' }] }));
    assert.strictEqual(r.verdict, 'no_warning_signs');
  }],
  ['"pay or be arrested" from the "IRS": the explanation names the payment demand, the threat, and the agency rule', () => {
    const r = analyze(email({ name: 'IRS Collections', address: 'collections@irs-gov.example', subject: 'Final notice', text: 'You owe back taxes. Pay the outstanding balance today or a warrant will be issued for your arrest.' }));
    assert.strictEqual(r.recommendedAction, 'GO_BACK');
    for (const c of ['PAYMENT_DEMAND', 'URGENT_PAYMENT_REQUEST', 'AGENCY_DOES_NOT_EMAIL']) assert.ok(codes(r).includes(c), `missing ${c}: ${codes(r)}`);
  }],
  ['company name on someone else\'s address: weak in a newsletter, moderate in an account alert', () => {
    const tierOf = r => (r.reasons.find(x => x.code === 'SENDER_NAME_MISMATCH') || {}).explanation;
    const newsletter = analyze(email({ name: 'Netflix', address: 'deals@partner-offers.example', subject: 'New this week', text: 'Shop now. Unsubscribe.' }));
    const alert = analyze(email({ name: 'Netflix', address: 'billing@partner-offers.example', subject: 'Payment declined', text: 'Update your payment details.' }));
    assert.match(tierOf(newsletter), /this alone isn't proof/);
    assert.match(tierOf(alert), /account or payment notice/);
    assert.strictEqual(newsletter.recommendedAction, 'VERIFY_INDEPENDENTLY');
  }],
  ['a Google ad click with its destination written in: checked where it really goes', () => {
    const r = analyze(link('https://www.googleadservices.com/pagead/aclk?sa=L&adurl=' + encodeURIComponent('https://paypal.com.rewards.example/claim'), 'Claim'));
    assert.ok(codes(r).includes('LOOKALIKE_DOMAIN'), codes(r).join(','));
  }],
  ['a scam ad through an ad network: still stopped by its wording, and the reason says we couldn\'t see the destination', () => {
    const r = analyze(link('https://www.googleadservices.com/pagead/aclk?sa=L&ai=abc', 'Claim now', 'Congratulations! You have won a $2,000 gift card. Claim before midnight.', { insideFrame: true }));
    assert.strictEqual(r.recommendedAction, 'GO_BACK');
    assert.match(explanationOf(r, 'UNVERIFIED_PRIZE_CLAIM'), /passes through googleadservices\.com/);
  }],
  ['a real Amazon ad through an ad network: no warning signs', () => {
    const r = analyze(link('https://www.googleadservices.com/pagead/aclk?sa=L&ai=abc', 'Shop now', 'Amazon Prime Day: deals on Echo devices. Shop now.', { insideFrame: true }));
    assert.strictEqual(r.verdict, 'no_warning_signs');
  }],
  ['a fake "googleadservices" on another website is neither followed nor excused as an ad network', () => {
    const r = analyze(link('https://googleadservices.com.evil.example/pagead/aclk?adurl=https://www.amazon.com/', 'www.amazon.com'));
    assert.ok(explanationOf(r, 'HIDDEN_DESTINATION'), `got: ${codes(r)}`);
    assert.doesNotMatch(explanationOf(r, 'HIDDEN_DESTINATION'), /counts clicks/);
  }],
];

// ---------- Phase 4 acceptance: one rule engine for a webpage, an ad, and a Gmail message ----------
// The same USPS "redelivery fee" scam, as each adapter would collect it, and a real USPS version of each.
const readFixture = name => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'inputs', name), 'utf8'));
const SAME_SCAM = {
  webpage: analyze(readFixture('webpage-delivery-fee.json')),
  ad: analyze(readFixture('ad-delivery-fee.json')),
  gmail: analyze(readFixture('email-delivery-fee.json')),
};
const REAL_USPS = {
  webpage: analyze(page({ url: 'https://tools.usps.com/redelivery', title: 'USPS - Schedule a Redelivery', headings: ['Redelivery'], text: 'Enter your tracking number to schedule a redelivery.', forms: [{ action: 'https://tools.usps.com/redelivery', hasPassword: false, hasPaymentField: true }] })),
  ad: analyze(link('https://www.googleadservices.com/pagead/aclk?sa=L&ai=xyz', 'Sign up', 'USPS Informed Delivery: see your mail before it arrives. Sign up free.', { insideFrame: true })),
  gmail: analyze(email({ name: 'USPS Informed Delivery', address: 'USPSInformeddelivery@email.informeddelivery.usps.com', subject: 'Your Daily Digest', text: 'You have 2 mailpieces and 1 package arriving today.', links: [{ text: 'See all', url: 'https://informeddelivery.usps.com/box' }] })),
};
const PHASE4_TESTS = [
  ['the scam is stopped on all three, and never "confirmed" (no known-threat match)', () => {
    for (const [where, r] of Object.entries(SAME_SCAM)) {
      assert.deepStrictEqual(validateResult(r), [], `${where}: breaks the contract`);
      assert.strictEqual(r.verdict, 'warn', where);
      assert.ok(['GO_BACK', 'DO_NOT_ENTER_INFO'].includes(r.recommendedAction), `${where}: ${r.recommendedAction}`);
    }
    assert.strictEqual(SAME_SCAM.webpage.recommendedAction, 'DO_NOT_ENTER_INFO', 'a payment page should say "do not enter info"');
  }],
  ['the same signs are found everywhere, with the same title and the same words', () => {
    for (const code of ['LOOKALIKE_DOMAIN', 'DELIVERY_PROBLEM_CLAIM', 'URGENT_PAYMENT_REQUEST']) {
      const found = Object.entries(SAME_SCAM).map(([where, r]) => [where, r.reasons.find(x => x.code === code)]);
      for (const [where, reason] of found) assert.ok(reason, `${where} is missing ${code}`);
      assert.strictEqual(new Set(found.map(([, x]) => x.title)).size, 1, `${code} has different titles`);
      if (code !== 'LOOKALIKE_DOMAIN') assert.strictEqual(new Set(found.map(([, x]) => x.explanation)).size, 1, `${code} reads differently`);
    }
    // The address sign names the same company and website everywhere; only "this website" / "a link" differs.
    for (const r of Object.values(SAME_SCAM)) assert.match(explanationOf(r, 'LOOKALIKE_DOMAIN'), /USPS.*usps-redelivery\.example|usps-redelivery\.example.*USPS/);
  }],
  ['each adapter\'s own information shows up only where it belongs', () => {
    assert.ok(codes(SAME_SCAM.gmail).includes('SENDER_NAME_MISMATCH'), 'Gmail: the sender');
    assert.ok(codes(SAME_SCAM.gmail).includes('BRAND_NAME_MISMATCH'), 'Gmail: links vs the company it claims');
    assert.ok(codes(SAME_SCAM.webpage).includes('CREDENTIALS_SENT_ELSEWHERE'), 'webpage: where the card number goes');
    assert.ok(codes(SAME_SCAM.webpage).includes('FAKE_SIGN_IN_PAGE'), 'webpage: USPS payment page off USPS');
    assert.ok(codes(SAME_SCAM.ad).includes('BRAND_NAME_MISMATCH'), 'ad: the ad names USPS, the link goes elsewhere');
    for (const c of ['SENDER_NAME_MISMATCH', 'CREDENTIALS_SENT_ELSEWHERE']) assert.ok(!codes(SAME_SCAM.ad).includes(c), `ad has ${c}`);
    assert.ok(!codes(SAME_SCAM.webpage).includes('SENDER_NAME_MISMATCH'));
  }],
  ['the real USPS webpage, ad, and email get no warning signs', () => {
    for (const [where, r] of Object.entries(REAL_USPS)) assert.strictEqual(r.verdict, 'no_warning_signs', `${where}: ${codes(r)}`);
  }],
];

// ---------- the same evidence through every adapter gives the same words ----------
// An adapter is anything that collects evidence: page.js, the other branch's
// page scanner, the click guard, the Gmail reader.
const ADAPTER_PAGE = { url: 'https://paypal-verify.example/', title: 'PayPal: Log in', headings: 'PayPal', text: 'Enter your password. You have won! Act now.', hasPassword: true, formActions: ['https://collect.example/p'] };
const viaContract = analyze(page({ url: ADAPTER_PAGE.url, title: ADAPTER_PAGE.title, headings: [ADAPTER_PAGE.headings], text: ADAPTER_PAGE.text, forms: [passwordForm('https://collect.example/p')] }));
// The other branch's scanner: hasPayment, method, fieldCount, scan/truncated, no mainHeadings.
const viaOtherScanner = analyze({
  source: 'webpage', pageUrl: ADAPTER_PAGE.url, pageTitle: ADAPTER_PAGE.title, visibleText: `${ADAPTER_PAGE.headings} ${ADAPTER_PAGE.text}`, links: [],
  forms: [{ action: 'https://collect.example/p', method: 'post', fieldCount: 2, hasPassword: true, hasPayment: false }],
  context: { scan: 'initial', truncated: { text: false, links: false } },
});
const viaLegacyPage = analyzePage(ADAPTER_PAGE);
const SHARED_LINK = { text: 'www.chase.com', url: 'https://chase-secure.example/verify' };
const linkViaClick = analyze(link(SHARED_LINK.url, SHARED_LINK.text));
const linkViaEmail = analyze(email({ links: [SHARED_LINK] }));
const linkViaLegacyGuard = analyzeLink({ text: SHARED_LINK.text, href: SHARED_LINK.url }, { pageUrl: PAGE_URL });
const explanationOf = (r, code) => (r.reasons.find(x => x.code === code) || {}).explanation;
const ADAPTER_TESTS = [
  ['page: contract input, the other branch\'s scanner, and old page.js give the same verdict', () => {
    assert.deepStrictEqual([viaOtherScanner.verdict, viaOtherScanner.recommendedAction], [viaContract.verdict, viaContract.recommendedAction]);
    assert.strictEqual(viaLegacyPage.action, 'warn');
  }],
  ['page: same reasons, same words, same order', () => {
    assert.deepStrictEqual(viaOtherScanner.reasons, viaContract.reasons);
    assert.deepStrictEqual(viaLegacyPage.reasons, viaContract.reasons.map(r => r.explanation));
  }],
  ['link: clicked, inside an email, and old guard.js explain each shared sign the same way', () => {
    for (const code of ['HIDDEN_DESTINATION', 'LOOKALIKE_DOMAIN']) {
      assert.ok(explanationOf(linkViaClick, code), `click missing ${code}`);
      assert.strictEqual(explanationOf(linkViaEmail, code), explanationOf(linkViaClick, code));
      assert.ok(linkViaLegacyGuard.reasons.includes(explanationOf(linkViaClick, code)));
    }
  }],
  ['every reason code has ONE title, whatever found it', () => {
    const titles = {};
    const all = [viaContract, viaOtherScanner, linkViaClick, linkViaEmail, ...COMBINED_TESTS.map(t => analyze(t.input))];
    for (const r of all) for (const x of r.reasons) {
      titles[x.code] = titles[x.code] || x.title;
      assert.strictEqual(x.title, titles[x.code], `${x.code} has two titles`);
    }
  }],
  ['the same input always gives the same result', () => {
    for (const t of COMBINED_TESTS) assert.deepStrictEqual(analyze(t.input), analyze(t.input));
  }],
];

// ---------- remote lookups ----------
const TRUSTED = { name: 'test service', trusted: true };
const UNTRUSTED = { name: 'unchecked feed', trusted: false };
const plainLink = link('https://garden-store.example/sale', 'Shop the sale');
const suspiciousLink = link('https://bit.ly/abc', 'Open');
const LOOKUP_TESTS = [
  ['a clean link: open now, a lookup may run alongside', () => assert.strictEqual(whenToLookUp(analyze(plainLink)), 'optional')],
  ['a link with warning signs: hold the click until the lookup answers', () => assert.strictEqual(whenToLookUp(analyze(suspiciousLink)), 'before_opening')],
  ['a link we already stop: no need to wait for a lookup', () => assert.strictEqual(whenToLookUp(analyze(link('https://paypal.com.x.example/'))), 'not_needed')],
  ['a blocked link: no need to wait', () => assert.strictEqual(whenToLookUp(analyze(link('https://known-phish.example/'))), 'not_needed')],
  ['lookup match from a trusted service: block', () =>
    assert.strictEqual(analyze(plainLink, { lookup: { status: 'match', url: 'https://garden-store.example/sale', source: TRUSTED } }).verdict, 'block')],
  ['lookup match from an untrusted feed: stop, but no block', () =>
    assert.deepStrictEqual(Object.values((({ verdict, recommendedAction }) => ({ verdict, recommendedAction }))(analyze(plainLink, { lookup: { status: 'match', url: 'https://garden-store.example/sale', source: UNTRUSTED } }))), ['warn', 'GO_BACK'])],
  ['"not on the list" never removes warning signs found here', () =>
    assert.deepStrictEqual(analyze(suspiciousLink, { lookup: { status: 'no_match', url: 'https://bit.ly/abc', source: TRUSTED } }), analyze(suspiciousLink))],
  ['a lookup error changes nothing (the click stays held by the browser side)', () =>
    assert.deepStrictEqual(analyze(suspiciousLink, { lookup: { status: 'error' } }), analyze(suspiciousLink))],
  ['a lookup error never turns a clean link into "verified": still no_warning_signs, never more', () =>
    assert.deepStrictEqual(analyze(plainLink, { lookup: { status: 'error' } }), analyze(plainLink))],
  ['lookup results follow the contract', () =>
    assert.deepStrictEqual(validateResult(analyze(plainLink, { lookup: { status: 'match', url: 'https://garden-store.example/sale', source: TRUSTED } })), [])],
];

// ---------- the shared fixtures (tests/fixtures/inputs) ----------
const FIXTURE_EXPECTED = {
  'email-fake-paypal.json': ['warn', 'GO_BACK'],
  'email-friend.json': ['no_warning_signs', 'NONE'],
  'link-in-scam-email.json': ['warn', 'GO_BACK'],
  'link-news-headline.json': ['no_warning_signs', 'NONE'],
  'link-prize-ad.json': ['warn', 'GO_BACK'],
  'webpage-fake-sign-in.json': ['warn', 'DO_NOT_ENTER_INFO'],
  'webpage-library-sign-in.json': ['no_warning_signs', 'NONE'],
  'webpage-prize-offer.json': ['warn', 'GO_BACK'],
  'webpage-delivery-fee.json': ['warn', 'DO_NOT_ENTER_INFO'],
  'ad-delivery-fee.json': ['warn', 'GO_BACK'],
  'email-delivery-fee.json': ['warn', 'GO_BACK'],
};

// ---------- run everything ----------

let passed = 0;
let total = 0;
const tally = { scams: 0, caught: 0, normal: 0, falseAlarms: 0 };

function check(name, fn) {
  total++;
  try {
    fn();
    passed++;
    console.log(`PASS  ${name}`);
  } catch (err) {
    console.log(`FAIL  ${name}: ${err.message}`);
    process.exitCode = 1;
  }
}

console.log('--- reading addresses ---');
for (const [name, actual, expected] of normalizerChecks) {
  check(`[address] ${name}`, () => assert.deepStrictEqual(actual, expected));
}

console.log('\n--- every rule ---');
for (const rule of RULE_TESTS) {
  rule.triggers.forEach((input, i) => check(`[rule] ${rule.code} triggers (${i + 1})`, () => {
    const result = analyze(input);
    assert.deepStrictEqual(validateResult(result), [], 'result breaks the contract');
    assert.ok(result.reasons.some(r => r.code === rule.code), `got: ${result.reasons.map(r => r.code).join(', ') || result.verdict}`);
  }));
  rule.doesNot.forEach((input, i) => check(`[rule] ${rule.code} does not trigger (${i + 1})`, () => {
    const result = analyze(input);
    assert.deepStrictEqual(validateResult(result), [], 'result breaks the contract');
    assert.ok(!result.reasons.some(r => r.code === rule.code), `got: ${result.reasons.map(r => r.code).join(', ')}`);
  }));
}

console.log('\n--- which combinations lead to which verdict ---');
for (const [name, findings, source, expected, opts] of POLICY_TESTS) {
  check(`[policy] ${name}`, () => {
    const d = decide(findings, source, opts);
    assert.deepStrictEqual([d.verdict, d.recommendedAction], expected);
  });
}

console.log('\n--- several rules at once ---');
for (const t of COMBINED_TESTS) {
  check(`[combined] ${t.name}`, () => {
    const r = analyze(t.input);
    assert.deepStrictEqual(validateResult(r), [], 'result breaks the contract');
    t.expect(r);
  });
}

console.log('\n--- context: email services, ad networks, kinds of message ---');
for (const [name, fn] of CONTEXT_TESTS) check(`[context] ${name}`, fn);

console.log('\n--- Phase 4: one engine for a webpage, an ad, and a Gmail message ---');
for (const [name, fn] of PHASE4_TESTS) check(`[phase 4] ${name}`, fn);

console.log('\n--- same evidence, every adapter ---');
for (const [name, fn] of ADAPTER_TESTS) check(`[adapter] ${name}`, fn);

console.log('\n--- remote lookups ---');
for (const [name, fn] of LOOKUP_TESTS) check(`[lookup] ${name}`, fn);

console.log('\n--- every rule has tests, words, points, and a place in the contract ---');
const contractTiers = Object.fromEntries([...fs.readFileSync(path.join(__dirname, '..', 'docs', 'interfaces.md'), 'utf8')
  .matchAll(/^\| `([A-Z_]+)` \| ([a-z]+) \|/gm)].map(m => [m[1], m[2]]));
const tested = new Set(RULE_TESTS.map(r => r.code));
for (const code of Object.keys(EXPLANATIONS)) {
  check(`[coverage] ${code}`, () => {
    assert.ok(REASON_CODES.has(code), 'missing from the reason-code table in docs/interfaces.md');
    assert.ok(RULES[code], 'missing points in risk-policy.js');
    assert.strictEqual(contractTiers[code], RULES[code].tier, 'tier in docs/interfaces.md differs from risk-policy.js');
    assert.ok(tested.has(code), 'no trigger / no-trigger test in RULE_TESTS');
  });
}
check('[coverage] every code in risk-policy.js has words in explanations.js', () =>
  assert.deepStrictEqual(Object.keys(RULES).filter(code => !EXPLANATIONS[code]), []));

console.log('\n--- shared fixtures ---');
const fixtureDir = path.join(__dirname, 'fixtures', 'inputs');
for (const file of fs.readdirSync(fixtureDir).filter(f => f.endsWith('.json')).sort()) {
  check(`[fixture] ${file}`, () => {
    const expected = FIXTURE_EXPECTED[file];
    assert.ok(expected, 'add the expected verdict to FIXTURE_EXPECTED');
    const result = analyze(JSON.parse(fs.readFileSync(path.join(fixtureDir, file), 'utf8')));
    assert.deepStrictEqual(validateResult(result), [], 'result breaks the contract');
    assert.deepStrictEqual([result.verdict, result.recommendedAction], expected);
  });
}

console.log('\n--- bad input never crashes ---');
for (const [name, input] of [['nothing', undefined], ['not an object', 'hello'], ['unknown source', { source: 'fax' }], ['links is not a list', { source: 'link', links: 'x', context: {} }]]) {
  check(`[robust] ${name}`, () => assert.deepStrictEqual(validateResult(analyze(input)), []));
}
check('[robust] unknown source -> "unknown"', () => assert.strictEqual(analyze({ source: 'fax' }).verdict, 'unknown'));

console.log('\n--- examples (older API, used by the browser code today) ---');
function runExample(group, c, result, flagged) {
  if (c.scam) { tally.scams++; if (flagged) tally.caught++; } else { tally.normal++; if (flagged) tally.falseAlarms++; }
  check(`[${group}] ${c.name}  (${result.level}, ${result.action}, ${result.score} points)`, () => {
    if (c.expect) assert.strictEqual(result.level, c.expect, `expected ${c.expect}, got ${result.level}`);
    if (c.expectAction) assert.strictEqual(result.action, c.expectAction, `expected action ${c.expectAction}, got ${result.action}`);
    if (c.expectReason) assert.ok(result.reasons.some(r => c.expectReason.test(r)), `missing reason ${c.expectReason}`);
    if (c.expectNoReason) assert.ok(!result.reasons.some(r => c.expectNoReason.test(r)), `unexpected reason ${c.expectNoReason}`);
  });
}
for (const c of emailCases) {
  const result = analyzeEmail(c.email);
  runExample('email', c, result, result.level !== 'low');
}
for (const c of linkCases) {
  const result = analyzeLink(c.link, c.context);
  runExample('link', c, result, result.action !== 'allow');
}
for (const c of pageCases) {
  const result = analyzePage(c.page);
  runExample('page', c, result, result.action !== 'allow');
}

console.log(`\n${passed}/${total} tests passed`);
console.log(`Scams caught:          ${tally.caught}/${tally.scams}`);
console.log(`False alarms (normal): ${tally.falseAlarms}/${tally.normal}`);
