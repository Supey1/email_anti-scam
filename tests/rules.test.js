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
const { analyze, analyzeEmail, analyzeLink, analyzePage } = require(path.join(__dirname, '..', 'extension', 'rules.js'));
const norm = require(path.join(__dirname, '..', 'extension', 'core', 'url-normalizer.js'));
const { EXPLANATIONS } = require(path.join(__dirname, '..', 'extension', 'core', 'explanations.js'));
const { RULES } = require(path.join(__dirname, '..', 'extension', 'core', 'risk-policy.js'));
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
    triggers: [link('https://login.known-phish.example/x')],
    doesNot: [link('https://known-phish-news.example/'), link('https://known-phish.example.other.example/')] },
  { code: 'LOOKALIKE_DOMAIN',
    triggers: [link('https://paypa1-secure.example/login'), link('https://paypal.com.fake-domain.example/'), link('https://xn--pypal-4ve.example/'), link('https://amazom.example/'), link('https://applesupport.example/')],
    doesNot: [link('https://www.paypal.com/signin'), link('https://www.paypal.co.uk/'), link('https://applebees.example/'), link('https://bucket.s3.amazonaws.com/file'), link('https://purchase-confirm.example/')] },
  { code: 'HIDDEN_DESTINATION',
    triggers: [link('https://evil.example/', 'www.chase.com')],
    doesNot: [link('https://secure.chase.com/x', 'www.chase.com'), link('https://news.bbc.co.uk/x', 'bbc.co.uk')] },
  { code: 'MISLEADING_URL',
    triggers: [link('https://www.paypal.com@evil.example/'), link('https://evil.example/www.paypal.com/signin')],
    doesNot: [link('https://www.paypal.com/signin'), link('https://reviews.example/paypal-review')] },
  { code: 'NUMBER_ADDRESS',
    triggers: [link('http://192.168.4.20/login'), link('http://3232235777/')],
    doesNot: [link('https://route-192.example/')] },
  { code: 'BRAND_NAME_MISMATCH',
    triggers: [link('https://parcel.example/x', 'Track with FedEx')],
    doesNot: [link('https://www.fedex.com/track', 'Track with FedEx')] },
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
    triggers: [email({ name: 'PayPal', address: 'alerts@mail.example' })],
    doesNot: [email({ name: 'PayPal', address: 'service@paypal.com' })] },
  { code: 'LOOKALIKE_SENDER',
    triggers: [email({ name: 'Alerts', address: 'alerts@paypa1-secure.example' })],
    doesNot: [email({ name: 'Alerts', address: 'alerts@paypal.com' }), email({ name: 'Tommy', address: 'tommy@gmail.com' })] },
  { code: 'COMPANY_ON_FREE_EMAIL',
    triggers: [email({ name: 'Billing Department', address: 'billing.dept@gmail.com' })],
    doesNot: [email({ name: 'Linda', address: 'linda@gmail.com' })] },
  { code: 'FAKE_SIGN_IN_PAGE',
    triggers: [FAKE_BANK_LOGIN],
    doesNot: [BANK_SECURITY_ARTICLE, page({ url: 'https://connect.secure.wellsfargo.com/auth', title: 'Wells Fargo Sign On', forms: [passwordForm('https://connect.secure.wellsfargo.com/auth')] })] },
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
    triggers: [page({ url: 'https://winner.example/', text: 'You have won! Pay a $4.99 processing fee to claim your prize.' })],
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
  { code: 'PRESSURE_TACTICS',
    triggers: [email({ text: 'Act now, this is urgent.' })],
    doesNot: [email({ text: 'No rush, whenever you have time.' })] },
  { code: 'INSIDE_SCAM_EMAIL',
    triggers: [link('https://plain.example/', 'Click here', '', { surroundingResult: { verdict: 'warn', recommendedAction: 'GO_BACK' } })],
    doesNot: [link('https://plain.example/', 'Click here', '', { surroundingResult: { verdict: 'warn', recommendedAction: 'VERIFY_INDEPENDENTLY' } })] },
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

console.log('\n--- every rule has tests, words, points, and a place in the contract ---');
const tested = new Set(RULE_TESTS.map(r => r.code));
for (const code of Object.keys(EXPLANATIONS)) {
  check(`[coverage] ${code}`, () => {
    assert.ok(REASON_CODES.has(code), 'missing from the reason-code table in docs/interfaces.md');
    assert.ok(RULES[code], 'missing points in risk-policy.js');
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
