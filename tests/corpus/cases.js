// The labelled test set for measuring accuracy (see docs/testing.md).
// EVERY address and name here is made up (".example" domains). No real scam links, no real accounts.
//
// Each case says what a careful person would conclude, written BEFORE looking at what the analyzer does:
//   label:         'scam' or 'legit'
//   blockCriteria: (scam cases) true if a hard block is deserved. The contract (docs/interfaces.md) reserves
//                  "block" for confirmed evidence: the destination is on a trusted list of known dangerous websites.
//   stopCriteria:  (scam cases) true if the warning should INTERRUPT (stop a click or cover a page: GO_BACK or
//                  DO_NOT_ENTER_INFO): a known brand is impersonated AND the destination is not that brand's, OR
//                  two or more independent strong signs appear together (for example, a gift-card payment request
//                  plus a request for secrecy), OR a block. Weaker scams should still be mentioned, without interrupting.
//   explain:       what the warning must mention to be accurate (checked against the top 3 reasons shown)
//   forbid:        claims the warning must NOT make (a wrong explanation is worse than a missing one)
//   hard:          true for cases written to be difficult (scams with no usual wording, honest-looking mistakes)
//
// This set was written alongside development, so it is a development set, not an independent one:
// results on it show what works and what does not, not how well the extension will do in the world.

const email = (id, label, summary, senderName, senderEmail, subject, text, links = [], extra = {}) =>
  ({ id, kind: 'email', label, summary, input: { senderName, senderEmail, subject, text, links }, ...extra });
const page = (id, label, summary, url, title, text, extra = {}) =>
  ({ id, kind: 'webpage', label, summary, input: { url, title, text, links: extra.links || [], forms: extra.forms || [], ads: extra.ads || [] }, ...extra.meta });
const ad = (id, label, summary, text, linkText, linkUrl, extra = {}) =>
  ({ id, kind: 'ad', label, summary, input: { pageUrl: 'https://news.example/story', text, link: [linkText, linkUrl] }, ...extra });
const link = (id, label, summary, text, href, extra = {}) =>
  ({ id, kind: 'link', label, summary, input: { text, href }, ...extra });

const cases = [
  // ---------------- scam emails ----------------
  email('S-E01', 'scam', 'Fake PayPal "account suspended" from a look-alike address', 'PayPal Security', 'alerts@paypa1-secure.xyz', 'Your account has been suspended',
    'We noticed unusual activity. Verify your account within 24 hours or it will be closed.', [['www.paypal.com', 'http://paypa1-secure.xyz/login']],
    { stopCriteria: true, explain: [/PayPal/], forbid: [/Amazon|Chase|Netflix/] }),
  email('S-E02', 'scam', 'Grandparent scam: bail money, gift cards, secrecy', 'Tommy', 'tommy83920@gmail.com', 'Grandma please help',
    "Grandma, I was in an accident and need bail money. Please buy gift cards and don't tell mom.", [],
    { stopCriteria: true, explain: [/gift cards|secret|family member/i] }),
  email('S-E03', 'scam', 'Fake Microsoft support from a free address', 'Microsoft Support', 'ms.helpdesk@outlook.com', 'Your computer has been infected',
    'Your computer is infected with a virus. Call tech support immediately.', [], { stopCriteria: true, explain: [/Microsoft/], forbid: [/PayPal/] }),
  email('S-E04', 'scam', 'Delivery notice with a shortened link', 'Delivery Notice', 'notice@parcel-update.example', 'Package on hold',
    'Your package could not be delivered. Click below to reschedule.', [['Reschedule delivery', 'https://bit.ly/fake-test-link']], { stopCriteria: false, explain: [/package|shortened/i] }),
  email('S-E05', 'scam', 'Fake IRS refund with a look-alike link', 'IRS Refunds', 'refund@irs-refund-center.example', 'You have a tax refund waiting',
    'Claim your refund now. Verify your identity and enter your social security number.', [['Claim refund', 'https://irs-refund-center.example/claim']],
    { stopCriteria: true, explain: [/IRS/], forbid: [/PayPal|Amazon/] }),
  email('S-E06', 'scam', 'Lottery win that asks for a gift-card "fee"', 'Prize Office', 'office@lucky-draw.example', 'You have won!',
    'You have won the lottery! To release your prize, send a gift card for the processing fee.', [], { stopCriteria: true, explain: [/won|gift card/i] }),
  email('S-E07', 'scam', 'Inheritance and bank account number request', 'Barrister Collins', 'collins.law@mail.example', 'Unclaimed funds in your name',
    'You are the sole beneficiary of an inheritance. Reply with your bank account number and date of birth to proceed.', [], { stopCriteria: true, explain: [/won|owed|private information|account/i] }),
  email('S-E08', 'scam', 'Fake Amazon order with a number-address link', 'Amazon Orders', 'orders@amazon-orders.example', 'Your order cannot be shipped',
    'Please update your payment method.', [['Update payment', 'http://203.0.113.9/amazon/pay']], { stopCriteria: true, explain: [/number address|Amazon/i] }),
  email('S-E09', 'scam', 'Crypto "guaranteed returns"', 'Alex Invest', 'alex@fast-returns.example', 'Double your bitcoin',
    'Send bitcoin today for guaranteed returns of 200%.', [], { stopCriteria: false, explain: [/crypto|gift cards|wire/i] }),
  email('S-E10', 'scam', 'HARD: polite "shared invoice" phishing with no usual wording', 'Morgan Lee', 'morgan.lee@docs-share-portal.example', 'Invoice 4471',
    'Hi, please review the invoice I shared with you when you have a moment.', [['View invoice', 'https://docs-share-portal.example/inv/4471']], { stopCriteria: false, hard: true }),
  email('S-E11', 'scam', 'Fake bank, link text hides the real destination', 'Chase Alerts', 'alerts@chase-verify.example', 'Action needed on your account',
    'Please sign in to review a recent charge.', [['www.chase.com/review', 'https://secure-review.example/login']], { stopCriteria: true, explain: [/Chase|really goes to/i] }),
  email('S-E12', 'scam', 'Fake Netflix billing on a risky ending', 'Netflix Billing', 'billing@netflix-help.top', 'Payment failed',
    'Update your payment to keep watching.', [['Update payment', 'https://netflix-billing-help.top/pay']], { stopCriteria: true, explain: [/Netflix/] }),
  email('S-E13', 'scam', 'Fake Apple ID lock', 'Apple Support', 'support@apple-id-verify.example', 'Your Apple ID is locked',
    'Your Apple ID is locked. Confirm your account.', [['Unlock', 'https://apple-id-verify.example/unlock']], { stopCriteria: true, explain: [/Apple/] }),
  email('S-E14', 'scam', 'USPS customs fee from a free mail address', 'USPS Tracking', 'usps.tracking@gmail.com', 'Customs fee due',
    'Your package is on hold. Pay the customs fee to reschedule delivery.', [], { stopCriteria: true, explain: [/USPS|Post Office|package/i] }),
  email('S-E15', 'scam', 'Stranded abroad, Western Union, keep it quiet', 'Nephew David', 'david.travel99@mail.example', 'Stuck in another country',
    "I'm stranded and need money by Western Union today. Please don't tell anyone, keep this a secret.", [], { stopCriteria: true, explain: [/wire|gift|secret/i] }),
  email('S-E16', 'scam', 'Fake Wells Fargo alert', 'Wells Fargo', 'alerts@wellsfargo-secure.example', 'Unusual sign-in activity',
    'We detected unusual activity. Verify your account.', [['Review activity', 'https://wellsfargo-secure.example/review']], { stopCriteria: true, explain: [/Wells Fargo/] }),
  email('S-E17', 'scam', 'HARD: vague parcel message, shortened link', 'Courier', 'courier@parcel-desk.example', 'Your parcel',
    'Your parcel is waiting. Tap to choose a delivery time.', [['Choose time', 'https://tinyurl.com/x9test']], { stopCriteria: false, explain: [/shortened/i], hard: true }),
  email('S-E18', 'scam', 'HARD: voicemail lure to an unknown site', 'Voice Service', 'noreply@voice-msg.example', 'New voicemail',
    'You have a new voicemail. Listen now.', [['Play message', 'https://voice-msg.example/play/88']], { stopCriteria: false, hard: true }),
  email('S-E19', 'scam', 'HARD: QR code lure with no link', 'Account Team', 'team@secure-notice.example', 'Action required',
    'Scan the QR code below to confirm your details.', [], { stopCriteria: false, hard: true }),

  // ---------------- legitimate emails ----------------
  email('L-E01', 'legit', 'Real PayPal receipt', 'PayPal', 'service@paypal.com', 'Your receipt from Coffee Shop',
    'You sent a payment of $4.50. View your activity anytime.', [['View activity', 'https://www.paypal.com/myaccount/activity']]),
  email('L-E02', 'legit', 'Friend asking about lunch', 'Linda', 'linda.m@gmail.com', 'Lunch Saturday?', 'Are you free for lunch on Saturday? The new diner opened on Main Street.'),
  email('L-E03', 'legit', 'Real bank statement notice', 'Chase', 'no-reply@chase.com', 'Your statement is ready',
    'Your June statement is ready to view.', [['View statement', 'https://www.chase.com/statements']]),
  email('L-E04', 'legit', 'Google password reset ("verify your identity")', 'Google', 'no-reply@accounts.google.com', 'Password reset requested',
    'Someone asked to reset your password. Verify your identity to continue.', [['Reset password', 'https://accounts.google.com/reset']]),
  email('L-E05', 'legit', 'Real Amazon shipping notice', 'Amazon.com', 'shipment-tracking@amazon.com', 'Your package has shipped',
    'Your package will arrive Thursday.', [['Track package', 'https://www.amazon.com/progress-tracker']]),
  email('L-E06', 'legit', 'Friend\'s newsletter with a shortened link', 'Ruth', 'ruth.k@gmail.com', 'Garden club photos', 'Here are the photos from Saturday.', [['Photos', 'https://bit.ly/garden-photos']]),
  email('L-E07', 'legit', 'Grandchild mentions a gift card for a birthday', 'Emma', 'emma.t@gmail.com', 'Happy birthday Grandma!', 'I bought you a gift card for the bookstore. See you Sunday!'),
  email('L-E08', 'legit', 'Doctor\'s office reminder', 'Valley Clinic', 'reminders@valleyclinic.example', 'Appointment tomorrow', 'Please confirm your appointment for tomorrow at 10am. If you cannot come, call us immediately.'),
  email('L-E09', 'legit', 'Real Netflix payment reminder', 'Netflix', 'info@netflix.com', 'Update your payment method', 'Please update your payment method to keep watching.', [['Update', 'https://www.netflix.com/youraccount']]),
  email('L-E10', 'legit', 'Real UPS delivery notice', 'UPS', 'pkginfo@ups.com', 'Delivery update', 'Your package could not be delivered. You can reschedule delivery online.', [['Reschedule', 'https://www.ups.com/track']]),
  email('L-E11', 'legit', 'Church volunteer sign-up, urgent', 'St. Mark Office', 'office@stmark.example', 'Urgent: volunteers needed', 'We urgently need volunteers for Saturday. Reply today!'),
  email('L-E12', 'legit', 'Utility bill mentioning an account number', 'City Water', 'billing@citywater.example', 'Your water bill', 'Your account number ends in 1234. Pay online anytime.', [['Pay online', 'https://pay.citywater.example/bill']]),
  email('L-E13', 'legit', 'News digest whose tracking links hide the destination', 'Daily Digest', 'digest@dailydigest.example', 'Your morning digest', 'Top story below.', [['Read the full story at nytimes.com', 'https://links.dailydigest.example/c/abc']]),
  email('L-E14', 'legit', 'Real Chase fraud alert', 'Chase', 'no-reply@chase.com', 'Did you make this purchase?', 'We noticed unusual activity on your card. Was this you?', [['Review', 'https://www.chase.com/fraud']]),
  email('L-E15', 'legit', 'Real Social Security newsletter', 'Social Security', 'news@ssa.gov', 'Your my Social Security update', 'Your yearly statement is available.', [['Sign in', 'https://www.ssa.gov/myaccount']]),
  email('L-E16', 'legit', 'Microsoft security code', 'Microsoft account team', 'account-security-noreply@accountprotection.microsoft.com', 'Your security code', 'Use this code to sign in: 482913.'),

  // ---------------- scam webpages ----------------
  page('S-P01', 'scam', 'Fake PayPal login that posts the password elsewhere', 'https://account-check.example/signin', 'PayPal - Log in', 'Verify your account to avoid it being locked.',
    { forms: [{ action: 'https://collect-login.example/post', hasPassword: true }], meta: { stopCriteria: false, explain: [/password|PayPal/i], forbid: [/Amazon|Chase/] } }),
  page('S-P02', 'scam', 'Look-alike bank address with a login form', 'https://chase-secure-login.example/', 'Sign in', 'Enter your details',
    { forms: [{ action: 'https://chase-secure-login.example/go', hasPassword: true }], meta: { stopCriteria: true, explain: [/Chase/], forbid: [/PayPal/] } }),
  page('S-P03', 'scam', 'Card form without a secure connection, sent elsewhere', 'http://cheap-watches.example/checkout', 'Checkout', 'Pay now to unlock your free gift card prize winner',
    { forms: [{ action: 'http://pay-now.example/charge', hasPayment: true }], meta: { stopCriteria: false, explain: [/card|secure/i] } }),
  page('S-P04', 'scam', 'Prize page with an off-site claim button', 'https://daily-deals.example/win', 'Congratulations!', 'You have won a $2,000 gift card. Claim your reward before midnight. Act now!',
    { links: [['Claim reward', 'https://claim-gift.example/start']], meta: { stopCriteria: false, explain: [/claim|prize|won/i] } }),
  page('S-P05', 'scam', 'Known dangerous site', 'https://known-phish.example/login', 'Sign in', 'Welcome', { meta: { blockCriteria: true, stopCriteria: true, explain: [/dangerous/i] } }),
  page('S-P06', 'scam', 'HARD: fake tech-support alert, no form or link', 'https://pc-alert.example/warning', 'Warning!', 'Your computer is infected with a virus. Call tech support immediately at 555-0100.', { meta: { stopCriteria: false, hard: true } }),
  page('S-P07', 'scam', 'HARD: fake "survey" page collecting card for shipping, same-site form', 'https://free-gift-survey.example/ship', 'Free gift', 'Pay only $1.99 shipping to receive your free gift.',
    { forms: [{ action: 'https://free-gift-survey.example/pay', hasPayment: true }], meta: { stopCriteria: false, hard: true } }),
  page('S-P08', 'scam', 'Fake Microsoft sign-in at an unrelated address', 'https://m-login.example/auth', 'Microsoft - Sign in', 'Sign in to continue',
    { forms: [{ action: 'https://m-login.example/auth', hasPassword: true }], meta: { stopCriteria: false, explain: [/Microsoft/], forbid: [/PayPal/] } }),

  // ---------------- legitimate webpages ----------------
  page('L-P01', 'legit', 'Real PayPal login', 'https://www.paypal.com/signin', 'PayPal - Log in', 'Verify your account', { forms: [{ action: 'https://www.paypal.com/signin', hasPassword: true }] }),
  page('L-P02', 'legit', 'Shop sale', 'https://corner-shop.example/sale', 'Summer sale', 'Act now! Sale ends today. Free shipping.', { links: [['Shop now', 'https://corner-shop.example/shop']] }),
  page('L-P03', 'legit', 'News article about gift card scams', 'https://daily-news.example/scams', 'How to spot gift card scams', 'Scammers ask you to pay with gift cards or wire transfer. Never tell anyone your password. Urgent: be careful.'),
  page('L-P04', 'legit', 'Library login', 'https://library.example/login', 'Library login', 'Enter your library card number and password.', { forms: [{ action: 'https://library.example/login', hasPassword: true }] }),
  page('L-P05', 'legit', 'Single sign-on on another domain', 'https://club.example/login', 'Club members', 'Log in to continue.', { forms: [{ action: 'https://auth.club-sso.example/login', hasPassword: true }] }),
  page('L-P06', 'legit', 'Checkout that uses a payment provider on another domain', 'https://bookshop.example/checkout', 'Checkout', 'Order total $24.00. Pay securely. Act now: only 2 left!',
    { forms: [{ action: 'https://checkout.payments-provider.example/pay', hasPayment: true }] }),
  page('L-P07', 'legit', 'Regional bank login (not a brand we know)', 'https://firstcommunity-bank.example/login', 'First Community Bank - Sign in', 'Sign in to online banking. Verify your identity if prompted.',
    { forms: [{ action: 'https://firstcommunity-bank.example/auth', hasPassword: true }] }),
  page('L-P08', 'legit', 'Grocery contest results with an on-site coupon link', 'https://grocer.example/contest', "Congratulations to last month's winner", 'Our winner was announced.', { links: [['Claim your coupon', 'https://grocer.example/coupons']] }),
  page('L-P09', 'legit', 'Charity donation page, card form on a processor domain', 'https://helpfulhands.example/donate', 'Donate', 'Your gift helps families. Donate today.',
    { forms: [{ action: 'https://donate.giving-processor.example/charge', hasPayment: true }] }),
  page('L-P11', 'legit', 'KNOWN FALSE POSITIVE: library anti-scam newsletter with a member login (advice read as a demand)', 'https://library.example/newsletter', 'Town library newsletter: stay safe',
    "Urgent: volunteers are needed for the book sale. Act now to reserve a shift! Beware of scams: never pay with gift cards or wire transfers, and never share your password or social security number. Congratulations to Dot, winner of last month's reading challenge! Claim your coupon at the front desk.",
    { forms: [{ action: 'https://library.example/login', hasPassword: true }] }),
  page('L-P10', 'legit', 'Forum thread about a phishing email', 'https://seniors-forum.example/t/123', 'Got a strange email', 'I got an email saying "verify your account" with a link to a .xyz site. Is it a scam? They said act now and mentioned gift cards.'),

  // ---------------- advertisements ----------------
  ad('S-A01', 'scam', 'Prize ad with unverified claim button', 'Congratulations! You have won a $2,000 gift card. Claim your reward before midnight. Act now!', 'Claim reward', 'https://claim-gift.example/x', { stopCriteria: false, explain: [/prize|claim/i] }),
  ad('S-A02', 'scam', 'Ad whose link text names a bank but leads elsewhere', 'Your bank', 'www.mybank.example/offer', 'https://other-site.example/o', { stopCriteria: false, explain: [/mybank\.example|really goes/i] }),
  ad('S-A03', 'scam', 'Ad that leads to a known dangerous site', 'Great deal on watches', 'Shop', 'https://known-phish.example/x', { blockCriteria: true, stopCriteria: true, explain: [/dangerous/i] }),
  ad('S-A04', 'scam', 'Ad imitating PayPal', 'Log in to review a charge', 'Review', 'https://paypa1-secure.example/x', { stopCriteria: true, explain: [/PayPal/i] }),
  ad('S-A05', 'scam', 'HARD: "free phone" ad, no claim wording, off-site form-like destination', 'Win a free phone, takes 30 seconds', 'Get started', 'https://free-phone-offer.example/go', { stopCriteria: false, hard: true }),
  ad('L-A01', 'legit', 'Sale ad', 'Summer sale: 50% off garden furniture.', 'Shop the sale', 'https://garden-store.example/sale'),
  ad('L-A02', 'legit', 'Book ad', 'New cookbook out now', 'Learn more', 'https://books.example/cookbook'),
  ad('L-A03', 'legit', 'Award notice ad', 'Congratulations to our customer of the year!', 'Read more', 'https://garden-store.example/award'),
  ad('L-A04', 'legit', 'Urgency only', 'Act now! Sale ends today.', 'Shop', 'https://shop.example/s'),
  ad('L-A05', 'legit', 'Ad whose link text shows a company site but goes through an ad tracker', 'New walking shoes', 'www.shoes.example', 'https://ad.doubleclick.net/click?id=77'),
  ad('L-A06', 'legit', 'Real Amazon prize promotion', 'You have won a gift card! Claim your reward.', 'Claim reward', 'https://www.amazon.com/gp/promo'),

  // ---------------- single links ----------------
  link('S-K01', 'scam', 'Fake brand site', 'Log in to PayPal', 'https://paypa1-secure.example/login', { stopCriteria: true, explain: [/PayPal/] }),
  link('S-K02', 'scam', 'Hidden destination', 'www.mybank.example/statement', 'https://other-site.example/x', { stopCriteria: false, explain: [/mybank\.example|really goes/i] }),
  link('S-K03', 'scam', 'Number address', 'Open', 'http://192.168.4.20/login', { stopCriteria: false, explain: [/number address/i] }),
  link('S-K04', 'scam', 'Known dangerous', 'Open', 'https://sub.fake-bank-login.example/', { blockCriteria: true, stopCriteria: true, explain: [/dangerous/i] }),
  link('S-K05', 'scam', 'HARD: look-alike without a known brand', 'Sign in to Dropbox', 'https://dropb0x-files.example/login', { stopCriteria: false, hard: true }),
  link('L-K01', 'legit', 'Recipe link', 'Read the recipe', 'https://recipes.example/soup'),
  link('L-K02', 'legit', 'Real PayPal', 'View activity', 'https://www.paypal.com/myaccount'),
  link('L-K03', 'legit', 'Shortened link only', 'See photos', 'https://bit.ly/abc'),
  link('L-K04', 'legit', 'Link text is the site it goes to', 'www.recipes.example', 'https://recipes.example/'),
  link('L-K05', 'legit', 'Link text is an email address', 'friend@mail.example', 'https://mail.example/compose'),
];

module.exports = cases;
