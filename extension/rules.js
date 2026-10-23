// rules.js: simple, explainable scam checks.
// Everything here runs on the user's own computer. No internet needed.
//
// There are three ways in, one for each thing we check:
//   analyzeEmail(email)        an email open in Gmail
//   analyzeLink(link, context) a link someone is about to click (on any website)
//   analyzePage(page)          the website someone is looking at
// They all share the same checks and return the same kind of answer:
//   { level, action, score, reasons, evidence, ... }
//
// How scoring works: every warning sign adds "risk points".
//   5 or more points -> "high"   (red: looks like a scam)
//   1 to 4 points    -> "medium" (yellow: be careful)
//   0 points         -> "low"    (green: no warning signs found)
// A website on the known-dangerous list (threat-list.js) is different: that is
// confirmed evidence, not a guess, so it is always "high" and gets blocked.
//
// What happens next ("action"):
//   "block"  known dangerous website: stop it, no way through
//   "warn"   strong warning signs: stop and explain, let the person choose
//   "allow"  not enough evidence to interrupt anyone
// Weak signs alone (one rushed word, an unusual website ending) never
// interrupt a click. Too many false alarms and people stop trusting us.
//
// To add a new check: call addReason(points, "plain, friendly sentence", kind).
// Write reasons the way you'd explain it to your grandparent.

// Companies scammers pretend to be most often, and their REAL website addresses.
// keys = words to look for inside a link's web address.
const BRANDS = [
  { label: 'PayPal', nameRe: /paypal/i, keys: ['paypal'], domains: ['paypal.com'] },
  { label: 'Amazon', nameRe: /amazon/i, keys: ['amazon'], domains: ['amazon.com', 'amazonaws.com'] },
  { label: 'Apple', nameRe: /\bapple\b|icloud/i, keys: ['apple', 'icloud'], domains: ['apple.com', 'icloud.com'] },
  { label: 'Microsoft', nameRe: /microsoft|office ?365/i, keys: ['microsoft', 'office365'], domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com'] },
  { label: 'Netflix', nameRe: /netflix/i, keys: ['netflix'], domains: ['netflix.com'] },
  { label: 'Chase', nameRe: /\bchase\b/i, keys: ['chase'], domains: ['chase.com'] },
  { label: 'Wells Fargo', nameRe: /wells ?fargo/i, keys: ['wellsfargo'], domains: ['wellsfargo.com'] },
  { label: 'Bank of America', nameRe: /bank of america/i, keys: ['bankofamerica', 'bofa'], domains: ['bankofamerica.com', 'bofa.com'] },
  { label: 'the IRS', nameRe: /\birs\b|internal revenue/i, keys: ['irs'], domains: ['irs.gov'] },
  { label: 'Social Security', nameRe: /social security/i, keys: ['ssa', 'socialsecurity'], domains: ['ssa.gov'] },
  { label: 'the Post Office (USPS)', nameRe: /\busps\b|postal service/i, keys: ['usps'], domains: ['usps.com', 'usps.gov'] },
  { label: 'FedEx', nameRe: /fedex/i, keys: ['fedex'], domains: ['fedex.com'] },
  { label: 'UPS', nameRe: /\bups\b/i, keys: ['ups'], domains: ['ups.com'] },
];

// Free personal email services. A real company never emails you from one of these.
const FREE_MAIL = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'hotmail.com', 'outlook.com', 'live.com',
  'msn.com', 'aol.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com', 'gmx.com', 'mail.com',
]);

// Link shorteners hide where a link really goes.
const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
  'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc',
]);

// Website endings that are cheap and often used by scam sites.
const RISKY_ENDINGS = new Set(['xyz', 'top', 'click', 'zip', 'mov', 'icu', 'buzz', 'cfd', 'sbs', 'rest', 'lol']);

// Scam-style wording. Each group can only add points once.
const WORDING_CHECKS = [
  {
    points: 3,
    patterns: [/gift ?cards?/, /wire transfer/, /\bbitcoin\b/, /\bcrypto/, /western union/, /moneygram/, /\bzelle\b/],
    reason: 'It mentions gift cards, wire transfers, or crypto. Scammers ask for these because the money can\'t be gotten back.',
  },
  {
    points: 2,
    patterns: [/suspended/, /\blocked\b/, /unusual (sign-?in )?activity/, /verify your (account|identity)/, /confirm your (account|identity)/, /update your (payment|billing)/, /unauthori[sz]ed/],
    reason: 'It says something is wrong with your account. This is a common trick to get you to log in on a fake page.',
  },
  {
    points: 1,
    patterns: [/\burgent/, /immediately/, /within (24|48|72) hours/, /act now/, /final notice/, /last warning/, /expires today/],
    reason: 'It tries to rush you. Real companies give you time to think.',
  },
  {
    points: 3,
    patterns: [/(don'?t|do not) tell/, /keep (this|it) (a )?secret/, /between (us|you and me)/],
    reason: 'It asks you to keep a secret. Real family and real companies don\'t ask that.',
  },
  {
    points: 3,
    patterns: [/you('ve| have) won/, /claim your (prize|reward)/, /\blottery\b/, /\binheritance\b/, /unclaimed (funds|money)/],
    reason: 'It says you won something or are owed money. This is a very common scam.',
  },
  {
    points: 2,
    patterns: [/social security number/, /\bssn\b/, /routing number/, /account number/, /date of birth/, /your password/],
    reason: 'It asks about private information like account numbers or passwords. Never send these by email.',
  },
  {
    points: 2,
    patterns: [/could not be delivered/, /couldn'?t be delivered/, /package (is )?on hold/, /(re-?delivery|customs|shipping) fee/, /reschedule (your )?delivery/],
    reason: 'It says a package couldn\'t be delivered. Fake delivery notices are a very common scam. Check the tracking number on the shipper\'s real website instead.',
  },
  {
    points: 2,
    patterns: [/remote access/, /\banydesk\b/, /\bteamviewer\b/, /tech(nical)? support/, /your computer (is|has been) (infected|hacked)/, /\bvirus(es)?\b/],
    reason: 'It talks about computer viruses or "tech support." Real companies won\'t contact you this way.',
  },
];

// Scam wording for websites, ads, and the text around a link.
// Webpages are full of ordinary words like "urgent" or "lottery" (think news
// stories), so these look for wording aimed AT the reader: "YOU have won",
// "YOUR computer is infected", "call this number".
const OFFER_CHECKS = [
  {
    id: 'prize',
    points: 3,
    patterns: [
      /\byou('ve| have)? (just )?(won|been selected|been chosen)\b/,
      /\bclaim your (free )?(prize|reward|gift|winnings|cash)/,
      /\bcongratulations\b[^.!]{0,60}\b(won|winner|selected|chosen)\b/,
      /\byou are (our|today'?s|the) (lucky )?winner/,
    ],
    reason: 'It promises you a prize or a reward.',
  },
  {
    id: 'payFirst',
    points: 3,
    patterns: [
      /\b(pay|fee|shipping|processing|handling)\b[^.!]{0,40}\bto (claim|receive|release|unlock|get) (your|the)\b/,
      /\b(pay|buy|send|purchase)\b[^.!]{0,30}\b(gift ?cards?|bitcoin|crypto|wire transfer|western union|moneygram)/,
    ],
    reason: 'It asks you to pay first, or to pay with gift cards, crypto, or a wire transfer. Real prizes and real companies don\'t work this way.',
  },
  {
    id: 'scare',
    points: 3,
    patterns: [
      /\byour (account|card|computer|device|pc|phone|iphone|mac)\b[^.!]{0,40}\b(locked|suspended|infected|compromised|hacked|disabled|blocked)\b/,
      /\b(virus(es)?|malware|trojan|spyware)\b[^.!]{0,30}\b(detected|found)\b/,
    ],
    reason: 'It says your account or computer has a serious problem.',
  },
  {
    id: 'callNow',
    points: 3,
    patterns: [
      /\bcall\b[^.!]{0,40}(\(?\d{3}\)?[-. ]?\d{3}[-. ]\d{4}|toll[- ]free|support|helpline|technician)/,
      /\b(do not|don'?t) (close|restart|shut down|turn off)\b[^.!]{0,30}\b(computer|browser|page|window)/,
    ],
    reason: 'It tells you to call a phone number, or not to close the page. Real security warnings never do this.',
  },
  {
    id: 'pressure',
    points: 1,
    patterns: [
      /\burgent/, /\bimmediately\b/, /within (24|48|72) hours/, /\bact (now|fast)\b/, /\blast chance\b/,
      /\bfinal notice\b/, /before midnight/, /expires (today|tonight|in \d+)/, /\bonly \d+ (left|remaining|minutes)/,
    ],
    reason: 'It tries to rush you.',
  },
];

// Warning signs that are much stronger together than apart.
const OFFER_COMBOS = [
  {
    needs: ['prize', 'pressure'],
    points: 2,
    reason: 'It promises a prize AND rushes you. Together, these are a classic scam pattern.',
  },
];

// ---------- helpers ----------

// Turns look-alike characters back into letters: "paypa1" -> "paypal", "rnicrosoft" -> "microsoft".
function normalizeLookalikes(text) {
  return text
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/5/g, 's')
    .replace(/\$/g, 's');
}

// The main part of a web address: "login.secure.paypal.com" -> "paypal.com".
function baseDomain(host) {
  const parts = host.split('.');
  if (parts.length > 2 && parts[parts.length - 1].length === 2 &&
      ['co', 'com', 'org', 'net', 'gov', 'ac'].includes(parts[parts.length - 2])) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

function isBrandDomain(host, brand) {
  return brand.domains.some(d => host === d || host.endsWith('.' + d));
}

// Short words must match exactly ("irs" should not match "first"),
// medium words must start a piece of the address ("chase" should not match "purchase"),
// long words can appear anywhere ("securepaypal").
function tokenMatchesKey(token, key) {
  if (key.length <= 3) return token === key;
  if (key.length <= 5) return token.startsWith(key);
  return token.includes(key);
}

// Which brand (if any) a web address is trying to look like.
function brandMentionedInHost(host) {
  const withoutEnding = host.split('.').slice(0, -1).join('.');
  const tokens = normalizeLookalikes(withoutEnding).split(/[.\-]/);
  return BRANDS.find(b => b.keys.some(k => tokens.some(t => tokenMatchesKey(t, k))));
}

function isAnyBrandDomain(host) {
  return BRANDS.some(b => isBrandDomain(host, b));
}

// Is this website on the known-dangerous list (threat-list.js)?
function isKnownThreat(host) {
  const list = typeof KNOWN_THREAT_DOMAINS !== 'undefined' ? KNOWN_THREAT_DOMAINS
    : typeof require !== 'undefined' ? require('./threat-list.js').KNOWN_THREAT_DOMAINS : [];
  return list.some(d => host === d || host.endsWith('.' + d));
}

// Gmail sometimes wraps links like https://www.google.com/url?q=REAL_LINK.
function unwrapRedirect(url) {
  if (/^(www\.)?google\.com$/.test(url.hostname) && url.pathname === '/url') {
    const inner = url.searchParams.get('q') || url.searchParams.get('url');
    if (inner) {
      try { return new URL(inner); } catch (e) { /* fall through */ }
    }
  }
  return url;
}

// "https://www.Example.com/x" -> "example.com". Returns '' if it isn't a web address.
function hostOf(href) {
  try {
    const url = unwrapRedirect(new URL(href));
    if (!/^https?:$/.test(url.protocol)) return '';
    return url.hostname.toLowerCase().replace(/^www\./, '');
  } catch (e) {
    return '';
  }
}

// Collects warning signs and turns them into an answer.
function makeCollector() {
  const evidence = [];
  const seen = new Set();
  function addReason(points, text, kind = 'wording') {
    if (seen.has(text)) return;
    seen.add(text);
    evidence.push({ points, text, kind });
  }
  function finish(extra = {}) {
    evidence.sort((a, b) => b.points - a.points);
    const score = evidence.reduce((sum, e) => sum + e.points, 0);
    const confirmed = evidence.some(e => e.kind === 'known_threat');
    const level = confirmed || score >= 5 ? 'high' : score >= 1 ? 'medium' : 'low';
    const action = confirmed ? 'block' : score >= 5 ? 'warn' : 'allow';
    return { level, action, confirmed, score, reasons: evidence.map(e => e.text), evidence, ...extra };
  }
  return { addReason, finish };
}

// ---------- checks ----------

function checkLink(link, addReason) {
  const report = { text: link.text || '', href: link.href, host: '', flags: [], knownThreat: false };
  const host = hostOf(link.href);
  if (!host) return report;
  report.host = host;
  const flag = (points, reason, short, kind = 'destination') => { addReason(points, reason, kind); report.flags.push(short); };

  if (isKnownThreat(host)) {
    report.knownThreat = true;
    flag(10, `A link goes to ${host}, which is on a list of known dangerous websites.`, 'known dangerous website', 'known_threat');
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) {
    flag(3, 'A link goes to a number address instead of a normal website name. Real companies almost never do this.', 'number address');
  }

  if (SHORTENERS.has(host)) {
    flag(1, 'A link is shortened, which hides where it really goes.', 'shortened link');
  }

  const ending = host.split('.').pop();
  if (RISKY_ENDINGS.has(ending)) {
    flag(1, `A link goes to a website ending in ".${ending}", which scam sites often use.`, 'risky website ending');
  }

  const brand = brandMentionedInHost(host);
  if (brand && !isBrandDomain(host, brand)) {
    flag(4, `A link pretends to be ${brand.label}, but it goes to ${host}, not ${brand.label}'s real website.`, `fake ${brand.label} site`);
  }

  // The link's words say one website, but it actually goes to another.
  const visibleText = report.text.replace(/\S+@\S+/g, '');
  const shown = visibleText.match(/\b((?:[a-z0-9-]+\.)+[a-z]{2,})\b/i);
  if (shown) {
    const shownHost = shown[1].toLowerCase().replace(/^www\./, '');
    if (baseDomain(shownHost) !== baseDomain(host)) {
      flag(3, `A link says it goes to ${shownHost}, but it really goes to ${host}.`, 'hidden destination');
    }
  } else {
    // The link's words name a company, but the address isn't that company's.
    const namedBrand = BRANDS.find(b => b.nameRe.test(visibleText));
    if (namedBrand && !isBrandDomain(host, namedBrand)) {
      flag(2, `A link mentions ${namedBrand.label}, but it goes to ${host}.`, `not really ${namedBrand.label}`);
    }
  }

  return report;
}

function checkSender(email, addReason) {
  const name = email.senderName || '';
  const address = (email.senderEmail || '').toLowerCase();
  const domain = address.includes('@') ? address.split('@').pop() : '';
  if (!domain) return;

  const claimedBrand = BRANDS.find(b => b.nameRe.test(name));
  if (claimedBrand && (FREE_MAIL.has(domain) || !isBrandDomain(domain, claimedBrand))) {
    addReason(4, `The sender's name says ${claimedBrand.label}, but the email address (${address}) is not from ${claimedBrand.label}.`, 'sender');
  } else if (FREE_MAIL.has(domain) && /support|security|billing|account|department|service|team|bank/i.test(name)) {
    addReason(2, `The sender says it is a company or department, but it uses a free personal email address (${address}).`, 'sender');
  }

  const lookalikeBrand = brandMentionedInHost(domain);
  if (lookalikeBrand && !isBrandDomain(domain, lookalikeBrand) && !FREE_MAIL.has(domain)) {
    addReason(4, `The sender's address (${address}) pretends to be ${lookalikeBrand.label}, but it isn't ${lookalikeBrand.label}'s real address.`, 'sender');
  }
}

// The same address checks as checkLink, worded for the page you're on.
function checkPageAddress(host, addReason) {
  if (isKnownThreat(host)) {
    addReason(10, `This website (${host}) is on a list of known dangerous websites.`, 'known_threat');
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[')) {
    addReason(3, 'This page is on a number address instead of a normal website name. Real companies almost never do this.', 'destination');
  }
  const ending = host.split('.').pop();
  if (RISKY_ENDINGS.has(ending)) {
    addReason(1, `This website ends in ".${ending}", which scam sites often use.`, 'destination');
  }
  const brand = brandMentionedInHost(host);
  if (brand && !isBrandDomain(host, brand)) {
    addReason(4, `This website's name pretends to be ${brand.label}, but ${host} is not ${brand.label}'s real website.`, 'destination');
  }
}

// Runs OFFER_CHECKS and OFFER_COMBOS on some text. Returns the ids that matched.
function checkOffer(text, addReason) {
  const lower = (text || '').toLowerCase();
  const matched = OFFER_CHECKS.filter(check => check.patterns.some(p => p.test(lower)));
  for (const check of matched) addReason(check.points, check.reason);
  const ids = matched.map(check => check.id);
  for (const combo of OFFER_COMBOS) {
    if (combo.needs.every(id => ids.includes(id))) addReason(combo.points, combo.reason);
  }
  return ids;
}

function checkWording(email, addReason) {
  const text = `${email.subject || ''}\n${email.bodyText || ''}`.toLowerCase();
  for (const check of WORDING_CHECKS) {
    if (check.patterns.some(p => p.test(text))) addReason(check.points, check.reason);
  }
  // "Grandparent scam": someone claims a family member is in trouble and needs money fast.
  if (/\b(grandma|grandpa|grandmother|grandfather|nana|papa)\b/.test(text) &&
      /\b(bail|jail|arrested|hospital|accident|lawyer)\b/.test(text)) {
    addReason(3, 'It says a family member is in trouble and needs help fast. Call that person directly using a phone number you already have.');
  }
}

// ---------- main entry point ----------

// email = { senderName, senderEmail, subject, bodyText, links: [{ text, href }] }
// returns { level: 'high' | 'medium' | 'low', action, score, reasons: [...], evidence: [...], links: [...] }
function analyzeEmail(email) {
  const { addReason, finish } = makeCollector();
  const links = (email.links || []).map(link => checkLink(link, addReason));
  checkSender(email, addReason);
  checkWording(email, addReason);
  return finish({ links });
}

// Someone is about to click a link. Should we stop them first?
// link    = { text, href }
// context = {
//   pageUrl,           the website the link is on
//   nearbyText,        words around the link, like the rest of an ad
//   surroundingLevel,  'high' if the link is inside an email that looks like a scam
// }
// returns { level, action: 'block' | 'warn' | 'allow', score, host, reasons, evidence, ... }
function analyzeLink(link, context = {}) {
  const { addReason, finish } = makeCollector();
  const host = hostOf(link.href);
  if (!host) return finish({ host });

  // Moving around inside the same website is the page's job (analyzePage), not ours.
  const pageHost = hostOf(context.pageUrl || '');
  if (pageHost && baseDomain(pageHost) === baseDomain(host) && !isKnownThreat(host)) {
    return finish({ host, sameSite: true });
  }

  const report = checkLink(link, addReason);

  // What the link and the ad around it promise. A link to a company's real
  // website is trusted here: a real bank can say "your card is blocked".
  if (!isAnyBrandDomain(host)) {
    const offerText = `${link.text || ''}\n${context.nearbyText || ''}`;
    const offers = checkOffer(offerText, addReason);
    if (offers.length) {
      const namedBrand = BRANDS.find(b => b.nameRe.test(offerText));
      if (namedBrand && !isBrandDomain(host, namedBrand)) {
        addReason(2, `The offer mentions ${namedBrand.label}, but the link goes to ${host}, not ${namedBrand.label}'s real website.`, 'destination');
      } else if (offers.some(id => id !== 'pressure')) {
        addReason(0, `We could not confirm that ${host} belongs to the company in this offer.`, 'destination');
      }
    }
  }

  if (context.surroundingLevel === 'high') {
    addReason(5, 'This link is inside an email that looks like a scam.', 'context');
  }

  return finish({ host, flags: report.flags });
}

// Is the website itself pretending to be something it isn't?
// page = {
//   url, title, headings (main headings' text), text (visible words),
//   hasPassword (does the page ask for a password?),
//   formActions (where the page's forms send what you type)
// }
// returns { level, action: 'block' | 'warn' | 'allow', score, host, reasons, evidence }
function analyzePage(page) {
  const { addReason, finish } = makeCollector();
  const host = hostOf(page.url || '');
  if (!host) return finish({ host });
  if (isAnyBrandDomain(host) && !isKnownThreat(host)) return finish({ host });

  checkPageAddress(host, addReason);

  // A sign-in page with a company's name on it, but not on that company's website.
  const heading = `${page.title || ''}\n${page.headings || ''}`;
  const claimedBrand = BRANDS.find(b => b.nameRe.test(heading));
  if (page.hasPassword && claimedBrand && !isBrandDomain(host, claimedBrand)) {
    addReason(5, `This page looks like a ${claimedBrand.label} sign-in page, but it is on ${host}, not ${claimedBrand.label}'s real website.`, 'page');
  }

  // The password you type would be sent to a different website.
  const elsewhere = (page.formActions || []).map(hostOf).find(h => h && baseDomain(h) !== baseDomain(host));
  if (page.hasPassword && elsewhere) {
    addReason(3, `What you type on this page would be sent to a different website (${elsewhere}).`, 'page');
  }

  checkOffer(`${heading}\n${(page.text || '').slice(0, 5000)}`, addReason);

  return finish({ host });
}

// Lets tests/rules.test.js load this file with Node. Chrome ignores this.
if (typeof module !== 'undefined') {
  module.exports = { analyzeEmail, analyzeLink, analyzePage, normalizeLookalikes, baseDomain, hostOf, isKnownThreat };
}
