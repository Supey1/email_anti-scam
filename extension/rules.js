// rules.js: simple, explainable scam checks.
// Everything here runs on the user's own computer. No internet needed.
//
// How scoring works: every warning sign adds "risk points".
//   5 or more points -> "high"   (red: looks like a scam)
//   1 to 4 points    -> "medium" (yellow: be careful)
//   0 points         -> "low"    (green: no warning signs found)
//
// To add a new check: call addReason(points, "plain, friendly sentence").
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

// ---------- checks ----------

function checkLink(link, addReason) {
  const report = { text: link.text || '', href: link.href, host: '', flags: [] };
  let url;
  try {
    url = unwrapRedirect(new URL(link.href));
  } catch (e) {
    return report;
  }
  const host = url.hostname.toLowerCase().replace(/^www\./, '');
  report.host = host;
  const flag = (points, reason, short) => { addReason(points, reason); report.flags.push(short); };

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
    addReason(4, `The sender's name says ${claimedBrand.label}, but the email address (${address}) is not from ${claimedBrand.label}.`);
  } else if (FREE_MAIL.has(domain) && /support|security|billing|account|department|service|team|bank/i.test(name)) {
    addReason(2, `The sender says it is a company or department, but it uses a free personal email address (${address}).`);
  }

  const lookalikeBrand = brandMentionedInHost(domain);
  if (lookalikeBrand && !isBrandDomain(domain, lookalikeBrand) && !FREE_MAIL.has(domain)) {
    addReason(4, `The sender's address (${address}) pretends to be ${lookalikeBrand.label}, but it isn't ${lookalikeBrand.label}'s real address.`);
  }
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
// returns { level: 'high' | 'medium' | 'low', score, reasons: [...], links: [...] }
function analyzeEmail(email) {
  const reasons = [];
  const seen = new Set();
  let score = 0;
  function addReason(points, text) {
    if (seen.has(text)) return;
    seen.add(text);
    reasons.push({ points, text });
    score += points;
  }

  const links = (email.links || []).map(link => checkLink(link, addReason));
  checkSender(email, addReason);
  checkWording(email, addReason);

  reasons.sort((a, b) => b.points - a.points);
  const level = score >= 5 ? 'high' : score >= 1 ? 'medium' : 'low';
  return { level, score, reasons: reasons.map(r => r.text), links };
}

// Lets tests/rules.test.js load this file with Node. Chrome ignores this.
if (typeof module !== 'undefined') {
  module.exports = {
    analyzeEmail, normalizeLookalikes, baseDomain,
    // Shared with analyzer.js (the webpage checks).
    checkLink, checkWording, brandMentionedInHost, isBrandDomain, BRANDS,
  };
}
