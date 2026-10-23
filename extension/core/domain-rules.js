// domain-rules.js: does a company name match the website or email address it comes from?
//
// Every check here compares a company someone CLAIMS to be (in a link,
// a sender name, or a page title) with the company's OFFICIAL websites.
// Look-alike addresses ("paypa1") are warning signs, not proof: the points
// for each sign are set in risk-policy.js.
//
// Each check returns "findings": { code, subject, data, evidence: { kind, value } }.
// The words people see are written in explanations.js.

(function () {
  'use strict';
  const core = globalThis.GranblockCore = globalThis.GranblockCore || {};
  if (typeof require !== 'undefined' && !core.urlNormalizer) require('./url-normalizer.js');
  const { registrableDomain, isSameOrSubdomain, publicSuffix, toLookalikeAscii } = core.urlNormalizer;

  // Companies scammers pretend to be most often, and their OFFICIAL websites.
  //   nameRe   how the company's name is written in text
  //   keys     words to look for inside a web address
  //   domains  official websites (and everything under them)
  // Before adding a website here, check it on the company's own site.
  const BRANDS = [
    { label: 'PayPal', nameRe: /paypal/i, keys: ['paypal'], domains: ['paypal.com', 'paypal.me', 'paypal.co.uk'] },
    { label: 'Amazon', nameRe: /amazon/i, keys: ['amazon'], domains: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.com.au'] },
    { label: 'Apple', nameRe: /\bapple\b|icloud/i, keys: ['apple', 'icloud'], domains: ['apple.com', 'icloud.com'] },
    { label: 'Microsoft', nameRe: /microsoft|office ?365/i, keys: ['microsoft', 'office365'], domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com'] },
    { label: 'Netflix', nameRe: /netflix/i, keys: ['netflix'], domains: ['netflix.com'] },
    { label: 'Chase', nameRe: /\bchase\b/i, keys: ['chase'], domains: ['chase.com'] },
    { label: 'Wells Fargo', nameRe: /wells ?fargo/i, keys: ['wellsfargo'], domains: ['wellsfargo.com'] },
    { label: 'Bank of America', nameRe: /bank of america/i, keys: ['bankofamerica', 'bofa'], domains: ['bankofamerica.com', 'bofa.com'] },
    { label: 'the IRS', nameRe: /\birs\b|internal revenue/i, keys: ['irs'], domains: ['irs.gov'] },
    { label: 'Social Security', nameRe: /social security/i, keys: ['ssa', 'socialsecurity'], domains: ['ssa.gov'] },
    { label: 'the Post Office (USPS)', nameRe: /\busps\b|postal service/i, keys: ['usps'], domains: ['usps.com'] },
    { label: 'FedEx', nameRe: /fedex/i, keys: ['fedex'], domains: ['fedex.com'] },
    { label: 'UPS', nameRe: /\bups\b/i, keys: ['ups'], domains: ['ups.com'] },
  ];

  // Websites with a company's word in their name that are NOT pretending:
  // "amazonaws.com" is where anyone can put files, not Amazon's shop.
  const NOT_IMPERSONATION = ['amazonaws.com'];

  // Free personal email services. A real company never emails you from one of these.
  const FREE_MAIL = new Set([
    'gmail.com', 'googlemail.com', 'yahoo.com', 'ymail.com', 'hotmail.com', 'outlook.com', 'live.com',
    'msn.com', 'aol.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com', 'gmx.com', 'mail.com',
  ]);

  // Words scammers glue onto a short company name: "applesupport", "chase-secure".
  const SCAM_AFFIXES = [
    'secure', 'security', 'support', 'login', 'signin', 'verify', 'verification', 'account', 'accounts', 'id',
    'help', 'service', 'services', 'billing', 'update', 'alert', 'alerts', 'online', 'bank', 'banking', 'pay',
    'payment', 'care', 'team', 'center', 'centre', 'mail', 'notice', 'auth',
  ];

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

  function isOfficialFor(hostname, brand) {
    return brand.domains.some(d => isSameOrSubdomain(hostname, d));
  }

  // The company this is an official website of, or null.
  function officialBrandFor(hostname) {
    return BRANDS.find(b => isOfficialFor(hostname, b)) || null;
  }

  // The company a piece of text names, or null.
  function brandNamedIn(text) {
    return BRANDS.find(b => b.nameRe.test(text || '')) || null;
  }

  // Short names must stand alone ("irs" should not match "first", "apple"
  // should not match "applebees") unless glued to a scam word ("applesupport").
  // Long names can appear anywhere ("securepaypal").
  function tokenMatchesKey(token, key) {
    if (key.length <= 5) {
      return token === key || SCAM_AFFIXES.some(a => token === key + a || token === a + key);
    }
    return token.includes(key);
  }

  // The words in an address, without its ending: "secure-paypal.co.uk" -> ["secure", "paypal"].
  function hostTokens(hostname) {
    const suffix = publicSuffix(hostname);
    return hostname.slice(0, -(suffix.length + 1)).split(/[.-]/).filter(Boolean);
  }

  function editDistanceIsOne(a, b) {
    if (a === b || Math.abs(a.length - b.length) > 1) return false;
    let i = 0, j = 0, edits = 0;
    while (i < a.length && j < b.length) {
      if (a[i] === b[j]) { i++; j++; continue; }
      if (++edits > 1) return false;
      if (a.length > b.length) i++;
      else if (b.length > a.length) j++;
      else { i++; j++; }
    }
    return edits + (a.length - i) + (b.length - j) === 1;
  }

  // Is this address pretending to be a company? Returns null or
  // { brand, technique, officialDomain? }. Techniques, strongest first:
  //   official_domain_in_front  "paypal.com.fake-domain.example"
  //   company_name              "paypal-secure.example", "applesupport.example"
  //   character_swap            "paypa1.example", "rnicrosoft.example"
  //   other_alphabet            "pаypal.example" with a Cyrillic "а"
  //   misspelling               "paypall.example", "amazom.example"
  function lookalikeOf(hostname) {
    if (!hostname || /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.startsWith('[')) return null;
    if (NOT_IMPERSONATION.some(d => isSameOrSubdomain(hostname, d))) return null;
    const owner = officialBrandFor(hostname);

    for (const brand of BRANDS) {
      if (brand === owner) continue;
      for (const d of brand.domains) {
        const at = hostname.indexOf(d);
        const before = at > 0 ? hostname[at - 1] : '.';
        const after = hostname[at + d.length];
        if (at >= 0 && before === '.' && (after === '.' || after === '-')) {
          return { brand, technique: 'official_domain_in_front', officialDomain: d };
        }
      }
    }

    const tokens = hostTokens(hostname);
    const findBrand = toks => BRANDS.find(b => b !== owner && b.keys.some(k => toks.some(t => tokenMatchesKey(t, k))));
    let brand = findBrand(tokens);
    if (brand) return { brand, technique: 'company_name' };
    brand = findBrand(tokens.map(normalizeLookalikes));
    if (brand) return { brand, technique: 'character_swap' };

    const plain = toLookalikeAscii(hostname);
    if (plain) {
      brand = findBrand(hostTokens(plain)) || findBrand(hostTokens(plain).map(normalizeLookalikes));
      if (brand) return { brand, technique: 'other_alphabet' };
    }

    const name = registrableDomain(hostname).split('.')[0];
    brand = BRANDS.find(b => b !== owner && b.keys.some(k => k.length >= 6 && editDistanceIsOne(name, k)));
    if (brand) return { brand, technique: 'misspelling' };
    return null;
  }

  // ---------- checks ----------

  // A link's or page's address pretends to be a company.
  function checkAddress(hostname, subject) {
    const fake = lookalikeOf(hostname);
    if (!fake) return [];
    return [{
      code: 'LOOKALIKE_DOMAIN',
      subject,
      data: { host: hostname.replace(/^www\./, ''), brand: fake.brand.label, technique: fake.technique, officialDomain: fake.officialDomain, registrable: registrableDomain(hostname) },
      evidence: { kind: 'domain', value: hostname },
    }];
  }

  // Words (a link's text, or the ad around it) name a company, but the link goes elsewhere.
  function checkNamedBrand(text, hostname, variant) {
    const brand = brandNamedIn(text);
    if (!brand || isOfficialFor(hostname, brand)) return [];
    return [{
      code: 'BRAND_NAME_MISMATCH',
      subject: 'link',
      data: { brand: brand.label, host: hostname.replace(/^www\./, ''), variant },
      evidence: { kind: 'text', value: brand.label },
    }];
  }

  // The sender's name or address pretends to be a company.
  function checkSender(senderName, senderEmail) {
    const name = senderName || '';
    const address = (senderEmail || '').toLowerCase().trim();
    const domain = address.includes('@') ? address.split('@').pop() : '';
    if (!domain) return [];
    const findings = [];
    const evidence = { kind: 'sender', value: address };

    const claimed = brandNamedIn(name);
    if (claimed && (FREE_MAIL.has(domain) || !isOfficialFor(domain, claimed))) {
      findings.push({ code: 'SENDER_NAME_MISMATCH', subject: 'sender', data: { brand: claimed.label, address }, evidence });
    } else if (FREE_MAIL.has(domain) && /support|security|billing|account|department|service|team|bank/i.test(name)) {
      findings.push({ code: 'COMPANY_ON_FREE_EMAIL', subject: 'sender', data: { address }, evidence });
    }

    const fake = FREE_MAIL.has(domain) ? null : lookalikeOf(domain);
    if (fake) {
      findings.push({ code: 'LOOKALIKE_SENDER', subject: 'sender', data: { brand: fake.brand.label, address }, evidence });
    }
    return findings;
  }

  // A sign-in or payment page with a company's name on it, but not on that company's website.
  function checkSignInPage(claimText, hostname, asksForSecrets) {
    if (!asksForSecrets) return [];
    const brand = brandNamedIn(claimText);
    if (!brand || isOfficialFor(hostname, brand)) return [];
    return [{
      code: 'FAKE_SIGN_IN_PAGE',
      subject: 'page',
      data: { brand: brand.label, host: hostname.replace(/^www\./, '') },
      evidence: { kind: 'domain', value: hostname },
    }];
  }

  core.domainRules = {
    BRANDS, FREE_MAIL, normalizeLookalikes, officialBrandFor, brandNamedIn, lookalikeOf,
    checkAddress, checkNamedBrand, checkSender, checkSignInPage,
  };
  if (typeof module !== 'undefined') module.exports = core.domainRules;
})();
