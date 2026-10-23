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

  // The lists (companies and their official websites, email services, ad
  // networks, free email) are DATA, kept in extension/data/.
  if (typeof require !== 'undefined' && !(globalThis.GranblockData && globalThis.GranblockData.companies)) require('../data/companies.js');
  if (typeof require !== 'undefined' && !(globalThis.GranblockData && globalThis.GranblockData.services)) require('../data/services.js');
  const { BRANDS, NOT_IMPERSONATION, SCAM_AFFIXES } = globalThis.GranblockData.companies;
  const { EMAIL_SERVICES, AD_NETWORKS, FREE_MAIL } = globalThis.GranblockData.services;

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

  function sendsEmailFrom(domain, brand) {
    return isOfficialFor(domain, brand) || (brand.emailDomains || []).some(d => isSameOrSubdomain(domain, d));
  }

  // The company whose own email address this is ("alerts@notify.wellsfargo.com"
  // -> Wells Fargo), or null. Free personal accounts never count, even a
  // company's own (icloud.com).
  function officialSender(senderEmail) {
    const address = (senderEmail || '').toLowerCase().trim();
    const domain = address.includes('@') ? address.split('@').pop() : '';
    if (!domain || FREE_MAIL.has(domain)) return null;
    return BRANDS.find(b => sendsEmailFrom(domain, b)) || null;
  }

  // 'email' for an email service, 'ad' for an ad network, or ''.
  function serviceKind(hostname) {
    if (EMAIL_SERVICES.some(d => isSameOrSubdomain(hostname, d))) return 'email';
    if (AD_NETWORKS.some(d => isSameOrSubdomain(hostname, d))) return 'ad';
    return '';
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

  // "amazom" for "amazon": one letter changed or added, same first letter.
  // Never one letter LESS: "cloud" is a word, not a misspelled "icloud".
  function misspells(token, key) {
    return key.length >= 6 && token.length >= key.length && token[0] === key[0] && editDistanceIsOne(token, key);
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

    const candidates = [registrableDomain(hostname).split('.')[0], ...tokens];
    brand = BRANDS.find(b => b !== owner && b.keys.some(k => candidates.some(t => misspells(t, k))));
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
  //   kind  what the message is: 'alert' (an account, security, payment, or
  //         delivery notice), 'marketing' (a newsletter or ad), or 'personal'.
  //         See textRules.messageKind().
  // A company name on someone else's address matters most in an alert: that's
  // what scammers fake. A newsletter sent through an email service is normal.
  function checkSender(senderName, senderEmail, kind = 'personal') {
    const name = senderName || '';
    const address = (senderEmail || '').toLowerCase().trim();
    const domain = address.includes('@') ? address.split('@').pop() : '';
    if (!domain) return [];
    const findings = [];
    const evidence = { kind: 'sender', value: address };

    // "service@paypal.com <x@evil.example>": an address written into the NAME.
    const shownAddress = (name.match(/[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})/i) || [])[1];
    const shownBrand = shownAddress ? officialBrandFor(shownAddress.toLowerCase()) : null;
    const claimed = shownBrand || brandNamedIn(name);
    // A company never emails from a free personal account, even its own ("Apple <someone@icloud.com>").
    if (claimed && (FREE_MAIL.has(domain) || !sendsEmailFrom(domain, claimed))) {
      let variant;
      if (shownBrand && !isSameOrSubdomain(domain, shownAddress.toLowerCase())) variant = 'address_in_name';
      else if (FREE_MAIL.has(domain)) variant = 'free_mail';
      else if (serviceKind(domain) === 'email') variant = kind === 'alert' ? 'alert' : null; // a newsletter through an email service is normal
      else variant = kind === 'alert' ? 'alert' : 'not_alert';
      if (variant) findings.push({ code: 'SENDER_NAME_MISMATCH', subject: 'sender', data: { brand: claimed.label, address, variant, shown: shownAddress }, evidence });
    } else if (!claimed && FREE_MAIL.has(domain) && /support|security|billing|account|department|service|team|bank/i.test(name)) {
      findings.push({ code: 'COMPANY_ON_FREE_EMAIL', subject: 'sender', data: { address }, evidence });
    }

    const fake = FREE_MAIL.has(domain) ? null : lookalikeOf(domain);
    if (fake) {
      findings.push({ code: 'LOOKALIKE_SENDER', subject: 'sender', data: { brand: fake.brand.label, address }, evidence });
    }
    return findings;
  }

  // An email claiming to be from an organization that says it never emails
  // people first to ask for personal or financial details, asking for exactly that.
  //   asks  the message asks for money, personal details, or account action
  function checkAgencyEmail(senderName, subject, asks) {
    if (!asks) return [];
    const brand = BRANDS.find(b => b.asksByEmail === false && (b.nameRe.test(senderName || '') || b.nameRe.test(subject || '')));
    if (!brand) return [];
    return [{ code: 'AGENCY_DOES_NOT_EMAIL', subject: 'sender', data: { brand: brand.label }, evidence: { kind: 'text', value: brand.label } }];
  }

  // An email that says it's from a company, but none of its links go to that
  // company's website. Links through email services and ad networks are
  // skipped (we can't see where they end up).
  //   claimed  the company the sender name or subject names
  //   links    [{ host, service }] for the email's links
  //   kind     see checkSender
  function checkMessageLinks(claimed, links, kind) {
    if (!claimed) return [];
    const readable = links.filter(l => l.host && !l.service);
    if (!readable.length || readable.some(l => isOfficialFor(l.host, claimed))) return [];
    return [{
      code: 'BRAND_NAME_MISMATCH',
      subject: 'link',
      data: { brand: claimed.label, host: readable[0].host, variant: 'message', alert: kind === 'alert' },
      evidence: { kind: 'domain', value: readable[0].host },
    }];
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
    BRANDS, FREE_MAIL, EMAIL_SERVICES, AD_NETWORKS, normalizeLookalikes, officialBrandFor, brandNamedIn, lookalikeOf,
    serviceKind, officialSender, isOfficialFor, checkAddress, checkNamedBrand, checkSender, checkAgencyEmail, checkMessageLinks, checkSignInPage,
  };
  if (typeof module !== 'undefined') module.exports = core.domainRules;
})();
