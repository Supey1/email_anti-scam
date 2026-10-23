// url-rules.js: warning signs in where a link (or the page you're on) really goes.
//
// These look at the address itself: known dangerous websites and addresses,
// number addresses, shortened links, risky endings, addresses written to
// mislead, and where sign-in and payment forms send what you type. Whether an
// address pretends to be a company is in domain-rules.js.
//
// Redirects: we only follow pass-through links whose real destination is
// written in the link itself (url-normalizer.js). We NEVER open a link to see
// where it goes: where a link leads can depend on who opens it and when, and
// opening it tells the scammer the link was looked at. A shortened link stays
// a "we can't see where this goes" warning sign.
//
// Each check returns "findings": { code, subject, data, evidence: { kind, value } }.

(function () {
  'use strict';
  const core = globalThis.GranblockCore = globalThis.GranblockCore || {};
  if (typeof require !== 'undefined' && !core.urlNormalizer) require('./url-normalizer.js');
  if (typeof require !== 'undefined' && !core.domainRules) require('./domain-rules.js');
  const { parseUrl, isSameOrSubdomain, sameSite, findDomainInText, embeddedUrls, isFreeHosting } = core.urlNormalizer;
  const { BRANDS } = core.domainRules;

  if (typeof require !== 'undefined' && !(globalThis.GranblockData && globalThis.GranblockData.addresses)) require('../data/addresses.js');
  const { SHORTENERS, RISKY_ENDINGS } = globalThis.GranblockData.addresses; // DATA: extension/data/addresses.js

  // Words that mean "sign in" or "pay", in a link's text or address.
  const SIGN_IN_TEXT = /\b(sign ?in|log ?in|log ?on|verify|confirm|unlock|update (your )?(account|payment|billing|card|details))\b/i;
  const SIGN_IN_PATH = /\/(login|log-in|signin|sign-in|logon|auth|verify|verification|account|billing|payment|checkout|wp-login\.php)(\/|\.|$)/i;

  // The known-dangerous list, as entries: { type: 'domain' | 'url', value, source, trusted }.
  // Normally the bundled data/threat-list.js. The service worker builds the ACTIVE
  // list (bundled + updates, minus expired entries and removed false positives),
  // and threat-sync.js hands it to useThreatEntries(), so the click guard and
  // Chrome's own blocking always agree.
  let activeEntries = null;

  function bundledEntries() {
    let list = null;
    if (typeof KNOWN_THREAT_DOMAINS !== 'undefined') {
      list = {
        KNOWN_THREAT_DOMAINS,
        KNOWN_THREAT_URLS: typeof KNOWN_THREAT_URLS !== 'undefined' ? KNOWN_THREAT_URLS : [],
        KNOWN_THREAT_SOURCE: typeof KNOWN_THREAT_SOURCE !== 'undefined' ? KNOWN_THREAT_SOURCE : { name: 'unknown', trusted: false },
      };
    } else if (typeof require !== 'undefined') {
      list = require('../data/threat-list.js');
    }
    if (!list) return [];
    const { name, trusted } = list.KNOWN_THREAT_SOURCE;
    return [
      ...list.KNOWN_THREAT_DOMAINS.map(value => ({ type: 'domain', value, source: name, trusted })),
      ...(list.KNOWN_THREAT_URLS || []).map(value => ({ type: 'url', value, source: name, trusted })),
    ];
  }

  function threatEntries() {
    return activeEntries || bundledEntries();
  }

  // Replaces the list (null goes back to the bundled one).
  function useThreatEntries(entries) {
    activeEntries = Array.isArray(entries) ? entries : null;
  }

  // Does this address match one entry? Whole websites match exactly or below;
  // single addresses match that address and below it (at a "/" boundary),
  // compared after reading both the same way.
  function entryMatches(entry, parsed) {
    if (entry.type === 'domain') return isSameOrSubdomain(parsed.hostname, entry.value);
    const listed = parseUrl(entry.value);
    if (!listed.ok || listed.hostname !== parsed.hostname) return false;
    const base = listed.pathname.endsWith('/') ? listed.pathname : listed.pathname + '/';
    return parsed.pathname === listed.pathname || parsed.pathname.startsWith(base);
  }

  // Is this address on the known-dangerous list? Returns null or
  // { source: { name, trusted }, match }. A trusted entry wins over an untrusted one.
  function knownThreat(parsed) {
    if (!parsed.ok || !parsed.isWeb) return null;
    const now = Date.now();
    const matches = threatEntries().filter(e => !(e.expiresAt && e.expiresAt <= now) && entryMatches(e, parsed));
    if (!matches.length) return null;
    const best = matches.find(e => e.trusted) || matches[0];
    return { source: { name: best.source, trusted: !!best.trusted }, match: best.value };
  }

  function isKnownThreat(hostname) {
    return !!knownThreat(parseUrl(`https://${hostname}/`));
  }

  // Checks an address. subject is 'link' or 'page' (it changes only the wording).
  // parsed comes from urlNormalizer.normalizeUrl().
  function checkAddress(parsed, subject) {
    if (!parsed.ok || !parsed.isWeb) return [];
    const { hostname, host } = parsed;
    const findings = [];
    const add = (code, data = {}, evidence = { kind: 'domain', value: hostname }) =>
      findings.push({ code, subject, data: { host, ...data }, evidence });

    const threat = knownThreat(parsed);
    if (threat) add('KNOWN_THREAT', { trusted: threat.source.trusted, source: threat.source.name }, { kind: 'url', value: parsed.href });
    if (parsed.isIp) add('NUMBER_ADDRESS', {}, { kind: 'url', value: parsed.href });
    if (SHORTENERS.has(host)) add('SHORTENED_LINK', {}, { kind: 'url', value: parsed.href });

    const ending = hostname.split('.').pop();
    if (RISKY_ENDINGS.has(ending)) add('RISKY_DOMAIN_ENDING', { ending });

    // The rest are tricks in how a LINK is written; the page you're on has already loaded.
    if (subject !== 'link') return findings;

    // A known dangerous address written inside the link (?next=https://...).
    // The website may send you on to it, so it counts, but it never hides
    // anything we found about the first website.
    if (!threat) {
      for (const inner of embeddedUrls(parsed)) {
        const innerThreat = knownThreat(inner);
        if (innerThreat) {
          add('KNOWN_THREAT', { trusted: innerThreat.source.trusted, source: innerThreat.source.name, host: inner.host, via: host }, { kind: 'url', value: inner.href });
          break;
        }
      }
    }

    // A sign-in name or password written into the address, before an "@".
    // "https://www.paypal.com@evil.example" really goes to evil.example.
    if (parsed.username || parsed.password) {
      const shown = parsed.username;
      if (findDomainInText(shown)) add('MISLEADING_URL', { shown, trick: 'before_at' }, { kind: 'url', value: parsed.href });
      else add('MISLEADING_URL', { trick: 'hidden_login' }, { kind: 'url', value: parsed.href });
    } else {
      // "https://evil.example/www.paypal.com/signin": a company's website written in the path.
      for (const brand of BRANDS) {
        if (brand.domains.some(d => isSameOrSubdomain(hostname, d))) continue;
        const shown = brand.domains.find(d => new RegExp(`(^|[/.])${d.replace(/\./g, '\\.')}(/|$)`).test(parsed.pathname));
        if (shown) {
          add('MISLEADING_URL', { shown, trick: 'in_path' }, { kind: 'url', value: parsed.href });
          break;
        }
      }
    }
    return findings;
  }

  // A sign-in or payment link that leads to a free hosting website.
  function checkSignInLink(linkText, parsed) {
    if (!parsed.ok || !parsed.isWeb || !isFreeHosting(parsed.hostname)) return [];
    if (!SIGN_IN_TEXT.test(linkText || '') && !SIGN_IN_PATH.test(parsed.pathname)) return [];
    return [{
      code: 'SIGN_IN_ON_FREE_HOSTING',
      subject: 'link',
      data: { host: parsed.host },
      evidence: { kind: 'url', value: parsed.href },
    }];
  }

  // A link's words show one website, but it really goes to another.
  function checkShownDestination(linkText, parsed) {
    if (!parsed.ok || !parsed.isWeb) return [];
    const shown = findDomainInText(linkText);
    if (!shown || sameSite(shown, parsed.hostname)) return [];
    // Showing a company's REAL website and going elsewhere is impersonation.
    const shownBrand = core.domainRules.officialBrandFor(shown);
    return [{
      code: 'HIDDEN_DESTINATION',
      subject: 'link',
      data: { shown, host: parsed.host, shownBrand: shownBrand ? shownBrand.label : null },
      evidence: { kind: 'url', value: parsed.href },
    }];
  }

  // Where a page's sign-in or payment forms send what you type.
  //   page   the parsed page address
  //   forms  the forms that have a password or payment box
  function checkSecretForms(page, forms) {
    if (!forms.length) return [];
    const findings = [];
    const add = (code, data, value) => findings.push({ code, subject: 'page', data: { host: page.host, ...data }, evidence: { kind: 'form', value } });
    const seen = new Set();
    // Your own computer (localhost) counts as secure, as it does in Chrome.
    const ownComputer = host => /^(localhost|.+\.localhost|127(\.\d{1,3}){3}|\[::1\])$/.test(host);
    // A password or card box on a page that itself isn't secure: the page (and the box) can be
    // read or changed on the way, wherever the form says it sends. Chrome marks these "Not secure".
    if (page.protocol === 'http:' && !ownComputer(page.hostname)) {
      seen.add('INSECURE_FORM');
      add('INSECURE_FORM', {}, page.href);
    }
    for (const form of forms) {
      const action = parseUrl(form.action || '', page.href);
      if (!action.ok) continue;
      if (action.isWeb) {
        const threat = knownThreat(action);
        if (threat && !seen.has('KNOWN_THREAT')) {
          seen.add('KNOWN_THREAT');
          findings.push({ code: 'KNOWN_THREAT', subject: 'form', data: { host: action.host, trusted: threat.source.trusted, source: threat.source.name }, evidence: { kind: 'form', value: action.href } });
        }
        if (!sameSite(action.hostname, page.hostname) && !seen.has('CREDENTIALS_SENT_ELSEWHERE')) {
          seen.add('CREDENTIALS_SENT_ELSEWHERE');
          add('CREDENTIALS_SENT_ELSEWHERE', { elsewhere: action.host }, action.href);
        }
      }
      if (action.protocol === 'http:' && !ownComputer(action.hostname) && !seen.has('INSECURE_FORM')) {
        seen.add('INSECURE_FORM');
        add('INSECURE_FORM', {}, action.href);
      }
    }
    if (isFreeHosting(page.hostname)) add('SIGN_IN_ON_FREE_HOSTING', {}, page.href);
    return findings;
  }

  core.urlRules = { SHORTENERS, RISKY_ENDINGS, bundledEntries, useThreatEntries, entryMatches, knownThreat, isKnownThreat, checkAddress, checkSignInLink, checkShownDestination, checkSecretForms };
  if (typeof module !== 'undefined') module.exports = core.urlRules;
})();
