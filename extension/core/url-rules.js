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

  // Link shorteners hide where a link really goes.
  const SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
    'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc',
  ]);

  // Website endings that are cheap and often used by scam sites.
  const RISKY_ENDINGS = new Set(['xyz', 'top', 'click', 'zip', 'mov', 'icu', 'buzz', 'cfd', 'sbs', 'rest', 'lol']);

  // Words that mean "sign in" or "pay", in a link's text or address.
  const SIGN_IN_TEXT = /\b(sign ?in|log ?in|log ?on|verify|confirm|unlock|update (your )?(account|payment|billing|card|details))\b/i;
  const SIGN_IN_PATH = /\/(login|log-in|signin|sign-in|logon|auth|verify|verification|account|billing|payment|checkout|wp-login\.php)(\/|\.|$)/i;

  // The lists in threat-list.js. In Chrome they're already loaded; in tests we load them here.
  function threatList() {
    if (typeof KNOWN_THREAT_DOMAINS !== 'undefined') {
      return {
        domains: KNOWN_THREAT_DOMAINS,
        urls: typeof KNOWN_THREAT_URLS !== 'undefined' ? KNOWN_THREAT_URLS : [],
        source: typeof KNOWN_THREAT_SOURCE !== 'undefined' ? KNOWN_THREAT_SOURCE : { name: 'unknown', trusted: false },
      };
    }
    if (typeof require !== 'undefined') {
      const list = require('../threat-list.js');
      return { domains: list.KNOWN_THREAT_DOMAINS, urls: list.KNOWN_THREAT_URLS || [], source: list.KNOWN_THREAT_SOURCE };
    }
    return { domains: [], urls: [], source: { name: 'none', trusted: false } };
  }

  // Is this address on the known-dangerous list? Returns null or { source, match }.
  // Whole websites match exactly or below; single addresses match that address
  // and below it (at a "/" boundary), compared after reading both the same way.
  function knownThreat(parsed) {
    if (!parsed.ok || !parsed.isWeb) return null;
    const list = threatList();
    const domain = list.domains.find(d => isSameOrSubdomain(parsed.hostname, d));
    if (domain) return { source: list.source, match: domain };
    for (const entry of list.urls) {
      const listed = parseUrl(entry);
      if (!listed.ok || listed.hostname !== parsed.hostname) continue;
      const base = listed.pathname.endsWith('/') ? listed.pathname : listed.pathname + '/';
      if (parsed.pathname === listed.pathname || parsed.pathname.startsWith(base)) return { source: list.source, match: entry };
    }
    return null;
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
    return [{
      code: 'HIDDEN_DESTINATION',
      subject: 'link',
      data: { shown, host: parsed.host },
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
      // Your own computer (localhost) counts as secure, as it does in Chrome.
      const ownComputer = /^(localhost|.+\.localhost|127(\.\d{1,3}){3}|\[::1\])$/.test(action.hostname);
      if (action.protocol === 'http:' && !ownComputer && !seen.has('INSECURE_FORM')) {
        seen.add('INSECURE_FORM');
        add('INSECURE_FORM', {}, action.href);
      }
    }
    if (isFreeHosting(page.hostname)) add('SIGN_IN_ON_FREE_HOSTING', {}, page.href);
    return findings;
  }

  core.urlRules = { SHORTENERS, RISKY_ENDINGS, knownThreat, isKnownThreat, checkAddress, checkSignInLink, checkShownDestination, checkSecretForms };
  if (typeof module !== 'undefined') module.exports = core.urlRules;
})();
