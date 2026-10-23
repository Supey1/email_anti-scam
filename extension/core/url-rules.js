// url-rules.js: warning signs in where a link (or the page you're on) really goes.
//
// These look at the address itself: known dangerous websites, number
// addresses, shortened links, risky endings, and addresses written to
// mislead. Whether an address pretends to be a company is in domain-rules.js.
//
// Each check returns "findings": { code, subject, data, evidence: { kind, value } }.

(function () {
  'use strict';
  const core = globalThis.GranblockCore = globalThis.GranblockCore || {};
  if (typeof require !== 'undefined' && !core.urlNormalizer) require('./url-normalizer.js');
  if (typeof require !== 'undefined' && !core.domainRules) require('./domain-rules.js');
  const { isSameOrSubdomain, sameSite, findDomainInText } = core.urlNormalizer;
  const { BRANDS } = core.domainRules;

  // Link shorteners hide where a link really goes.
  const SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
    'cutt.ly', 'shorturl.at', 'rb.gy', 't.ly', 'tiny.cc',
  ]);

  // Website endings that are cheap and often used by scam sites.
  const RISKY_ENDINGS = new Set(['xyz', 'top', 'click', 'zip', 'mov', 'icu', 'buzz', 'cfd', 'sbs', 'rest', 'lol']);

  // The list in threat-list.js. In Chrome it's already loaded; in tests we load it here.
  function knownThreatDomains() {
    if (typeof KNOWN_THREAT_DOMAINS !== 'undefined') return KNOWN_THREAT_DOMAINS;
    if (typeof require !== 'undefined') return require('../threat-list.js').KNOWN_THREAT_DOMAINS;
    return [];
  }

  function isKnownThreat(hostname) {
    return knownThreatDomains().some(d => isSameOrSubdomain(hostname, d));
  }

  // Checks an address. subject is 'link' or 'page' (it changes only the wording).
  // parsed comes from urlNormalizer.normalizeUrl().
  function checkAddress(parsed, subject) {
    if (!parsed.ok || !parsed.isWeb) return [];
    const { hostname, host } = parsed;
    const findings = [];
    const add = (code, data = {}, evidence = { kind: 'domain', value: hostname }) =>
      findings.push({ code, subject, data: { host, ...data }, evidence });

    if (isKnownThreat(hostname)) add('KNOWN_THREAT');
    if (parsed.isIp) add('NUMBER_ADDRESS', {}, { kind: 'url', value: parsed.href });
    if (SHORTENERS.has(host)) add('SHORTENED_LINK', {}, { kind: 'url', value: parsed.href });

    const ending = hostname.split('.').pop();
    if (RISKY_ENDINGS.has(ending)) add('RISKY_DOMAIN_ENDING', { ending });

    // The rest are tricks in how a LINK is written; the page you're on has already loaded.
    if (subject !== 'link') return findings;

    // "https://www.paypal.com@evil.example": everything before "@" is decoration.
    if (parsed.username.includes('.')) {
      add('MISLEADING_URL', { shown: parsed.username, trick: 'before_at' }, { kind: 'url', value: parsed.href });
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

  core.urlRules = { SHORTENERS, RISKY_ENDINGS, isKnownThreat, checkAddress, checkShownDestination };
  if (typeof module !== 'undefined') module.exports = core.urlRules;
})();
