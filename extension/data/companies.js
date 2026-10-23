// companies.js: DATA. The companies and agencies scammers pretend to be most
// often, their official websites and email addresses, and what they say about
// themselves (the IRS never emails first to ask for money or details).
//
// These are facts to check, not rules: core/domain-rules.js uses them. A wrong
// official website lets a fake through; a missing one flags a real link. Check
// every entry on the organization's own website, and add a test with it
// (tests/rules.test.js, tests/fixtures/regression/).

(function () {
  'use strict';
  const data = globalThis.GranblockData = globalThis.GranblockData || {};

  // Before adding anything here, check it on the organization's own website.
  const BRANDS = [
    { label: 'PayPal', nameRe: /paypal/i, keys: ['paypal'], domains: ['paypal.com', 'paypal.me', 'paypal.co.uk'] },
    { label: 'Amazon', nameRe: /amazon/i, keys: ['amazon'], domains: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.com.au'] },
    { label: 'Apple', nameRe: /\bapple\b|icloud/i, keys: ['apple', 'icloud'], domains: ['apple.com', 'icloud.com'] },
    { label: 'Microsoft', nameRe: /microsoft|office ?365/i, keys: ['microsoft', 'office365'], domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com'] },
    { label: 'Netflix', nameRe: /netflix/i, keys: ['netflix'], domains: ['netflix.com'] },
    { label: 'Chase', nameRe: /\bchase\b/i, keys: ['chase'], domains: ['chase.com'] },
    { label: 'Wells Fargo', nameRe: /wells ?fargo/i, keys: ['wellsfargo'], domains: ['wellsfargo.com'] },
    { label: 'Bank of America', nameRe: /bank of america/i, keys: ['bankofamerica', 'bofa'], domains: ['bankofamerica.com', 'bofa.com'] },
    // irs.gov: "The IRS doesn't initiate contact with taxpayers by email ... to request personal or financial information."
    { label: 'the IRS', nameRe: /\birs\b|internal revenue/i, keys: ['irs'], domains: ['irs.gov'], asksByEmail: false },
    { label: 'Social Security', nameRe: /social security/i, keys: ['ssa', 'socialsecurity'], domains: ['ssa.gov'] },
    { label: 'the Post Office (USPS)', nameRe: /\busps\b|postal service/i, keys: ['usps'], domains: ['usps.com'] },
    { label: 'FedEx', nameRe: /fedex/i, keys: ['fedex'], domains: ['fedex.com'] },
    { label: 'UPS', nameRe: /\bups\b/i, keys: ['ups'], domains: ['ups.com'] },
  ];


  // "amazonaws.com" is where anyone can put files, not Amazon's shop.
  const NOT_IMPERSONATION = ['amazonaws.com'];


  // Words scammers glue onto a short company name: "applesupport", "chase-secure".
  const SCAM_AFFIXES = [
    'secure', 'security', 'support', 'login', 'signin', 'verify', 'verification', 'account', 'accounts', 'id',
    'help', 'service', 'services', 'billing', 'update', 'alert', 'alerts', 'online', 'bank', 'banking', 'pay',
    'payment', 'care', 'team', 'center', 'centre', 'mail', 'notice', 'auth',
  ];

  data.companies = { BRANDS, NOT_IMPERSONATION, SCAM_AFFIXES };
  if (typeof module !== 'undefined') module.exports = data.companies;
})();
