// data/threat-list.js: DATA. Websites we KNOW are dangerous ("threat intelligence").
//
// Anything on this list is blocked twice:
//   1. service-worker.js tells Chrome to stop the page from ever loading
//      (this also catches typed addresses, redirects, and pop-ups).
//   2. guard.js stops a click on a link to it and explains why.
//
// Right now this is a PRACTICE list of made-up ".example" addresses, so we can
// test and demo blocking safely. These can never be real websites.
// Next step (README roadmap, Step 4): fill this from a maintained source of
// known phishing and malware sites. Never paste real scam links into this repo
// by hand.
//
// Where this list comes from. Only a TRUSTED source can make the extension
// block something outright; anything else is a strong warning the person can
// choose to go past. Mark a real source trusted only after checking how it
// confirms entries and what its terms allow (README roadmap, Step 4b).
const KNOWN_THREAT_SOURCE = { name: 'Practice list (made-up .example addresses)', trusted: true };

// Whole websites. A listed address also covers everything under it:
// "known-phish.example" covers "login.known-phish.example" too.
const KNOWN_THREAT_DOMAINS = [
  'known-phish.example',
  'fake-bank-login.example',
  'malware-download.example',
];

// Single dangerous addresses on websites that are otherwise fine, such as a
// fake sign-in page planted on a hacked blog. Covers that address and
// everything below it, nothing else on the website.
const KNOWN_THREAT_URLS = [
  'https://hacked-blog.example/wp-content/uploads/secure/',
];

if (typeof module !== 'undefined') {
  module.exports = { KNOWN_THREAT_SOURCE, KNOWN_THREAT_DOMAINS, KNOWN_THREAT_URLS };
}
