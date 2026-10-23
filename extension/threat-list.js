// threat-list.js: websites we KNOW are dangerous ("threat intelligence").
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
// A listed address also blocks everything under it:
// "known-phish.example" blocks "login.known-phish.example" too.

const KNOWN_THREAT_DOMAINS = [
  'known-phish.example',
  'fake-bank-login.example',
  'malware-download.example',
];

if (typeof module !== 'undefined') {
  module.exports = { KNOWN_THREAT_DOMAINS };
}
