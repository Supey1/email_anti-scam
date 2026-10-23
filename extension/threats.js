// threats.js: websites already known to be dangerous.
// Used in two places: the service worker blocks these before the page loads,
// and the link guard stops clicks on them.
//
// This is a small built-in list for the demo, using made-up ".example" addresses
// that can never be real websites. A real, maintained source (like Google Safe
// Browsing) is roadmap Step 4; it would be plugged in through lookupThreat().

const THREAT_DOMAINS = [
  'known-phish.example',
  'fake-bank-login.example',
];

// Returns the matching threat domain for a hostname, or null.
function lookupThreat(host) {
  host = (host || '').toLowerCase().replace(/^www\./, '');
  return THREAT_DOMAINS.find(d => host === d || host.endsWith('.' + d)) || null;
}

// Lets tests load this file with Node. Chrome ignores this.
if (typeof module !== 'undefined') {
  module.exports = { THREAT_DOMAINS, lookupThreat };
}
