// explanations.js: turns each warning sign into plain words.
//
// Every reason code from docs/interfaces.md has:
//   title    a short label
//   explain  one plain sentence with the details (company, website), written
//            the way you'd explain it to your grandparent
//   flag     a few words for the list of links in the Gmail panel (link signs only)
// "subject" says what the sign is about: 'link', 'page', 'sender', or 'text'.
// For wording, data.variant says whether it was found in an 'email' or on the 'web'.
//
// What the person should DO comes from the result's recommendedAction; the
// warning screen (Person B) words that part.

(function () {
  'use strict';
  const core = globalThis.GranblockCore = globalThis.GranblockCore || {};

  const onPage = subject => subject === 'page';

  const EXPLANATIONS = {
    KNOWN_THREAT: {
      title: 'Known dangerous website',
      explain: (d, s) => onPage(s)
        ? `This website (${d.host}) is on a list of known dangerous websites.`
        : `A link goes to ${d.host}, which is on a list of known dangerous websites.`,
      flag: () => 'known dangerous website',
    },
    LOOKALIKE_DOMAIN: {
      title: 'Fake company address',
      explain: (d, s) => {
        if (d.technique === 'official_domain_in_front') {
          return `${onPage(s) ? 'This website\'s address' : 'A link\'s address'} starts with ${d.officialDomain}, but it really belongs to ${d.registrable}, not ${d.brand}.`;
        }
        if (d.technique === 'other_alphabet') {
          return `${onPage(s) ? 'This website\'s name' : 'A link'} uses letters from another alphabet to look like ${d.brand}, but ${d.host} is not ${d.brand}'s real website.`;
        }
        if (d.technique === 'misspelling') {
          return `${onPage(s) ? 'This website\'s name' : 'A link'} is a misspelling of ${d.brand}: ${d.host} is not ${d.brand}'s real website.`;
        }
        return onPage(s)
          ? `This website's name pretends to be ${d.brand}, but ${d.host} is not ${d.brand}'s real website.`
          : `A link pretends to be ${d.brand}, but it goes to ${d.host}, not ${d.brand}'s real website.`;
      },
      flag: d => `fake ${d.brand} site`,
    },
    HIDDEN_DESTINATION: {
      title: 'Link goes somewhere else',
      explain: d => `A link says it goes to ${d.shown}, but it really goes to ${d.host}.`,
      flag: () => 'hidden destination',
    },
    MISLEADING_URL: {
      title: 'Misleading address',
      explain: d => d.trick === 'before_at'
        ? `A link is written to look like it goes to ${d.shown}, but it really goes to ${d.host}.`
        : `A link's address includes ${d.shown}, but it really goes to ${d.host}.`,
      flag: () => 'misleading address',
    },
    NUMBER_ADDRESS: {
      title: 'Number address',
      explain: (d, s) => onPage(s)
        ? 'This page is on a number address instead of a normal website name. Real companies almost never do this.'
        : 'A link goes to a number address instead of a normal website name. Real companies almost never do this.',
      flag: () => 'number address',
    },
    BRAND_NAME_MISMATCH: {
      title: 'Company name doesn\'t match',
      explain: d => d.variant === 'offer'
        ? `The offer mentions ${d.brand}, but the link goes to ${d.host}, not ${d.brand}'s real website.`
        : `A link mentions ${d.brand}, but it goes to ${d.host}.`,
      flag: d => `not really ${d.brand}`,
    },
    SHORTENED_LINK: {
      title: 'Shortened link',
      explain: () => 'A link is shortened, which hides where it really goes.',
      flag: () => 'shortened link',
    },
    RISKY_DOMAIN_ENDING: {
      title: 'Unusual website ending',
      explain: (d, s) => onPage(s)
        ? `This website ends in ".${d.ending}", which scam sites often use.`
        : `A link goes to a website ending in ".${d.ending}", which scam sites often use.`,
      flag: () => 'risky website ending',
    },
    UNVERIFIED_PRIZE_CLAIM: {
      title: 'Unverified prize offer',
      explain: d => `We could not confirm that ${d.host} belongs to the company in this offer.`,
    },
    SENDER_NAME_MISMATCH: {
      title: 'Sender doesn\'t match',
      explain: d => `The sender's name says ${d.brand}, but the email address (${d.address}) is not from ${d.brand}.`,
    },
    LOOKALIKE_SENDER: {
      title: 'Fake sender address',
      explain: d => `The sender's address (${d.address}) pretends to be ${d.brand}, but it isn't ${d.brand}'s real address.`,
    },
    COMPANY_ON_FREE_EMAIL: {
      title: 'Company using a personal email',
      explain: d => `The sender says it is a company or department, but it uses a free personal email address (${d.address}).`,
    },
    FAKE_SIGN_IN_PAGE: {
      title: 'Fake sign-in page',
      explain: d => `This page looks like a ${d.brand} sign-in page, but it is on ${d.host}, not ${d.brand}'s real website.`,
    },
    CREDENTIALS_SENT_ELSEWHERE: {
      title: 'Details sent elsewhere',
      explain: d => `What you type on this page would be sent to a different website (${d.elsewhere}).`,
    },
    PRIZE_CLAIM: {
      title: 'Prize offer',
      explain: d => d.variant === 'email'
        ? 'It says you won something or are owed money. This is a very common scam.'
        : 'It promises you a prize or a reward.',
    },
    PRIZE_WITH_PRESSURE: {
      title: 'Prize and rushing',
      explain: () => 'It promises a prize AND rushes you. Together, these are a classic scam pattern.',
    },
    PAY_TO_CLAIM: {
      title: 'Pay first',
      explain: () => 'It asks you to pay first, or to pay with gift cards, crypto, or a wire transfer. Real prizes and real companies don\'t work this way.',
    },
    PAYMENT_METHOD_REQUEST: {
      title: 'Hard-to-refund payment',
      explain: () => 'It mentions gift cards, wire transfers, or crypto. Scammers ask for these because the money can\'t be gotten back.',
    },
    ACCOUNT_PROBLEM_CLAIM: {
      title: 'Account problem',
      explain: d => d.variant === 'email'
        ? 'It says something is wrong with your account. This is a common trick to get you to log in on a fake page.'
        : 'It says your account or computer has a serious problem.',
    },
    CALL_THIS_NUMBER: {
      title: 'Call this number',
      explain: () => 'It tells you to call a phone number, or not to close the page. Real security warnings never do this.',
    },
    TECH_SUPPORT_CLAIM: {
      title: 'Tech support',
      explain: () => 'It talks about computer viruses or "tech support." Real companies won\'t contact you this way.',
    },
    PERSONAL_INFO_REQUEST: {
      title: 'Asks for private details',
      explain: () => 'It asks about private information like account numbers or passwords. Never send these by email.',
    },
    DELIVERY_PROBLEM_CLAIM: {
      title: 'Delivery problem',
      explain: () => 'It says a package couldn\'t be delivered. Fake delivery notices are a very common scam. Check the tracking number on the shipper\'s real website instead.',
    },
    SECRECY_REQUEST: {
      title: 'Asks you to keep a secret',
      explain: () => 'It asks you to keep a secret. Real family and real companies don\'t ask that.',
    },
    FAMILY_EMERGENCY: {
      title: 'Family emergency',
      explain: () => 'It says a family member is in trouble and needs help fast. Call that person directly using a phone number you already have.',
    },
    PRESSURE_TACTICS: {
      title: 'Rushing you',
      explain: d => d.variant === 'email'
        ? 'It tries to rush you. Real companies give you time to think.'
        : 'It tries to rush you.',
    },
    INSIDE_SCAM_EMAIL: {
      title: 'Inside a scam email',
      explain: () => 'This link is inside an email that looks like a scam.',
    },
  };

  // A finding -> { code, title, explanation }, as in docs/interfaces.md.
  function explain(finding) {
    const entry = EXPLANATIONS[finding.code];
    if (!entry) return { code: finding.code, title: finding.code, explanation: 'A warning sign was found.' };
    return { code: finding.code, title: entry.title, explanation: entry.explain(finding.data || {}, finding.subject) };
  }

  // A link finding -> a few words for the Gmail panel's list of links, or ''.
  function flagFor(finding) {
    const entry = EXPLANATIONS[finding.code];
    return entry && entry.flag ? entry.flag(finding.data || {}) : '';
  }

  core.explanations = { EXPLANATIONS, explain, flagFor };
  if (typeof module !== 'undefined') module.exports = core.explanations;
})();
