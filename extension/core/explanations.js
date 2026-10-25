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
      explain: (d, s) => {
        if (onPage(s)) return `This website (${d.host}) is on a list of known dangerous websites.`;
        if (s === 'form') return `What you type on this page would be sent to ${d.host}, which is on a list of known dangerous websites.`;
        if (d.via) return `A link passes through ${d.via} on its way to ${d.host}, which is on a list of known dangerous websites.`;
        return `A link goes to ${d.host}, which is on a list of known dangerous websites.`;
      },
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
      explain: d => {
        if (d.variant === 'via_service') return `A link says it goes to ${d.shown}, but it first passes through ${d.service}, a service that counts clicks, so we can't see where it really ends up.`;
        if (d.shownBrand) return `A link says it goes to ${d.shown}, ${d.shownBrand}'s real website, but it really goes to ${d.host}.`;
        return `A link says it goes to ${d.shown}, but it really goes to ${d.host}.`;
      },
      flag: () => 'hidden destination',
    },
    MISLEADING_URL: {
      title: 'Misleading address',
      explain: d => {
        if (d.trick === 'before_at') return `A link is written to look like it goes to ${d.shown}, but it really goes to ${d.host}.`;
        if (d.trick === 'hidden_login') return `A link has a hidden sign-in name or password written into it, and goes to ${d.host}. Normal links don't do this.`;
        return `A link's address includes ${d.shown}, but it really goes to ${d.host}.`;
      },
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
      explain: d => {
        if (d.variant === 'offer') return `The offer mentions ${d.brand}, but the link goes to ${d.host}, not ${d.brand}'s real website.`;
        if (d.variant === 'message') return `This email says it's from ${d.brand}, but none of its links go to ${d.brand}'s real website (one goes to ${d.host}).`;
        return `A link mentions ${d.brand}, but it goes to ${d.host}.`;
      },
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
      explain: d => d.service
        ? `This offer's link passes through ${d.service}, an advertising or email service, so we couldn't check which company it really leads to.`
        : `We could not confirm that ${d.host} belongs to the company in this offer.`,
    },
    SENDER_NAME_MISMATCH: {
      title: 'Sender doesn\'t match',
      explain: d => {
        if (d.variant === 'address_in_name') return `The sender's name shows the address ${d.shown}, but the email really came from ${d.address}.`;
        if (d.variant === 'free_mail') return `The sender's name says ${d.brand}, but it came from a free personal email account (${d.address}). ${d.brand} never does this.`;
        if (d.variant === 'alert') return `This looks like an official notice from ${d.brand}, but it came from ${d.address}, not one of ${d.brand}'s own email addresses.`;
        return `The sender's name says ${d.brand}, but the email address (${d.address}) is not from ${d.brand}. Companies sometimes send ads through other services, so this alone isn't proof.`;
      },
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
      explain: d => `This page looks like a sign-in or payment page for ${d.brand}, but it is on ${d.host}, not ${d.brand}'s real website.`,
    },
    IMPERSONATED_SITE: {
      title: 'Pretending to be a company',
      explain: d => `This page calls itself ${d.brand}, but it is on ${d.host}, not ${d.brand}'s real website. Fake shops copy real ones to take your money or details.`,
    },
    SIGN_IN_ON_FREE_HOSTING: {
      title: 'Sign-in on a free website',
      explain: (d, s) => onPage(s)
        ? `This page asks for a password or card number, but it's on ${d.host}, a free website anyone can make. Real banks and companies never do this.`
        : `A sign-in link goes to ${d.host}, a free website anyone can make. Real banks and companies never put their sign-in pages there.`,
      flag: () => 'sign-in on a free website',
    },
    INSECURE_FORM: {
      title: 'Not sent securely',
      explain: () => 'What you type on this page would be sent without protection, so others could read it.',
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
      explain: () => 'It asks you to pay a fee before you get something (a prize or a package), or to pay with gift cards, crypto, or a wire transfer. Real companies don\'t work this way.',
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
      explain: () => 'It says a package couldn\'t be delivered or needs a fee. Fake delivery notices are a very common scam. Check the tracking number on the shipper\'s real website instead.',
    },
    SECRECY_REQUEST: {
      title: 'Asks you to keep a secret',
      explain: () => 'It asks you to keep a secret. Real family and real companies don\'t ask that.',
    },
    FAMILY_EMERGENCY: {
      title: 'Family emergency',
      explain: () => 'It says a family member is in trouble and needs help fast. Call that person directly using a phone number you already have.',
    },
    UNEXPECTED_CHARGE: {
      title: 'Surprise charge, call to cancel',
      explain: () => 'It says you were charged for something and gives a phone number to cancel or get a refund. This is how "refund" scams start. Don\'t call: check your bank or card statement yourself.',
    },
    PAYMENT_DEMAND: {
      title: 'Asks for money',
      explain: () => 'It asks you to pay or send money.',
    },
    THREAT_OF_CONSEQUENCES: {
      title: 'Threatens you',
      explain: () => 'It threatens you with arrest, legal action, or losing your benefits. Real agencies and companies don\'t threaten people by email or pop-up.',
    },
    URGENT_PAYMENT_REQUEST: {
      title: 'Urgent demand for money',
      explain: () => 'It asks for money AND rushes or threatens you. Together, these are a classic scam pattern. Check with the company or agency using a number you already have.',
    },
    AGENCY_DOES_NOT_EMAIL: {
      title: 'Agency that doesn\'t email first',
      explain: d => `This says it's from ${d.brand} and asks for money or personal details. ${d.brand} says it never emails people first to ask for these.`,
    },
    PRESSURE_TACTICS: {
      title: 'Rushing you',
      explain: d => d.variant === 'email'
        ? 'It tries to rush you. Real companies give you time to think.'
        : 'It tries to rush you.',
    },
    INVESTMENT_PROMISE: {
      title: 'Promises big profits',
      explain: () => 'It promises guaranteed, risk-free, or very large profits. Real investments never guarantee profits; promises like this are how investment scams pull people in.',
    },
    CRYPTO_GIVEAWAY: {
      title: 'Send crypto, get more back',
      explain: () => 'It asks you to send crypto and promises to send back more. This is always a scam: nothing comes back.',
    },
    CELEBRITY_ENDORSEMENT: {
      title: 'Famous name on an investment',
      explain: d => `It uses the name ${d.name || 'of a famous person'} to sell an investment or crypto offer. Scammers put famous names and faces on fake ads without permission.`,
    },
    DEPOSIT_TO_TRADE: {
      title: 'Deposit to start trading',
      explain: () => 'It asks you to put money in, often in crypto, to start trading or investing.',
    },
    INVESTMENT_PITCH: {
      title: 'Profits plus a deposit',
      explain: () => 'It sells an investment with big promises or a famous name AND asks you to put money in. Together, this is how investment scams work. Talk to someone you trust before investing.',
    },
    JOB_FEE: {
      title: 'Pay to start a job',
      explain: () => 'It offers a job but asks you to pay first, for equipment, training, or a fee. Real employers pay you; they never ask you to pay them.',
    },
    OVERPAYMENT: {
      title: 'Send back the difference',
      explain: () => 'It asks you to deposit a check and send part of the money back. The check will bounce days later, and the money you sent will be gone.',
    },
    JOB_DETAILS_REQUEST: {
      title: 'Job asks for private details',
      explain: () => 'It offers a job and asks you to send private details, like your Social Security or bank account number, by email or text. Real employers collect these in person or on a secure form.',
    },
    RECOVERY_FEE: {
      title: 'Pay to get money back',
      explain: () => 'It offers to get back money you lost, for a fee. This is a second scam aimed at people who were already scammed. Your bank and the police don\'t charge to help.',
    },
    SEXTORTION_THREAT: {
      title: 'Blackmail threat',
      explain: () => 'It threatens to send private videos or photos to people you know unless you pay. These emails are sent to millions of people, and the "recording" almost never exists. Don\'t pay and don\'t reply.',
    },
    CHARGE_WITH_PRESSURE: {
      title: 'Surprise charge and a deadline',
      explain: () => 'It says you were charged AND gives you a deadline to call. Scammers rush you so you call before checking your bank or card statement.',
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
