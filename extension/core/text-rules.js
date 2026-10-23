// text-rules.js: scam wording.
//
// There are two sets of checks:
//   EMAIL_CHECKS  for an email someone received. It's written TO them, so
//                 "gift card" or "your account is locked" means something.
//   WEB_CHECKS    for websites, ads, and the words around a link. Webpages
//                 are full of ordinary words like "urgent" or "lottery"
//                 (think news stories), so these look for wording aimed AT
//                 the reader: "YOU have won", "YOUR computer is infected".
// Each check can only count once, however many times its words appear.
//
// How much each sign counts, and which signs need backing up by another,
// is decided in risk-policy.js. The words people see are in explanations.js.

(function () {
  'use strict';
  const core = globalThis.GranblockCore = globalThis.GranblockCore || {};

  // In the money rules, "(?:[^.!]|\.\d)" means "within the same sentence", where a
  // dot followed by a digit ("$1.99") doesn't end the sentence.

  // Asking for money now, and threats if you don't. Shared by both sets.
  // Written to the reader ("YOU will be arrested"), so news stories don't count.
  const PAYMENT_DEMAND = {
    code: 'PAYMENT_DEMAND',
    patterns: [
      /\b(pay|payment|settle|remit)\b(?:[^.!]|\.\d){0,30}\b(now|today|immediately|overdue|outstanding|owed|past due)\b/,
      /\b(outstanding|overdue|unpaid|past due) (balance|invoice|bill|amount|payment|debt|taxes)\b/,
      /\byou owe\b/,
      /\bsend (me |us )?(\$\s?\d|money|funds|the payment)/,
      /\btransfer (the )?(money|funds|\$\s?\d)/,
    ],
  };
  const THREAT_OF_CONSEQUENCES = {
    code: 'THREAT_OF_CONSEQUENCES',
    patterns: [
      /\b(you|your)\b(?:[^.!]|\.\d){0,40}\b(will be|could be|be) (arrested|sued|prosecuted|deported|jailed)\b/,
      /\b(warrant|legal action|lawsuit|court action|criminal charges)\b(?:[^.!]|\.\d){0,40}\b(against you|in your name|for your arrest)\b/,
      /\b(arrest|legal action|lawsuit|prosecution|penalties|charges)\b(?:[^.!]|\.\d){0,30}\b(if you|unless you)\b/,
      /\byour (social security( number)?|benefits|license|medicare|ssn)\b(?:[^.!]|\.\d){0,30}\b(suspended|cancell?ed|revoked|frozen|blocked)\b/,
    ],
  };

  // Pay a fee first: to claim a prize, release a package, or with gift cards.
  const PAY_TO_CLAIM = {
    code: 'PAY_TO_CLAIM',
    patterns: [
      /\b(pay|fee|shipping|processing|handling)\b(?:[^.!]|\.\d){0,40}\bto (claim|receive|release|unlock|get) (your|the)\b/,
      /\b(re-?delivery|customs|shipping|delivery|release) fee\b(?:[^.!]|\.\d){0,40}\b(pay|of \$|\$\s?\d)|\bpay\b(?:[^.!]|\.\d){0,30}\b(re-?delivery|customs|shipping|delivery) fee\b/,
      /\b(pay|buy|send|purchase)\b(?:[^.!]|\.\d){0,30}\b(gift ?cards?|bitcoin|crypto|wire transfer|western union|moneygram)/,
    ],
  };

  const EMAIL_CHECKS = [
    { code: 'PAYMENT_METHOD_REQUEST', patterns: [/gift ?cards?/, /wire transfer/, /\bbitcoin\b/, /\bcrypto/, /western union/, /moneygram/, /\bzelle\b/] },
    { code: 'ACCOUNT_PROBLEM_CLAIM', patterns: [/\b(account|card|access|profile|service)\b[^.!]{0,30}\b(suspended|locked|disabled|on hold)\b/, /\b(suspended|locked|disabled)\b[^.!]{0,30}\b(account|card)\b/, /unusual (sign-?in )?activity/, /verify your (account|identity)/, /confirm your (account|identity)/, /update your (payment|billing)/, /unauthori[sz]ed/] },
    { code: 'PRESSURE_TACTICS', patterns: [/\burgent/, /immediately/, /within (24|48|72) hours/, /act now/, /final notice/, /last warning/, /expires today/] },
    { code: 'SECRECY_REQUEST', patterns: [/(don'?t|do not) tell/, /keep (this|it) (a )?secret/, /between (us|you and me)/] },
    { code: 'PRIZE_CLAIM', patterns: [/you('ve| have) won/, /claim your (prize|reward)/, /\blottery\b/, /\binheritance\b/, /unclaimed (funds|money)/] },
    { code: 'PERSONAL_INFO_REQUEST', patterns: [/social security number/, /\bssn\b/, /routing number/, /account number/, /date of birth/, /your password/] },
    { code: 'DELIVERY_PROBLEM_CLAIM', patterns: [/could not be delivered/, /couldn'?t be delivered/, /package (is )?on hold/, /(re-?delivery|customs|shipping) fee/, /reschedule (your )?delivery/] },
    { code: 'TECH_SUPPORT_CLAIM', patterns: [/remote access/, /\banydesk\b/, /\bteamviewer\b/, /tech(nical)? support/, /your (computer|pc|device) (is|has been) (infected|hacked)/, /\b(computer|pc|device) (has )?(a )?virus/, /\bvirus(es)? (detected|found|on your)/] },
    PAY_TO_CLAIM,
    PAYMENT_DEMAND,
    THREAT_OF_CONSEQUENCES,
  ];

  const WEB_CHECKS = [
    {
      code: 'PRIZE_CLAIM',
      patterns: [
        /\byou('ve| have)? (just )?(won|been selected|been chosen)\b/,
        /\bclaim your (free )?(prize|reward|gift|winnings|cash)/,
        /\bcongratulations\b[^.!]{0,60}\b(won|winner|selected|chosen)\b/,
        /\byou are (our|today'?s|the) (lucky )?winner/,
      ],
    },
    PAY_TO_CLAIM,
    {
      code: 'ACCOUNT_PROBLEM_CLAIM',
      patterns: [
        /\byour (account|card|computer|device|pc|phone|iphone|mac)\b[^.!]{0,40}\b(locked|suspended|infected|compromised|hacked|disabled|blocked)\b/,
        /\b(virus(es)?|malware|trojan|spyware)\b[^.!]{0,30}\b(detected|found)\b/,
      ],
    },
    {
      code: 'CALL_THIS_NUMBER',
      patterns: [
        /\bcall\b[^.!]{0,40}(\(?\d{3}\)?[-. ]?\d{3}[-. ]\d{4}|toll[- ]free)/,
        /\b(do not|don'?t) (close|restart|shut down|turn off)\b[^.!]{0,30}\b(computer|browser|page|window)/,
      ],
    },
    {
      code: 'DELIVERY_PROBLEM_CLAIM',
      patterns: [
        /\byour (package|parcel|delivery|shipment)\b[^.!]{0,40}\b(on hold|could not be delivered|couldn'?t be delivered|undeliverable|held|is waiting|was returned)\b/,
        /\b(re-?delivery|customs|shipping) fee\b/,
      ],
    },
    PAYMENT_DEMAND,
    THREAT_OF_CONSEQUENCES,
    {
      code: 'PRESSURE_TACTICS',
      patterns: [
        /\burgent/, /\bimmediately\b/, /within (24|48|72) hours/, /\bact (now|fast)\b/, /\blast chance\b/,
        /\bfinal notice\b/, /before midnight/, /expires (today|tonight|in \d+)/, /\bonly \d+ (left|remaining|minutes)/,
      ],
    },
  ];

  // Words used when someone is WARNING about scams rather than running one:
  // a news story, a bank's safety page. Scam pages almost never say "scam".
  const SCAM_ADVICE = /\bscam(s|mer|mers|med)?\b|\bphishing\b|\bfraudsters?\b|\bimpost[eo]rs?\b/g;

  function runChecks(checks, text, variant) {
    const lower = (text || '').toLowerCase();
    const findings = [];
    for (const check of checks) {
      for (const pattern of check.patterns) {
        const match = lower.match(pattern);
        if (match) {
          findings.push({ code: check.code, subject: 'text', data: { variant }, evidence: { kind: 'text', value: match[0] } });
          break;
        }
      }
    }
    return findings;
  }

  // Wording in an email.
  function checkEmailText(text) {
    const findings = runChecks(EMAIL_CHECKS, text, 'email');
    // "Grandparent scam": someone claims a family member is in trouble and needs money fast.
    const lower = (text || '').toLowerCase();
    const family = lower.match(/\b(grandma|grandpa|grandmother|grandfather|nana|papa)\b/);
    const trouble = lower.match(/\b(bail|jail|arrested|hospital|accident|lawyer)\b/);
    const money = /\b(money|bail|send|wire|gift ?cards?|pay|cash|help me)\b/.test(lower);
    if (family && trouble && money) {
      findings.push({ code: 'FAMILY_EMERGENCY', subject: 'text', data: { variant: 'email' }, evidence: { kind: 'text', value: `${family[0]} … ${trouble[0]}` } });
    }
    return findings;
  }

  // Wording on a website, in an ad, or around a link.
  function checkWebText(text) {
    return runChecks(WEB_CHECKS, text, 'web');
  }

  // What kind of message is this? Decides how much a company-name mismatch matters.
  //   'alert'      account, security, payment, or delivery notices: what scammers fake
  //   'marketing'  newsletters and ads (often sent through email services)
  //   'personal'   anything else
  const STRONG_ALERT = /\b(password|sign-?in|log-?in|security|verify|verification|suspend(ed)?|locked|unusual|unauthori[sz]ed|payment (failed|declined)|declined|on hold|could not be delivered|undeliverable|delivery (attempt|failed)|redelivery|overdue|past due|final notice|refund|you owe)\b/;
  const ALERT = /\b(account|billing|invoice|statement|package|parcel|shipment|tracking)\b/;
  const MARKETING = /\b(unsubscribe|newsletter|manage (your )?(email )?preferences|view (this email )?in (your )?browser|\d+% off|shop now)\b/;
  function messageKind(subject, text) {
    const all = `${subject || ''}\n${(text || '').slice(0, 3000)}`.toLowerCase();
    if (STRONG_ALERT.test(all)) return 'alert';
    if (MARKETING.test(all)) return 'marketing';
    if (ALERT.test(all)) return 'alert';
    return 'personal';
  }

  // Is this text talking ABOUT scams (two or more mentions)?
  function looksLikeScamAdvice(text) {
    return ((text || '').toLowerCase().match(SCAM_ADVICE) || []).length >= 2;
  }

  core.textRules = { EMAIL_CHECKS, WEB_CHECKS, checkEmailText, checkWebText, looksLikeScamAdvice, messageKind };
  if (typeof module !== 'undefined') module.exports = core.textRules;
})();
