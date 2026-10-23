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
  if (typeof require !== 'undefined' && !(globalThis.GranblockData && globalThis.GranblockData.people)) require('../data/people.js');
  const { ENDORSERS } = globalThis.GranblockData.people;

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
  const PAY_A_FEE = [
    /\b(pay|fee|shipping|processing|handling)\b(?:[^.!]|\.\d){0,40}\bto (claim|receive|release|unlock|get) (your|the)\b/,
    /\bto (claim|receive|release|unlock|get) (your|the)\b(?:[^.!]|\.\d){0,40}\b(pay|fee)\b/, // "To release your winnings, pay a fee"
    /\b(re-?delivery|customs|shipping|delivery|release) fee\b(?:[^.!]|\.\d){0,40}\b(pay|of \$|\$\s?\d)|\bpay\b(?:[^.!]|\.\d){0,30}\b(re-?delivery|customs|shipping|delivery) fee\b/,
  ];
  const PAY_HARD_TO_REFUND = /\b(pay|buy|send|purchase)\b(?:[^.!]|\.\d){0,30}\b(gift ?cards?|bitcoin|crypto|wire transfer|western union|moneygram)/;
  // Websites and ads: fees, and paying with gift cards or crypto.
  const PAY_TO_CLAIM = { code: 'PAY_TO_CLAIM', patterns: [...PAY_A_FEE, PAY_HARD_TO_REFUND] };
  // Emails: fees only. Gift cards and crypto already have their own email check
  // (PAYMENT_METHOD_REQUEST); counting them twice would say the same thing twice.
  const PAY_TO_CLAIM_EMAIL = { code: 'PAY_TO_CLAIM', patterns: PAY_A_FEE };

  const EMAIL_CHECKS = [
    { code: 'PAYMENT_METHOD_REQUEST', patterns: [/gift ?cards?/, /wire transfer/, /\bbitcoin\b/, /\bcrypto/, /\b(usdt|tether)\b/, /western union/, /moneygram/, /\bzelle\b/] },
    { code: 'ACCOUNT_PROBLEM_CLAIM', patterns: [/\b(account|card|access|profile|service)\b[^.!]{0,30}\b(suspended|locked|disabled|on hold)\b/, /\b(suspended|locked|disabled)\b[^.!]{0,30}\b(account|card)\b/, /unusual (sign-?in )?activity/, /verify your (account|identity)/, /confirm your (account|identity)/, /update your (payment|billing)/, /unauthori[sz]ed/] },
    { code: 'PRESSURE_TACTICS', patterns: [/\burgent/, /immediately/, /within (24|48|72) hours/, /act now/, /final notice/, /last warning/, /expires today/] },
    { code: 'SECRECY_REQUEST', patterns: [/(don'?t|do not) tell/, /keep (this|it) (a )?secret/, /between (us|you and me)/, /\b(keep|treat) (this|it) (confidential|private)\b/] },
    { code: 'PRIZE_CLAIM', patterns: [/you('ve| have) won/, /claim your (prize|reward)/, /\blottery\b/, /\binheritance\b/, /unclaimed (funds|money)/] },
    { code: 'PERSONAL_INFO_REQUEST', patterns: [/social security number/, /\bssn\b/, /routing number/, /account number/, /date of birth/, /\b(enter|confirm|verify|send|provide|reply with|type|update|give( us| me)?|share|tell (us|me)) your (password|pin|passcode)\b/] },
    { code: 'DELIVERY_PROBLEM_CLAIM', patterns: [/could not be delivered/, /couldn'?t be delivered/, /package (is )?on hold/, /(re-?delivery|customs|shipping) fee/, /reschedule (your )?delivery/] },
    { code: 'TECH_SUPPORT_CLAIM', patterns: [/remote access/, /\banydesk\b/, /\bteamviewer\b/, /tech(nical)? support/, /your (computer|pc|device) (is|has been) (infected|hacked)/, /\b(computer|pc|device) (has )?(a )?virus/, /\bvirus(es)? (detected|found|on your)/] },
    PAY_TO_CLAIM_EMAIL,
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
        /\byour (account|card|computer|device|pc|phone|iphone|mac)\b[^.!]{0,40}\b(locked|suspended|infected|compromised|hacked|disabled|blocked|at risk)\b/,
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
  const SCAM_ADVICE = /\bscam(s|mer|mers|med)?\b|\bphishing\b|\bfraudsters?\b|\bimpost[eo]rs?\b|\bsextortion\b/g;

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

  // "Refund" scams: a surprise charge, and a phone number to cancel it.
  // All three parts must be there: an amount charged, a phone number to call,
  // and cancelling or disputing. (A normal receipt has the first part only.)
  const SPAN = '(?:[^.!]|\\.\\d)'; // within one sentence ("$399.99" doesn't end it)
  const CHARGED = new RegExp(`\\b(renewed|charged|billed|order(ed)?|purchased?|invoice|payment)\\b${SPAN}{0,60}\\$\\s?\\d`);
  const CALL_NUMBER = new RegExp(`\\b(call|phone|contact)\\b${SPAN}{0,60}(\\(?\\d{3}\\)?[-. ]?\\d{3}[-. ]\\d{4}|toll[- ]free)`);
  const TO_CANCEL = /\b(cancel|refund|dispute|did not (authorize|make|order)|didn'?t (authorize|make|order))/;
  function checkUnexpectedCharge(lower, variant) {
    const charged = lower.match(CHARGED);
    if (!charged || !CALL_NUMBER.test(lower) || !TO_CANCEL.test(lower)) return [];
    return [{ code: 'UNEXPECTED_CHARGE', subject: 'text', data: { variant }, evidence: { kind: 'text', value: charged[0] } }];
  }

  // ---------- scam stories: investment, jobs, recovery, blackmail ----------
  //
  // These need two parts in the same message (a promise of profits AND
  // investing words, a job AND a fee), and each part is checked for
  // "not", "never", or "no" just before it, and for "if someone..." earlier
  // in its sentence: "returns are not guaranteed", "never pay for equipment",
  // "no upfront fees", "if someone asks you to send back the difference"
  // are what honest companies and safety advice say.

  const NEGATION = /\b(no|not|never|cannot|can'?t|don'?t|doesn'?t|won'?t|isn'?t|aren'?t|shouldn'?t)\b/;
  // The employer paying is the opposite of a job scam: "WE will pay for your training".
  const EMPLOYER_PAYS = /\b(we|we'?ll|we will|we'?d|company will|employer will)\s+$/;
  const MAX_TRIES = 20; // occurrences checked per pattern (hostile text can repeat a phrase)

  // The words just before position `index`, in the same sentence.
  function leadIn(lower, index) {
    return lower.slice(Math.max(0, index - 30), index).split(/[.!?]\s/).pop();
  }
  // Where the sentence around position `index` starts and ends (up to 300 characters each way).
  function sentenceStart(lower, index) {
    return Math.max(0, lower.lastIndexOf('. ', index), lower.lastIndexOf('! ', index), lower.lastIndexOf('? ', index), index - 300);
  }
  function sentenceAt(lower, index) {
    const ends = ['. ', '! ', '? '].map(e => lower.indexOf(e, index)).filter(i => i >= 0);
    return lower.slice(sentenceStart(lower, index), Math.min(ends.length ? Math.min(...ends) : lower.length, index + 300));
  }
  // Safety advice describes what a scammer might do: "IF SOMEONE asks you to send back the difference..."
  const HYPOTHETICAL = /\b(if|when) (someone|anyone|a stranger|a buyer|a seller|a caller|they|scammers?|a company|an employer|a job)\b/;
  const everywhere = patterns => patterns.map(p => new RegExp(p.source, 'g'));
  // The first match of any pattern that isn't negated (and passes `accept`).
  function affirmed(lower, patterns, { notBefore = [], inside = false, accept = () => true } = {}) {
    for (const pattern of patterns) {
      let tries = 0;
      for (const m of lower.matchAll(pattern)) {
        const lead = leadIn(lower, m.index);
        const denied = NEGATION.test(lead) || notBefore.some(re => re.test(lead)) || (inside && NEGATION.test(m[0])) ||
          HYPOTHETICAL.test(lower.slice(sentenceStart(lower, m.index), m.index));
        if (!denied && accept(m)) return m;
        if (++tries >= MAX_TRIES) break;
      }
    }
    return null;
  }
  const found = (code, variant, match, extra = {}) =>
    ({ code, subject: 'text', data: { variant, ...extra }, evidence: { kind: 'text', value: match[0] } });

  const S = SPAN;
  const INVESTING = /\b(invest\w*|trading|trade|traders?|crypto\w*|bitcoin|btc|eth|ethereum|usdt|tether|forex|stocks?|robot|mining|portfolio)\b/;
  const COIN = '(btc|bitcoin|eth|ethereum|crypto\\w*|usdt|tether|doge(coin)?|xrp|solana|coins?)';

  // Guaranteed, risk-free, or impossible profits ("I made 300% this month").
  const PROFIT_PROMISE = everywhere([
    new RegExp(`\\bguarantee[ds]?\\b${S}{0,25}\\b(returns?|profits?|earnings|gains|payouts?|roi)\\b`),
    /\b(returns?|profits?|earnings|gains) (are |is )?(100% )?guaranteed\b/,
    new RegExp(`\\b(risk[- ]free|no[- ]risk|zero[- ]risk)\\b${S}{0,30}\\b(returns?|profits?|invest\\w*|trading|earnings|gains|income)\\b`),
    /\b(double|triple|10x) your (money|investment|bitcoin|btc|crypto|savings|deposit)\b/,
    /\b\d+(\.\d+)? ?% (daily|weekly|a day|per day|a week|per week) (returns?|profits?|interest|roi|gains)\b/,
    new RegExp(`\\b(made|make|earned|earn|gained|gain|returns? of|profits? of)\\b${S}{0,15}\\b\\d{2,}(\\.\\d+)? ?% (a|per|each|every|this|in a|in one|in just a) (day|week|month)\\b`),
    /\bearn(ing)? (up to )?\$\s?\d[\d,]*(\.\d+)? (a|per|each|every) (day|week)\b/,
  ]);
  // "Send 0.1 BTC and get 0.2 BTC back": no innocent use.
  const SEND_TO_GET_MORE = everywhere([
    new RegExp(`\\b(send|deposit|transfer)\\b${S}{0,40}\\b${COIN}\\b${S}{0,60}\\b(get|receive|we('ll| will) (send|return)|sends?( you)?|returns?)\\b${S}{0,30}\\b(back|double|twice|2x|in return)\\b`),
  ]);
  // A famous name selling an investment ("Elon Musk is giving away bitcoin").
  const escape = t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/'/g, "['\u2019]");
  const NAMES = `(${ENDORSERS.map(n => escape(n.toLowerCase())).join('|')})`;
  const NAME_PATTERNS = ENDORSERS.map(name => ({ name, re: new RegExp(escape(name.toLowerCase())) }));
  const ENDORSES = '(giving away|giveaway|gives away|reveals?|revealed|secret|recommends?|endorses?|endorsed|backed by|approved by|invests? with|uses this|swears by|(his|her|their) (new )?(platform|system|app|method|strategy|investment))';
  const CELEBRITY = everywhere([
    new RegExp(`(?<![a-z])${NAMES}(?![a-z])${S}{0,60}\\b${ENDORSES}\\b`),
    new RegExp(`\\b${ENDORSES}\\b${S}{0,60}(?<![a-z])${NAMES}(?![a-z])`),
  ]);
  // Put money in to start trading. Normal at a real brokerage, so it only
  // counts together with a promise of profits (risk-policy.js).
  const DEPOSIT = everywhere([
    new RegExp(`\\b(deposit|invest|fund (your|the|an) account with|top up)\\b${S}{0,25}(\\$\\s?\\d|\\d[\\d,.]* ?(usdt|btc|eth|bitcoin|dollars))`),
  ]);

  function checkInvestment(lower, variant) {
    const findings = [];
    const giveaway = affirmed(lower, SEND_TO_GET_MORE);
    if (giveaway) findings.push(found('CRYPTO_GIVEAWAY', variant, giveaway));
    if (!INVESTING.test(lower)) return findings;
    const promise = affirmed(lower, PROFIT_PROMISE);
    if (promise) findings.push(found('INVESTMENT_PROMISE', variant, promise));
    const celebrity = affirmed(lower, CELEBRITY, { inside: true });
    if (celebrity) {
      const name = (NAME_PATTERNS.find(x => x.re.test(celebrity[0])) || {}).name || '';
      findings.push(found('CELEBRITY_ENDORSEMENT', variant, celebrity, { name }));
    }
    const deposit = affirmed(lower, DEPOSIT);
    if (deposit) findings.push(found('DEPOSIT_TO_TRADE', variant, deposit));
    return findings;
  }

  // Job scams. Only in a message about a job you were offered.
  const JOB = /\byou(?:'ve| have)? been (hired|selected|accepted|chosen)\b|\byou(?:'re| are) (hired|selected|accepted)\b|\b(job|employment) (offer|opportunity)\b|\boffer of employment\b|\byour (new )?(position|role|job)\b|\bstart date\b|\bwork[- ]from[- ]home\b|\bremote (job|position|work)\b|\b(data entry|mystery shopper|secret shopper|personal assistant|package (handler|forwarder|inspector))\b|\bonboarding\b|\bpayroll\b|\brecruit(er|ing|ment)?\b/;
  // Pay for equipment or training: with an amount or a fee in the same sentence.
  const JOB_COSTS = everywhere([
    new RegExp(`\\b(pay|send|buy|purchase|wire|deposit)\\b${S}{0,50}\\b(equipment|training|starter kit|kit|software|laptop|computer|background check|certification|uniform|registration|application fee|work permit|visa)\\b`),
  ]);
  const VENDOR = everywhere([/\b(approved|designated|preferred|authorized|certified) (vendor|supplier|store)\b/]);
  const FREE_TO_YOU = /\b(no cost|free of charge|at our expense|we (will )?(pay|cover)|reimburse[sd]? (in full )?(before|up front|in advance))\b/;
  // The fake check: "deposit it and send back the difference".
  const SEND_BACK = everywhere([
    new RegExp(`\\b(send|wire|transfer|return|refund|forward|give)\\b( it| the rest| this)?( back)?${S}{0,20}\\b(the |any )?(difference|extra( money| amount)?|excess|overpayment|remaining (amount|funds|money))\\b`),
  ]);
  const A_CHECK = /\b(check|cheque|money order|deposit(ed)?|overpa(id|y|yment)|paid you (too much|extra|more))\b/;
  // "Reply with your Social Security number": by email, not on a secure form.
  const SENSITIVE = '(social security( number)?|ssn|routing number|bank account( number)?|account number|bank (details|information|info)|date of birth|driver\'?s license( number)?|passport( number)?|credit card( number)?)';
  const SEND_DETAILS = everywhere([
    new RegExp(`\\b(reply|respond|email|send|text|provide|forward|share)\\b( us| me| back)?( with)?${S}{0,40}\\b${SENSITIVE}\\b`),
  ]);
  const SECURE_WAY = /\b(portal|workday|adp|secure (site|link|form|website)|in person|first day|hr system)\b/;

  function checkJob(lower, variant) {
    const findings = [];
    const sendBack = A_CHECK.test(lower) && affirmed(lower, SEND_BACK, { notBefore: [EMPLOYER_PAYS] });
    if (sendBack) findings.push(found('OVERPAYMENT', variant, sendBack));
    if (!JOB.test(lower)) return findings;
    const fee = affirmed(lower, JOB_COSTS, { notBefore: [EMPLOYER_PAYS], accept: m => /\$\s?\d|\bfees?\b/.test(sentenceAt(lower, m.index)) }) ||
      affirmed(lower, VENDOR, { accept: m => /\b(buy|purchase|pay|order)\b/.test(sentenceAt(lower, m.index)) && !FREE_TO_YOU.test(sentenceAt(lower, m.index)) });
    if (fee) findings.push(found('JOB_FEE', variant, fee));
    const details = affirmed(lower, SEND_DETAILS, { accept: m => !SECURE_WAY.test(sentenceAt(lower, m.index)) });
    if (details) findings.push(found('JOB_DETAILS_REQUEST', variant, details));
    return findings;
  }

  // "We can recover the money you lost", for a fee: a second scam aimed at
  // people who were already scammed.
  const RECOVER = /\brecover(ed|ing)? (your|the) (lost |stolen )?(money|funds|bitcoin|crypto\w*|savings|losses|investment|deposit)\b|\b(recovery|retrieval) (agency|agent|service|services|team|experts?|specialists?|department|office|fee)\b|\b(funds|asset|crypto|bitcoin|money) recovery\b|\bget (it|them|your (lost |stolen )?(money|funds|bitcoin|crypto|savings)) back\b/;
  const LOSS = /\b(lost|stolen|scam(med)?|losses|fraud)\b/;
  const RECOVERY_COST = everywhere([
    /\b(recovery|processing|upfront|up-front|up front|service|retainer|release|administrative|legal|small) (fee|fees|payment|cost)\b/,
    new RegExp(`\\bpay\\b${S}{0,40}(\\$\\s?\\d|\\bfees?\\b|\\bupfront\\b|\\bup front\\b|\\bretainer\\b)`),
  ]);

  function checkRecovery(lower, variant) {
    const claim = lower.match(RECOVER);
    if (!claim || !LOSS.test(lower)) return [];
    const cost = affirmed(lower, RECOVERY_COST);
    return cost ? [found('RECOVERY_FEE', variant, claim)] : [];
  }

  // Blackmail: "pay, or the video goes to all your contacts". Aimed at YOUR
  // contacts, so a news story about "victims' contacts" doesn't count.
  const MEDIA = '(video|videos|photos?|pictures?|images?|recordings?|footage|clip|tape)';
  const AUDIENCE = '(contacts|friends|family|colleagues|co-?workers|employer|boss|followers|social media|wife|husband|partner)';
  const EXPOSE = everywhere([
    new RegExp(`\\b(send|share|release|leak|post|publish|forward|upload|show|distribute|expose)\\b${S}{0,40}\\b${MEDIA}\\b${S}{0,40}\\byour ${AUDIENCE}\\b`),
    new RegExp(`\\b${MEDIA}\\b${S}{0,30}\\b(will|to) (be )?(sent|shared|released|leaked|posted|published)\\b${S}{0,30}\\byour ${AUDIENCE}\\b`),
  ]);
  const BLACKMAIL_PAY = /\$\s?\d|\b(pay|bitcoin|btc|crypto\w*|wallet|gift ?cards?)\b/;

  function checkBlackmail(lower, variant) {
    if (!BLACKMAIL_PAY.test(lower)) return [];
    const threat = affirmed(lower, EXPOSE);
    return threat ? [found('SEXTORTION_THREAT', variant, threat)] : [];
  }

  function checkStories(lower, variant) {
    return [...checkInvestment(lower, variant), ...checkJob(lower, variant), ...checkRecovery(lower, variant), ...checkBlackmail(lower, variant)];
  }

  // Wording in an email.
  function checkEmailText(text) {
    const findings = runChecks(EMAIL_CHECKS, text, 'email');
    const lower = (text || '').toLowerCase();
    const money = /\b(money|bail|send|wire|gift ?cards?|pay|cash|help me)\b/.test(lower);
    // "Grandparent scam": someone claims a family member is in trouble and needs money fast.
    const family = lower.match(/\b(grandma|grandpa|grandmother|grandfather|nana|papa)\b/);
    const trouble = lower.match(/\b(bail|jail|arrested|hospital|accident|lawyer)\b/);
    // "Hi Mom, this is my new number": the same scam, from an unknown number.
    const newNumber = lower.match(/\b(new (phone )?number|lost my phone|broke my phone|dropped my phone)\b/);
    const relative = lower.match(/\b(mom|mum|mother|dad|father|grandma|grandpa|nana|papa)\b/);
    if (family && trouble && money) {
      findings.push({ code: 'FAMILY_EMERGENCY', subject: 'text', data: { variant: 'email' }, evidence: { kind: 'text', value: `${family[0]} … ${trouble[0]}` } });
    } else if (relative && newNumber && money) {
      findings.push({ code: 'FAMILY_EMERGENCY', subject: 'text', data: { variant: 'email' }, evidence: { kind: 'text', value: `${relative[0]} … ${newNumber[0]}` } });
    }
    findings.push(...checkUnexpectedCharge(lower, 'email'), ...checkStories(lower, 'email'));
    return findings;
  }

  // Wording on a website, in an ad, or around a link.
  function checkWebText(text) {
    const lower = (text || '').toLowerCase();
    const stories = checkStories(lower, 'web');
    // "You've been selected" for a JOB is the job story, not a prize.
    const job = stories.some(f => f.code === 'JOB_FEE' || f.code === 'JOB_DETAILS_REQUEST');
    const words = runChecks(WEB_CHECKS, text, 'web').filter(f => !(job && f.code === 'PRIZE_CLAIM' && /selected|chosen/.test(f.evidence.value)));
    return [...words, ...checkUnexpectedCharge(lower, 'web'), ...stories];
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
