// analyzer.js: checks webpages and single links, using the same plain rules as rules.js.
//
// Evidence goes in, a verdict comes out, with the reasons in plain words:
//   "block"  strong evidence (a website already known to be dangerous)
//   "warn"   credible warning signs that work together
//   "allow"  nothing convincing found (weak signs are listed in `notes`)
//
// A scary word alone never causes a warning. A news article about gift card
// scams should not be flagged. Wording only counts when something structural
// backs it up, like a password form that sends your password to another website.

const RULES = (typeof module !== 'undefined')
  ? require('./rules.js')
  : { checkLink, checkWording, brandMentionedInHost, isBrandDomain, baseDomain, BRANDS, analyzeEmail };
const THREATS = (typeof module !== 'undefined') ? require('./threats.js') : { lookupThreat };

// Sites we never second-guess: government, schools, and the real websites of the brands we know.
function isTrustedHost(host) {
  if (/\.(gov|edu|mil)$/.test(host)) return true;
  return RULES.BRANDS.some(b => RULES.isBrandDomain(host, b));
}

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase().replace(/^www\./, ''); } catch (e) { return ''; }
}

const PRIZE_WORDS = /you('ve| have) won|claim your (prize|reward|gift)|congratulations|free gift card|\$\d[\d,]* gift card|winner/i;
const CLAIM_BUTTON = /claim|redeem|collect|get (my|your) (prize|reward|gift)|spin/i;

const RECOMMENDED = {
  block: 'Do not continue. Go back to safety.',
  warn: 'Do not enter passwords or payment details. Check with someone you trust first.',
  allow: '',
};

const CLAIM_IN_TEXT = /claim (your|now|it|reward|prize)|redeem (your|now)|collect your/i;
const AD_ADVICE = 'Do not click it. Check the offer with a person you trust, or go to the company\'s own website yourself.';

// Checks one advertisement. Advertisements use the same checks as everything else; the ad
// context only says "this is an ad" and gives its text and destination.
// ad = { signals: [...], text, link: { text, url } | null }
// Most ads are fine: an ad is only flagged for credible warning signs, never for being an ad.
function analyzeAd(ad, pageUrl) {
  const result = { verdict: 'allow', score: 0, reasons: [], recommendedAction: '', evidence: [], source: 'advertisement' };
  if (!ad || !ad.link) return result;
  const host = hostOf(ad.link.url);
  if (!host) return result;

  const threat = THREATS.lookupThreat(host);
  if (threat) {
    result.verdict = 'block';
    result.score = 10;
    result.reasons.push(`An advertisement on this page leads to ${host}, which has been reported as a dangerous website.`);
    result.evidence.push({ kind: 'threat-list', detail: threat });
    result.recommendedAction = RECOMMENDED.block;
    return result;
  }
  if (isTrustedHost(host)) return result;

  const found = [];
  let structural = 0;
  let wording = 0;
  const add = (kind, points, text, detail) => {
    if (found.some(f => f.text === text)) return;
    found.push({ points, text });
    if (kind === 'wording') wording += points; else structural += points;
    result.evidence.push({ kind, detail: detail || text });
  };

  // What the link's words say versus where it goes (fake company, hidden destination, number address...).
  // Same threshold as a plain link click (analyzeLink), so an ad's link is judged the same either way.
  let linkPoints = 0;
  RULES.checkLink({ text: ad.link.text, href: ad.link.url }, (points, text) => {
    linkPoints += points;
    add('link', points, `In an advertisement: ${text.charAt(0).toLowerCase()}${text.slice(1)}`, ad.link.url);
  });

  // A prize or reward whose claim button leads to a website nobody has verified.
  const sameSite = pageUrl && RULES.baseDomain(host) === RULES.baseDomain(hostOf(pageUrl));
  const claimText = `${ad.text || ''} ${ad.link.text || ''}`;
  if (!sameSite && PRIZE_WORDS.test(claimText) && (CLAIM_BUTTON.test(ad.link.text || '') || CLAIM_IN_TEXT.test(ad.text || ''))) {
    add('link', 3, `The advertisement promises a prize, but its button goes to ${host}, a website that has not been verified as belonging to the company making the offer.`, ad.link.url);
  }

  RULES.checkWording({ subject: '', bodyText: ad.text || '' }, (points, text) => add('wording', points, text));

  result.score = structural + wording;
  if (linkPoints >= 3 || structural >= 4 || (structural >= 2 && result.score >= 5)) {
    found.sort((a, b) => b.points - a.points);
    result.verdict = 'warn';
    result.reasons = found.map(f => f.text);
    result.recommendedAction = AD_ADVICE;
  }
  return result;
}

// evidence = { url, title, visibleText, links: [{ text, href }], forms: [{ action, hasPassword, hasPayment }] }
// returns { verdict, score, reasons, notes, recommendedAction, evidence }
function analyzePage(evidence) {
  const host = hostOf(evidence.url);
  const result = { verdict: 'allow', score: 0, reasons: [], notes: [], recommendedAction: '', evidence: [] };
  if (!host) return result;

  const threat = THREATS.lookupThreat(host);
  if (threat) {
    result.verdict = 'block';
    result.score = 10;
    result.reasons.push(`${host} has been reported as a dangerous website.`);
    result.evidence.push({ kind: 'threat-list', detail: threat });
    result.recommendedAction = RECOMMENDED.block;
    return result;
  }
  if (isTrustedHost(host)) return result;

  const seen = new Set();
  let structural = 0;
  let wording = 0;
  function add(kind, points, text, detail) {
    if (seen.has(text)) return;
    seen.add(text);
    if (kind === 'wording') wording += points; else structural += points;
    result.reasons.push({ points, text });
    result.evidence.push({ kind, detail: detail || text });
  }

  // 1. The page's own address.
  const brand = RULES.brandMentionedInHost(host);
  if (brand && !RULES.isBrandDomain(host, brand)) {
    add('address', 4, `This website's address (${host}) is made to look like ${brand.label}, but it is not ${brand.label}'s real website.`, host);
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    add('address', 2, 'This page is at a number address instead of a normal website name.', host);
  }

  // 2. Forms that ask for passwords or card numbers.
  const secretForms = (evidence.forms || []).filter(f => f.hasPassword || f.hasPayment);
  const pageBase = RULES.baseDomain(host);
  for (const form of secretForms) {
    const target = hostOf(form.action);
    if (/^http:/i.test(evidence.url) || /^http:/i.test(form.action || '')) {
      add('form', 2, 'This page asks for a password or card number without a secure connection.', form.action);
    }
    if (target && RULES.baseDomain(target) !== pageBase) {
      add('form', 3, `This page asks for your ${form.hasPayment ? 'card number' : 'password'}, but sends it to a different website (${target}).`, form.action);
    }
  }
  if (secretForms.some(f => f.hasPassword)) {
    const claimed = RULES.BRANDS.find(b => b.nameRe.test(evidence.title || ''));
    if (claimed && !RULES.isBrandDomain(host, claimed)) {
      add('form', 3, `This page says it is ${claimed.label} and asks for a password, but it is at ${host}.`, evidence.title);
    }
  }

  // 3. A prize claim whose button leads to some other website.
  const text = `${evidence.title || ''}\n${evidence.visibleText || ''}`;
  if (PRIZE_WORDS.test(text)) {
    const cta = (evidence.links || []).find(l => {
      const target = hostOf(l.href);
      return target && CLAIM_BUTTON.test(l.text) && RULES.baseDomain(target) !== pageBase;
    });
    if (cta) {
      const target = hostOf(cta.href);
      add('link', 3, `The offer's claim button goes to ${target}, a different website that has not been verified as belonging to the company making the offer.`, cta.href);
    }
  }

  // 4. Wording. Counts only as supporting evidence.
  const wordingReasons = [];
  RULES.checkWording({ subject: evidence.title, bodyText: evidence.visibleText }, (points, reason) => wordingReasons.push({ points, reason }));
  for (const w of wordingReasons) add('wording', w.points, w.reason);

  const score = structural + wording;
  result.score = score;
  const adReasons = [];
  for (const ad of (evidence.ads || []).slice(0, 20)) {
    const r = analyzeAd(ad, evidence.url);
    if (r.verdict !== 'allow') for (const text of r.reasons) if (!adReasons.includes(text)) adReasons.push(text);
  }
  const warn = structural >= 4 || (structural >= 2 && score >= 5);
  result.reasons.sort((a, b) => b.points - a.points);
  const texts = result.reasons.map(r => r.text);
  if (warn) {
    result.verdict = 'warn';
    result.reasons = texts.concat(adReasons.filter(t => !texts.includes(t)));
    result.recommendedAction = RECOMMENDED.warn;
  } else if (adReasons.length) {
    // The page itself looks ordinary, but an advertisement on it has credible warning signs.
    // The page is not "blocked": only the ad is the problem.
    result.verdict = 'warn';
    result.reasons = adReasons;
    result.notes = texts;
    result.recommendedAction = AD_ADVICE;
  } else {
    result.notes = texts;
    result.reasons = [];
  }
  return result;
}

// Checks one link the person is about to click. Strong signs only,
// because every false alarm teaches people to ignore the warning.
// link = { text, href }
// context = { ad: { text, signals } } (optional): the link sits inside an advertisement.
function analyzeLink(link, context) {
  const host = hostOf(link.href);
  const result = { verdict: 'allow', score: 0, reasons: [], recommendedAction: '', evidence: [], host };
  if (!host) return result;

  const threat = THREATS.lookupThreat(host);
  if (threat) {
    result.verdict = 'block';
    result.score = 10;
    result.reasons.push(`This link goes to ${host}, which has been reported as a dangerous website.`);
    result.evidence.push({ kind: 'threat-list', detail: threat });
    result.recommendedAction = RECOMMENDED.block;
    return result;
  }

  const reasons = [];
  const report = RULES.checkLink(link, (points, text) => { result.score += points; reasons.push({ points, text }); });
  result.host = report.host || host;
  if (result.score >= 3) {
    reasons.sort((a, b) => b.points - a.points);
    result.verdict = 'warn';
    result.reasons = reasons.map(r => r.text);
    result.evidence = report.flags.map(f => ({ kind: 'link', detail: f }));
    result.recommendedAction = 'Do not click it unless you are sure. Contact the company using a number from your card or bill.';
  }
  if (context && context.ad && result.verdict === 'allow') {
    const ad = analyzeAd({ signals: context.ad.signals, text: context.ad.text, link: { text: link.text, url: link.href } }, '');
    if (ad.verdict !== 'allow') return { ...ad, host: result.host };
  }
  return result;
}

// ---------- the one entry point (docs/interfaces.md) ----------
// analyze(evidence) takes what a scanner or adapter collected and returns a result.
// Webpage and email evidence go through the same call, so every adapter gets the same kind of answer.
//
// Output note (temporary, see docs/integration-checklist.md): still the older result shape
// (verdict "allow", reasons as sentences) until the structured contract is adopted.

const EMAIL_ADVICE = {
  block: 'Do not click any links in this email. Do not reply, and never send money, gift cards, or passwords. Call a family member or someone you trust before doing anything.',
  warn: 'Do not click links unless you were expecting this email. If it says it is from a company, call them using the number on your card or bill, not a number in this email.',
  allow: '',
};

function analyzeEmailEvidence(evidence) {
  const ctx = evidence.context || {};
  const old = RULES.analyzeEmail({
    senderName: ctx.senderName || '',
    senderEmail: ctx.senderEmail || '',
    subject: ctx.subject || evidence.pageTitle || '',
    bodyText: evidence.visibleText || '',
    links: (evidence.links || []).map(l => ({ text: l.text, href: l.url })),
  });
  // A high score means several strong signs together: that is "block" for an email.
  const verdict = old.level === 'high' ? 'block' : old.level === 'medium' ? 'warn' : 'allow';
  return { verdict, score: old.score, reasons: old.reasons, notes: [], recommendedAction: EMAIL_ADVICE[verdict], evidence: [], links: old.links, source: 'email' };
}

function analyze(evidence) {
  if (!evidence || typeof evidence !== 'object') return { verdict: 'unknown', score: 0, reasons: [], recommendedAction: '', evidence: [] };
  try {
    if (evidence.source === 'email') return analyzeEmailEvidence(evidence);
    const context = evidence.context || {};
    return analyzePage({
      url: evidence.pageUrl,
      title: evidence.pageTitle,
      visibleText: evidence.visibleText,
      links: (evidence.links || []).map(l => ({ text: l.text, href: l.url })),
      forms: evidence.forms || [],
      ads: context.ads || [],
    });
  } catch (error) {
    return { verdict: 'unknown', score: 0, reasons: [], recommendedAction: '', evidence: [] };
  }
}

// Lets tests load this file with Node. Chrome ignores this.
if (typeof module !== 'undefined') {
  module.exports = { analyze, analyzePage, analyzeLink, analyzeAd, isTrustedHost };
}
