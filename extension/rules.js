// rules.js: the front door to the scam checks.
// Everything here runs on the user's own computer. No internet needed.
//
// The checks themselves live in extension/core/:
//   url-normalizer.js  reads web addresses safely (never "contains" checks)
//   url-rules.js       known dangerous websites, number addresses, shortened and misleading links
//   domain-rules.js    company names versus their official websites, look-alike addresses
//   text-rules.js      scam wording: gift cards, prizes, "your account is locked"...
//   risk-policy.js     how much each sign counts, and when to warn or block
//   explanations.js    plain words for every warning sign
//   analyzer.js        puts it all together (core/analyzer.js)
//
// THE way in, for new code:
//   analyze(input)   input and result are described in docs/interfaces.md
//
// For the browser code (Person B's screens): the same analyze(), with the
// small bits of glue every screen would otherwise repeat. Contract results
// (docs/interfaces.md), plus a few extras the screens show:
//   checkWebpage(evidence)  a page from content/page-scanner.js, including the
//                           ads it found (context.ads)
//   checkLinkClick(click)   a link someone clicked: { text, url, pageUrl, inAd, adText, insideFrame, surroundingResult }
//                           -> result + host (where it really goes)
//   checkEmail(evidence)    an email from content/gmail-adapter.js
//                           -> result + links [{ text, host, flags }]
//   stopsPerson(result)     should the screen stop the person (block, GO_BACK, DO_NOT_ENTER_INFO)?
//                           "warn" + VERIFY_INDEPENDENTLY never interrupts.
//
// Older ways in, used only by the examples in tests/rules.test.js. They return the old shape:
//   analyzeEmail(email)        an email open in Gmail
//   analyzeLink(link, context) a link someone is about to click
//   analyzePage(page)          the website someone is looking at
//   -> { level: 'high' | 'medium' | 'low', action: 'block' | 'warn' | 'allow',
//        confirmed, score, reasons: [...sentences], evidence, ... }
//
// To add a new check: add it to the right file in core/, give it a reason
// code in docs/interfaces.md, its points in risk-policy.js, its words in
// explanations.js, and two tests in tests/rules.test.js (one that should
// trigger it and one that should not).

if (typeof require !== 'undefined' && typeof module !== 'undefined') require('./core/analyzer.js');

// See docs/interfaces.md.
//   options.lookup  a remote threat lookup's answer, if there is one
function analyze(input, options) {
  return GranblockCore.analyzer.analyze(input, options);
}

// Should a click wait for a remote threat lookup? See docs/interfaces.md.
function whenToLookUp(result) {
  return GranblockCore.analyzer.whenToLookUp(result);
}

// A new-style decision -> the old result shape.
function legacyResult(evaluation, extra) {
  const { decision } = evaluation;
  const { pointsFor } = GranblockCore.riskPolicy;
  const { explain } = GranblockCore.explanations;
  const KIND = { threat: 'known_threat', destination: 'destination', identity: 'sender', page: 'page', context: 'context' };
  const evidence = decision.reasons.map(r => ({
    points: r.points,
    text: explain(r.findings[0]).explanation,
    kind: r.code === 'FAKE_SIGN_IN_PAGE' ? 'page' : KIND[GranblockCore.riskPolicy.RULES[r.code].group] || 'wording',
  }));
  return {
    level: decision.stops ? 'high' : decision.score >= 1 ? 'medium' : 'low',
    action: decision.verdict === 'block' ? 'block' : decision.stops ? 'warn' : 'allow',
    confirmed: decision.confirmed,
    score: decision.score,
    reasons: evidence.map(e => e.text),
    evidence,
    ...extra,
  };
}

// Short labels for each link, for the Gmail panel's list of links.
function legacyLinkReport(findings) {
  const { flagFor } = GranblockCore.explanations;
  const flags = [];
  for (const f of findings) {
    const flag = flagFor(f);
    if (flag && !flags.includes(flag)) flags.push(flag);
  }
  return { flags, knownThreat: findings.some(f => f.code === 'KNOWN_THREAT') };
}

// The older ways in clean their input the same way analyze() does.
const evaluateClean = input => GranblockCore.analyzer.evaluate(GranblockCore.analyzer.cleanInput(input));

// email = { senderName, senderEmail, subject, bodyText, links: [{ text, href }] }
function analyzeEmail(email) {
  const evaluation = evaluateClean({
    source: 'email',
    pageUrl: '',
    pageTitle: email.subject || '',
    visibleText: email.bodyText || '',
    links: (email.links || []).map(l => ({ text: l.text || '', url: l.href })),
    forms: [],
    context: { senderName: email.senderName || '', senderEmail: email.senderEmail || '', subject: email.subject || '' },
  });
  const links = evaluation.links.map(l => ({ text: l.text, href: l.href, host: l.host, ...legacyLinkReport(l.findings) }));
  return legacyResult(evaluation, { links });
}

// link = { text, href }
// context = { pageUrl, nearbyText, surroundingLevel: 'high' if the link is inside a scam email }
function analyzeLink(link, context = {}) {
  const evaluation = evaluateClean({
    source: 'link',
    pageUrl: context.pageUrl || '',
    pageTitle: '',
    visibleText: '',
    links: [{ text: link.text || '', url: link.href }],
    forms: [],
    context: {
      nearbyText: context.nearbyText || '',
      insideFrame: false,
      ...(context.surroundingLevel === 'high' ? { surroundingResult: { verdict: 'warn', recommendedAction: 'GO_BACK' } } : {}),
    },
  });
  const report = legacyLinkReport(evaluation.flags || []);
  return legacyResult(evaluation, { host: evaluation.host, flags: report.flags, ...(evaluation.sameSite ? { sameSite: true } : {}) });
}

// page = { url, title, headings, text, hasPassword, formActions }
function analyzePage(page) {
  const actions = page.formActions && page.formActions.length ? page.formActions : [page.url || ''];
  const evaluation = evaluateClean({
    source: 'webpage',
    pageUrl: page.url || '',
    pageTitle: page.title || '',
    visibleText: page.text || '',
    links: [],
    forms: page.hasPassword ? actions.map(action => ({ action, hasPassword: true, hasPaymentField: false })) : [],
    context: { mainHeadings: page.headings ? [page.headings] : [] },
  });
  return legacyResult(evaluation, { host: evaluation.host });
}

// ---------- for the browser code ----------

const STOPS = ['GO_BACK', 'DO_NOT_ENTER_INFO'];
function stopsPerson(result) {
  return !!result && (result.verdict === 'block' || (result.verdict === 'warn' && STOPS.includes(result.recommendedAction)));
}

// How strongly a result asks the person to act: block, then stop, then "check first".
function strength(result) {
  if (result.verdict === 'block') return 3;
  if (stopsPerson(result)) return 2;
  return result.verdict === 'warn' ? 1 : 0;
}

// The page, and every ad on it judged the way a click on that ad would be.
// A scam ad on an ordinary page warns about the ad; the page's own reasons come first.
// An ad leading to a known dangerous website stops the person, but doesn't make the
// PAGE "known dangerous": the click on the ad is what gets blocked.
const MAX_ADS = 20;
const asAdOnPage = r => (r.verdict === 'block' ? { ...r, verdict: 'warn', recommendedAction: 'GO_BACK' } : r);
function checkWebpage(evidence) {
  const page = analyze(evidence);
  if (!evidence || typeof evidence !== 'object') return page;
  const ctx = evidence.context && typeof evidence.context === 'object' ? evidence.context : {};
  const ads = (Array.isArray(ctx.ads) ? ctx.ads : []).filter(ad => ad && ad.link && ad.link.url).slice(0, MAX_ADS)
    .map(ad => asAdOnPage(checkLinkClick({ text: ad.link.text, url: ad.link.url, pageUrl: evidence.pageUrl, inAd: true, adText: ad.text, insideFrame: !!ad.frame })));
  const results = [page, ...ads];
  const strongest = results.reduce((best, r) => (strength(r) > strength(best) ? r : best), page);
  if (strength(strongest) === 0) return page;
  const seen = new Set();
  const reasons = [];
  for (const r of [page, ...ads].filter(r => strength(r) > 0)) {
    for (const reason of r.reasons) if (!seen.has(reason.code)) { seen.add(reason.code); reasons.push(reason); }
  }
  const codes = new Set(reasons.map(r => r.code));
  const evidenceList = results.flatMap(r => r.evidence).filter(e => codes.has(e.reasonCode));
  return { ...strongest, reasons, evidence: evidenceList };
}

// click = { text, url, pageUrl, insideFrame,
//           inAd, adText (the link is in something content/ad-signals.js recognized as an ad, and the ad's words),
//           surroundingResult (the result of the email the link is in, if any) }
function checkLinkClick(click) {
  const c = click && typeof click === 'object' ? click : {};
  const result = analyze({
    source: 'link',
    pageUrl: typeof c.pageUrl === 'string' ? c.pageUrl : '',
    pageTitle: '',
    visibleText: '',
    links: [{ text: typeof c.text === 'string' ? c.text : '', url: typeof c.url === 'string' ? c.url : '' }],
    forms: [],
    context: {
      nearbyText: typeof c.adText === 'string' ? c.adText : '',
      inAd: c.inAd === true,
      insideFrame: !!c.insideFrame,
      ...(c.surroundingResult ? { surroundingResult: c.surroundingResult } : {}),
    },
  });
  const parsed = GranblockCore.urlNormalizer.normalizeUrl(typeof c.url === 'string' ? c.url : '');
  return { ...result, host: parsed.ok && parsed.isWeb ? parsed.host : '' };
}

function checkEmail(evidence) {
  const result = analyze(evidence);
  let links = [];
  try {
    const evaluation = GranblockCore.analyzer.evaluate(GranblockCore.analyzer.cleanInput(evidence));
    links = (evaluation.links || []).map(l => ({ text: l.text, host: l.host, flags: legacyLinkReport(l.findings).flags }));
  } catch (e) { /* the result already says "unknown" */ }
  return { ...result, links };
}

// Lets the tests load this file with Node. Chrome ignores this.
if (typeof module !== 'undefined') {
  module.exports = { analyze, whenToLookUp, checkWebpage, checkLinkClick, checkEmail, stopsPerson, analyzeEmail, analyzeLink, analyzePage };
}
