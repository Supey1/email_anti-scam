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
//   analyzer.js        puts it all together
//
// THE way in, for new code:
//   analyze(input)   input and result are described in docs/interfaces.md
//
// Older ways in, kept working until the browser code (Person B) moves to
// analyze(). They return the old shape:
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

// email = { senderName, senderEmail, subject, bodyText, links: [{ text, href }] }
function analyzeEmail(email) {
  const evaluation = GranblockCore.analyzer.evaluate({
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
  const evaluation = GranblockCore.analyzer.evaluate({
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
  const evaluation = GranblockCore.analyzer.evaluate({
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

// Lets tests/rules.test.js load this file with Node. Chrome ignores this.
if (typeof module !== 'undefined') {
  module.exports = { analyze, whenToLookUp, analyzeEmail, analyzeLink, analyzePage };
}
