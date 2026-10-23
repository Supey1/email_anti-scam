// analyzer.js: combines the warning signs into one answer.
//
// analyze(input) takes the evidence described in docs/interfaces.md
// (an email, a webpage, or a clicked link) and returns the result described
// there: a verdict, specific reasons, and what the person should do.
// It never throws: if anything goes wrong, the verdict is "unknown".
//
//   url-normalizer.js  reads addresses safely
//   url-rules.js       where a link really goes
//   domain-rules.js    company names versus official websites
//   text-rules.js      scam wording
//   risk-policy.js     how much each sign counts, and what to do about it
//   explanations.js    plain words for each sign

(function () {
  'use strict';
  const core = globalThis.GranblockCore = globalThis.GranblockCore || {};
  if (typeof require !== 'undefined') {
    for (const [name, file] of [['urlNormalizer', './url-normalizer.js'], ['domainRules', './domain-rules.js'], ['urlRules', './url-rules.js'],
      ['textRules', './text-rules.js'], ['riskPolicy', './risk-policy.js'], ['explanations', './explanations.js']]) {
      if (!core[name]) require(file);
    }
  }
  const { normalizeUrl, parseUrl, sameSite, findDomainInText } = core.urlNormalizer;
  const urlRules = core.urlRules;
  const domainRules = core.domainRules;
  const textRules = core.textRules;
  const { keepText, decide } = core.riskPolicy;
  const { explain } = core.explanations;

  const SCHEMA_VERSION = 1;
  const UNKNOWN = Object.freeze({ schemaVersion: SCHEMA_VERSION, verdict: 'unknown', reasons: [], recommendedAction: 'NONE', evidence: [] });
  const NOTHING_FOUND = decide([], 'webpage');

  // All the address checks for one link.
  function checkLinkAddress(text, parsed) {
    if (!parsed.ok || !parsed.isWeb) return [];
    const findings = [
      ...urlRules.checkAddress(parsed, 'link'),
      ...domainRules.checkAddress(parsed.hostname, 'link'),
    ];
    const shown = urlRules.checkShownDestination(text, parsed);
    findings.push(...shown);
    // The link's words name a company (but no website), and the address isn't that company's.
    if (!shown.length && !findDomainInText(text)) findings.push(...domainRules.checkNamedBrand(text, parsed.hostname, 'link_text'));
    return findings;
  }

  function evaluateEmail(input) {
    const ctx = input.context || {};
    const findings = [];
    const links = (input.links || []).map(link => {
      const parsed = normalizeUrl(link.url);
      const linkFindings = checkLinkAddress(link.text || '', parsed);
      findings.push(...linkFindings);
      return { text: link.text || '', href: link.url, host: parsed.ok && parsed.isWeb ? parsed.host : '', findings: linkFindings };
    });
    findings.push(...domainRules.checkSender(ctx.senderName, ctx.senderEmail));
    findings.push(...textRules.checkEmailText(`${ctx.subject || ''}\n${input.visibleText || ''}`));
    return { decision: decide(findings, 'email'), links };
  }

  function evaluateLink(input) {
    const ctx = input.context || {};
    const link = (input.links || [])[0] || { text: '', url: '' };
    const page = parseUrl(input.pageUrl || '');
    const parsed = normalizeUrl(link.url, page.ok && page.isWeb ? page.href : undefined);
    if (!parsed.ok || !parsed.isWeb) return { decision: NOTHING_FOUND, host: '' };
    const { hostname, host } = parsed;

    // Moving around inside the same website is the page check's job, not ours.
    if (page.ok && page.isWeb && sameSite(page.hostname, hostname) && !urlRules.isKnownThreat(hostname)) {
      return { decision: NOTHING_FOUND, host, sameSite: true };
    }

    const other = checkLinkAddress(link.text || '', parsed);
    const surrounding = ctx.surroundingResult || {};
    if (surrounding.recommendedAction === 'GO_BACK') {
      other.push({ code: 'INSIDE_SCAM_EMAIL', subject: 'link', data: { host }, evidence: { kind: 'url', value: parsed.href } });
    }

    // What the link and the ad around it promise. A link to a company's real
    // website is trusted here: a real bank can say "your card is blocked".
    const derived = [];
    let text = [];
    if (!domainRules.officialBrandFor(hostname)) {
      const offerText = `${link.text || ''}\n${ctx.nearbyText || ''}`;
      text = keepText(textRules.checkWebText(offerText), other, 'link', textRules.looksLikeScamAdvice(offerText));
      if (text.length) {
        const mismatch = domainRules.checkNamedBrand(offerText, hostname, 'offer');
        if (mismatch.length) derived.push(...mismatch);
        else if (text.some(f => f.code === 'PRIZE_CLAIM' || f.code === 'PAY_TO_CLAIM')) {
          derived.push({ code: 'UNVERIFIED_PRIZE_CLAIM', subject: 'link', data: { host }, evidence: { kind: 'url', value: parsed.href } });
        }
      }
    }
    return { decision: decide([...other, ...text, ...derived], 'link'), host, flags: other };
  }

  function evaluatePage(input) {
    const ctx = input.context || {};
    const page = parseUrl(input.pageUrl || '');
    if (!page.ok || !page.isWeb) return { decision: NOTHING_FOUND, host: '' };
    const { hostname, host } = page;
    // The company's real website.
    if (domainRules.officialBrandFor(hostname) && !urlRules.isKnownThreat(hostname)) return { decision: NOTHING_FOUND, host };

    const other = [
      ...urlRules.checkAddress(page, 'page'),
      ...domainRules.checkAddress(hostname, 'page'),
    ];

    const claim = `${input.pageTitle || ''}\n${(ctx.mainHeadings || []).join('\n')}`;
    const secretForms = (input.forms || []).filter(f => f.hasPassword || f.hasPaymentField);
    other.push(...domainRules.checkSignInPage(claim, hostname, secretForms.length > 0));

    // The password or card number would be sent to a different website.
    for (const form of secretForms) {
      const action = parseUrl(form.action || '', page.href);
      if (action.ok && action.isWeb && !sameSite(action.hostname, hostname)) {
        other.push({ code: 'CREDENTIALS_SENT_ELSEWHERE', subject: 'page', data: { host, elsewhere: action.host }, evidence: { kind: 'form', value: action.href } });
        break;
      }
    }

    const pageText = `${claim}\n${(input.visibleText || '').slice(0, 5000)}`;
    const text = keepText(textRules.checkWebText(pageText), other, 'webpage', textRules.looksLikeScamAdvice(pageText));
    return { decision: decide([...other, ...text], 'webpage', { asksForSecrets: secretForms.length > 0 }), host };
  }

  // The full decision, with the details tests and older callers need.
  function evaluate(input) {
    if (input.source === 'email') return evaluateEmail(input);
    if (input.source === 'link') return evaluateLink(input);
    if (input.source === 'webpage') return evaluatePage(input);
    throw new Error(`unknown source: ${input.source}`);
  }

  // A decision -> the result in docs/interfaces.md.
  function toResult(decision) {
    const evidence = [];
    const seen = new Set();
    for (const reason of decision.reasons) {
      for (const f of reason.findings) {
        if (!f.evidence) continue;
        const key = `${reason.code}|${f.evidence.kind}|${f.evidence.value}`;
        if (seen.has(key)) continue;
        seen.add(key);
        evidence.push({ kind: f.evidence.kind, value: f.evidence.value, reasonCode: reason.code });
      }
    }
    return {
      schemaVersion: SCHEMA_VERSION,
      verdict: decision.verdict,
      reasons: decision.reasons.map(reason => explain(reason.findings[0])),
      recommendedAction: decision.recommendedAction,
      evidence,
    };
  }

  // THE entry point. See docs/interfaces.md.
  function analyze(input) {
    try {
      if (!input || typeof input !== 'object') return { ...UNKNOWN };
      return toResult(evaluate(input).decision);
    } catch (e) {
      return { ...UNKNOWN };
    }
  }

  core.analyzer = { SCHEMA_VERSION, analyze, evaluate, toResult };
  if (typeof module !== 'undefined') module.exports = core.analyzer;
})();
