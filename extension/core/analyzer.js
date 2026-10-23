// analyzer.js: combines the warning signs into one answer.
//
// analyze(input) takes the evidence described in docs/interfaces.md
// (an email, a webpage, or a clicked link) and returns the result described
// there: a verdict, specific reasons, and what the person should do.
// It never throws: if anything goes wrong, the verdict is "unknown".
// It runs on this computer, instantly, so a click can be held or let through
// in the same moment it happens.
//
// Remote lookups (asking a threat service about an address) are slow and
// happen elsewhere. Their answer comes back in through analyze(input, { lookup }),
// and whenToLookUp(result) says whether a click must wait for one.
// See "Remote lookups" in docs/interfaces.md.
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
  const { normalizeUrl, parseUrl, sameSite, findDomainInText, registrableDomain } = core.urlNormalizer;
  const urlRules = core.urlRules;
  const domainRules = core.domainRules;
  const textRules = core.textRules;
  const { keepText, decide } = core.riskPolicy;
  const { explain } = core.explanations;

  const SCHEMA_VERSION = 1;
  // How much page text is read. Scanners add text that appears later (pop-ups)
  // to the END, so this must be big enough to reach it on long pages.
  const MAX_TEXT = 50000;
  const UNKNOWN = Object.freeze({ schemaVersion: SCHEMA_VERSION, verdict: 'unknown', reasons: [], recommendedAction: 'NONE', evidence: [] });

  // All the address checks for one link.
  function checkLinkAddress(text, parsed) {
    if (!parsed.ok || !parsed.isWeb) return [];
    const findings = [
      ...urlRules.checkAddress(parsed, 'link'),
      ...domainRules.checkAddress(parsed.hostname, 'link'),
      ...urlRules.checkSignInLink(text, parsed),
    ];
    const shown = urlRules.checkShownDestination(text, parsed);
    // Through an email service or ad network we can't see where the link ends
    // up, so we can't compare it with company names. The other checks still count.
    if (domainRules.serviceKind(parsed.hostname)) {
      for (const f of shown) Object.assign(f.data, { variant: 'via_service', service: registrableDomain(parsed.hostname) });
      findings.push(...shown);
      return findings;
    }
    findings.push(...shown);
    // The link's words name a company (but no website), and the address isn't that company's.
    if (!shown.length && !findDomainInText(text)) findings.push(...domainRules.checkNamedBrand(text, parsed.hostname, 'link_text'));
    return findings;
  }

  // Codes that mean "the message asks for money, details, or account action".
  const ASKS = new Set(['PAYMENT_DEMAND', 'PAYMENT_METHOD_REQUEST', 'PAY_TO_CLAIM', 'PERSONAL_INFO_REQUEST', 'ACCOUNT_PROBLEM_CLAIM', 'THREAT_OF_CONSEQUENCES']);

  function evaluateEmail(input) {
    const ctx = input.context || {};
    const text = (input.visibleText || '').slice(0, MAX_TEXT);
    const findings = [];
    const links = (input.links || []).map(link => {
      const parsed = normalizeUrl(link.url);
      const linkFindings = checkLinkAddress(link.text || '', parsed);
      findings.push(...linkFindings);
      const host = parsed.ok && parsed.isWeb ? parsed.host : '';
      return { text: link.text || '', href: link.url, host, service: host ? domainRules.serviceKind(parsed.hostname) : '', findings: linkFindings };
    });
    const wording = textRules.checkEmailText(`${ctx.subject || ''}\n${text}`);
    findings.push(...wording);

    // Who it claims to be, judged by what KIND of message it is: a company name
    // on someone else's address matters in an account alert, much less in a newsletter.
    const kind = textRules.messageKind(ctx.subject, text);
    findings.push(...domainRules.checkSender(ctx.senderName, ctx.senderEmail, kind));
    const claimed = domainRules.brandNamedIn(ctx.senderName) || domainRules.brandNamedIn(ctx.subject);
    findings.push(...domainRules.checkMessageLinks(claimed, links, kind));
    findings.push(...domainRules.checkAgencyEmail(ctx.senderName, ctx.subject, wording.some(f => ASKS.has(f.code))));
    return { findings, links, kind };
  }

  function evaluateLink(input) {
    const ctx = input.context || {};
    const link = (input.links || [])[0] || { text: '', url: '' };
    const page = parseUrl(input.pageUrl || '');
    const parsed = normalizeUrl(link.url, page.ok && page.isWeb ? page.href : undefined);
    if (!parsed.ok || !parsed.isWeb) return { findings: [], host: '' };
    const { hostname, host } = parsed;

    // Moving around inside the same website is the page check's job, not ours.
    if (page.ok && page.isWeb && sameSite(page.hostname, hostname) && !urlRules.knownThreat(parsed)) {
      return { findings: [], host, sameSite: true };
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
        // A real ad's click usually goes through an ad network first: we can't
        // compare the company in the ad with an address we can't see.
        const service = domainRules.serviceKind(hostname);
        const mismatch = service ? [] : domainRules.checkNamedBrand(offerText, hostname, 'offer');
        if (mismatch.length) derived.push(...mismatch);
        else if (text.some(f => f.code === 'PRIZE_CLAIM' || f.code === 'PAY_TO_CLAIM')) {
          derived.push({ code: 'UNVERIFIED_PRIZE_CLAIM', subject: 'link', data: { host, service: service ? registrableDomain(hostname) : '' }, evidence: { kind: 'url', value: parsed.href } });
        }
      }
    }
    return { findings: [...other, ...text, ...derived], host, flags: other };
  }

  function evaluatePage(input) {
    const ctx = input.context || {};
    const page = parseUrl(input.pageUrl || '');
    if (!page.ok || !page.isWeb) return { findings: [], host: '' };
    const { hostname, host } = page;
    // The company's real website.
    if (domainRules.officialBrandFor(hostname) && !urlRules.knownThreat(page)) return { findings: [], host };

    const other = [
      ...urlRules.checkAddress(page, 'page'),
      ...domainRules.checkAddress(hostname, 'page'),
    ];

    const claim = `${input.pageTitle || ''}\n${(ctx.mainHeadings || []).join('\n')}`;
    // "hasPayment" is the name the page scanner on the other branch uses (integration checklist).
    const secretForms = (input.forms || []).filter(f => f.hasPassword || f.hasPaymentField || f.hasPayment);
    other.push(...domainRules.checkSignInPage(claim, hostname, secretForms.length > 0));
    // Where the password or card number would be sent.
    other.push(...urlRules.checkSecretForms(page, secretForms));

    const pageText = `${claim}\n${(input.visibleText || '').slice(0, MAX_TEXT)}`;
    const text = keepText(textRules.checkWebText(pageText), other, 'webpage', textRules.looksLikeScamAdvice(pageText));
    return { findings: [...other, ...text], host, asksForSecrets: secretForms.length > 0 };
  }

  // A remote lookup's answer, as a finding. Only a match adds anything:
  // "not on the list" never removes what we found here.
  //   lookup = { status: 'match' | 'no_match' | 'error', url, source: { name, trusted } }
  //   ('failed' is accepted as an older name for 'error'.)
  function lookupFindings(input, lookup) {
    if (!lookup || lookup.status !== 'match') return [];
    const parsed = parseUrl(lookup.url || '');
    const source = lookup.source || { name: 'unknown', trusted: false };
    return [{
      code: 'KNOWN_THREAT',
      subject: input.source === 'webpage' ? 'page' : 'link',
      data: { host: parsed.ok ? parsed.host : lookup.url, trusted: !!source.trusted, source: source.name, remote: true },
      evidence: { kind: 'url', value: parsed.ok ? parsed.href : String(lookup.url) },
    }];
  }

  // The full decision, with the details tests and older callers need.
  function evaluate(input, options = {}) {
    let evaluation;
    if (input.source === 'email') evaluation = evaluateEmail(input);
    else if (input.source === 'link') evaluation = evaluateLink(input);
    else if (input.source === 'webpage') evaluation = evaluatePage(input);
    else throw new Error(`unknown source: ${input.source}`);
    const findings = [...evaluation.findings, ...lookupFindings(input, options.lookup)];
    return { ...evaluation, decision: decide(findings, input.source, { asksForSecrets: !!evaluation.asksForSecrets }) };
  }

  // Should the browser ask a remote threat service before opening this?
  //   'not_needed'      the answer is already clear (blocked, or the person is being stopped)
  //   'before_opening'  there are warning signs: hold the click and show "checking"
  //                     until the answer comes back. Never let it open just because
  //                     the check is slow.
  //   'optional'        no warning signs: open now; a check may run alongside
  function whenToLookUp(result) {
    if (!result || result.verdict === 'block') return 'not_needed';
    if (result.recommendedAction === 'GO_BACK' || result.recommendedAction === 'DO_NOT_ENTER_INFO') return 'not_needed';
    if (result.verdict === 'warn') return 'before_opening';
    return 'optional';
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
  //   options.lookup  a remote lookup's answer (see lookupFindings), if there is one
  function analyze(input, options = {}) {
    try {
      if (!input || typeof input !== 'object') return { ...UNKNOWN };
      return toResult(evaluate(input, options || {}).decision);
    } catch (e) {
      return { ...UNKNOWN };
    }
  }

  core.analyzer = { SCHEMA_VERSION, MAX_TEXT, analyze, evaluate, toResult, whenToLookUp };
  if (typeof module !== 'undefined') module.exports = core.analyzer;
})();
