// risk-policy.js: which warning signs, and which combinations, lead to a block or a warning.
//
// This is the only file that says how much each sign counts. The rule files
// only say WHAT they found; this file decides what it MEANS.
//
// 1. A website on the known-dangerous list is confirmed evidence, not a guess:
//    verdict "block".
// 2. Every other sign has points. Each kind of sign counts once, however many
//    times it appears (two shortened links are still one warning sign).
// 3. Some signs count only when backed up by another (see keepText below).
// 4. Some signs are stronger together (see COMBOS).
// 5. Total points:
//      5 or more  -> "warn" + stop the person (GO_BACK or DO_NOT_ENTER_INFO)
//      1 to 4     -> "warn" + VERIFY_INDEPENDENTLY (shown, never interrupts)
//      0          -> "no_warning_signs"

(function () {
  'use strict';
  const core = globalThis.GranblockCore = globalThis.GranblockCore || {};

  const STOP_AT = 5;
  const SHOW_AT = 1;

  // group: what kind of evidence it is. Independent groups backing each other
  // up is what makes a warning believable.
  //   threat       on the known-dangerous list
  //   destination  where a link or page really goes
  //   identity     who it claims to be versus who it is
  //   page         what the page does with what you type
  //   claim        a story: you won, your account is locked, a package is stuck
  //   request      asks you to do something: pay, call, share details
  //   pressure     rushing or secrecy
  //   combo        added by COMBOS
  //   context      where the link is (inside a scam email)
  const RULES = {
    KNOWN_THREAT: { points: 10, group: 'threat' },
    LOOKALIKE_DOMAIN: { points: 4, group: 'destination' },
    HIDDEN_DESTINATION: { points: 3, group: 'destination' },
    MISLEADING_URL: { points: 3, group: 'destination' },
    NUMBER_ADDRESS: { points: 3, group: 'destination' },
    BRAND_NAME_MISMATCH: { points: 2, group: 'destination' },
    SHORTENED_LINK: { points: 1, group: 'destination' },
    RISKY_DOMAIN_ENDING: { points: 1, group: 'destination' },
    UNVERIFIED_PRIZE_CLAIM: { points: 0, group: 'destination' },
    SENDER_NAME_MISMATCH: { points: 4, group: 'identity' },
    LOOKALIKE_SENDER: { points: 4, group: 'identity' },
    COMPANY_ON_FREE_EMAIL: { points: 2, group: 'identity' },
    FAKE_SIGN_IN_PAGE: { points: 5, group: 'identity' },
    CREDENTIALS_SENT_ELSEWHERE: { points: 3, group: 'page' },
    PRIZE_CLAIM: { points: 3, group: 'claim' },
    ACCOUNT_PROBLEM_CLAIM: { points: 3, email: 2, group: 'claim' },
    DELIVERY_PROBLEM_CLAIM: { points: 2, group: 'claim' },
    TECH_SUPPORT_CLAIM: { points: 2, group: 'claim' },
    FAMILY_EMERGENCY: { points: 3, group: 'claim' },
    PAYMENT_METHOD_REQUEST: { points: 3, group: 'request' },
    PAY_TO_CLAIM: { points: 3, group: 'request' },
    PERSONAL_INFO_REQUEST: { points: 2, group: 'request' },
    CALL_THIS_NUMBER: { points: 3, group: 'request' },
    SECRECY_REQUEST: { points: 3, group: 'pressure' },
    PRESSURE_TACTICS: { points: 1, group: 'pressure' },
    PRIZE_WITH_PRESSURE: { points: 2, group: 'combo' },
    INSIDE_SCAM_EMAIL: { points: 5, group: 'context' },
  };

  const TEXT_GROUPS = new Set(['claim', 'request', 'pressure']);

  // Signs that are much stronger together than apart.
  const COMBOS = [
    { needs: ['PRIZE_CLAIM', 'PRESSURE_TACTICS'], adds: 'PRIZE_WITH_PRESSURE' },
  ];

  function pointsFor(finding, source) {
    const rule = RULES[finding.code];
    if (!rule) return 0;
    // Writing a company's real website in front of a fake one has no innocent use.
    if (finding.code === 'LOOKALIKE_DOMAIN' && finding.data.technique === 'official_domain_in_front') return 5;
    // "paypal.com@evil.example" has no innocent use either.
    if (finding.code === 'MISLEADING_URL' && finding.data.trick === 'before_at') return 5;
    return rule[source] !== undefined ? rule[source] : rule.points;
  }

  function isText(finding) {
    return TEXT_GROUPS.has((RULES[finding.code] || {}).group);
  }

  // Which wording findings count?
  // Emails are written TO the person, so all their wording counts.
  // On websites and around links, one scary phrase alone is too common
  // (a bank's safety tips say "your account is locked" too). Wording counts
  // only if another kind of evidence backs it up, or if it tells two parts
  // of a scam story (like "you won" + "pay a fee"). On a page that talks
  // ABOUT scams, wording counts only with other evidence.
  function keepText(textFindings, otherFindings, source, isScamAdvice) {
    if (source === 'email') return textFindings;
    const backedUp = otherFindings.some(f => pointsFor(f, source) > 0);
    if (backedUp) return textFindings;
    if (isScamAdvice) return [];
    const groups = new Set(textFindings.map(f => RULES[f.code].group));
    return groups.size >= 2 ? textFindings : [];
  }

  // Turns findings into a decision.
  //   source          'webpage' | 'email' | 'link'
  //   asksForSecrets  the page has a password or payment box
  // Returns { verdict, recommendedAction, confirmed, score, reasons: [{ code, points, findings }] }
  function decide(findings, source, { asksForSecrets = false } = {}) {
    const all = findings.slice();
    const codes = new Set(all.map(f => f.code));
    for (const combo of COMBOS) {
      if (combo.needs.every(code => codes.has(code)) && !codes.has(combo.adds)) {
        all.push({ code: combo.adds, subject: 'text', data: { needs: combo.needs }, evidence: null });
      }
    }

    // One reason per code. Its points are the strongest of its findings.
    const byCode = new Map();
    for (const f of all) {
      const points = pointsFor(f, source);
      const entry = byCode.get(f.code);
      if (!entry) byCode.set(f.code, { code: f.code, points, findings: [f] });
      else {
        entry.findings.push(f);
        if (points > entry.points) {
          entry.points = points;
          entry.findings.unshift(entry.findings.pop()); // the strongest finding explains the reason
        }
      }
    }
    const reasons = [...byCode.values()].sort((a, b) => b.points - a.points);
    const score = reasons.reduce((sum, r) => sum + r.points, 0);
    const confirmed = byCode.has('KNOWN_THREAT');

    let verdict, recommendedAction;
    if (confirmed) {
      verdict = 'block';
      recommendedAction = 'GO_BACK';
    } else if (score >= STOP_AT) {
      verdict = 'warn';
      recommendedAction = source === 'webpage' && asksForSecrets ? 'DO_NOT_ENTER_INFO' : 'GO_BACK';
    } else if (score >= SHOW_AT) {
      verdict = 'warn';
      recommendedAction = 'VERIFY_INDEPENDENTLY';
    } else {
      verdict = 'no_warning_signs';
      recommendedAction = 'NONE';
    }
    return {
      verdict,
      recommendedAction,
      confirmed,
      score,
      reasons: verdict === 'no_warning_signs' ? [] : reasons,
    };
  }

  core.riskPolicy = { RULES, COMBOS, STOP_AT, SHOW_AT, pointsFor, isText, keepText, decide };
  if (typeof module !== 'undefined') module.exports = core.riskPolicy;
})();
