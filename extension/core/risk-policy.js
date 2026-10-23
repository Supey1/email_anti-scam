// risk-policy.js: which warning signs, and which combinations, lead to each verdict.
//
// This is the only file that decides what the evidence MEANS. The rule files
// only say what they found.
//
// Every warning sign has a tier:
//   confirmed  on the known-dangerous list from a TRUSTED source
//   strong     no innocent explanation: enough on its own to stop someone
//   moderate   a real warning sign, but there can be innocent reasons
//   weak       common on normal websites too: never enough on its own,
//              however many weak signs there are
// and points (each kind of sign counts once, however often it appears).
//
// The verdict:
//   block                          any confirmed sign
//   warn + GO_BACK / DO_NOT_ENTER  any strong sign,
//                                  OR 5+ points with at least one moderate sign
//   warn + VERIFY_INDEPENDENTLY    1+ points (shown, never interrupts)
//   no_warning_signs               nothing
// A known-dangerous match from an UNTRUSTED source is strong, not confirmed:
// it stops the person, but they can choose to continue.
//
// Before points are added up, some wording is set aside (keepText): on
// websites and around links, one scary phrase needs backing up.
//
// | Example                                         | Verdict                       |
// |-------------------------------------------------|-------------------------------|
// | Address on the trusted known-dangerous list     | block                         |
// | paypal.com.fake-domain.example                  | warn, stop (strong)           |
// | paypa1-secure.example alone                     | warn, verify (moderate, 4)    |
// | paypa1-secure.xyz                               | warn, stop (4 + 1, moderate)  |
// | Shortened link + .xyz + "act now" + brand name  | warn, verify (weak only)      |
// | .xyz ending alone, or "urgent" alone in an email| warn, verify                  |
// | "urgent" alone on a webpage                     | no warning signs (keepText)   |

(function () {
  'use strict';
  const core = globalThis.GranblockCore = globalThis.GranblockCore || {};

  const STOP_AT = 5;
  const SHOW_AT = 1;

  // group: what kind of evidence it is (used by keepText).
  //   threat, destination, identity, page, claim, request, pressure, combo, context
  const RULES = {
    KNOWN_THREAT: { tier: 'confirmed', points: 10, group: 'threat' },

    FAKE_SIGN_IN_PAGE: { tier: 'strong', points: 5, group: 'identity' },
    INSIDE_SCAM_EMAIL: { tier: 'strong', points: 5, group: 'context' },

    LOOKALIKE_DOMAIN: { tier: 'moderate', points: 4, group: 'destination' },
    HIDDEN_DESTINATION: { tier: 'moderate', points: 3, group: 'destination' },
    MISLEADING_URL: { tier: 'moderate', points: 3, group: 'destination' },
    NUMBER_ADDRESS: { tier: 'moderate', points: 3, group: 'destination' },
    SENDER_NAME_MISMATCH: { tier: 'moderate', points: 4, group: 'identity' },
    LOOKALIKE_SENDER: { tier: 'moderate', points: 4, group: 'identity' },
    SIGN_IN_ON_FREE_HOSTING: { tier: 'moderate', points: 3, group: 'page' },
    CREDENTIALS_SENT_ELSEWHERE: { tier: 'moderate', points: 3, group: 'page' },
    PRIZE_CLAIM: { tier: 'moderate', points: 3, group: 'claim' },
    ACCOUNT_PROBLEM_CLAIM: { tier: 'moderate', points: 3, email: 2, group: 'claim' },
    DELIVERY_PROBLEM_CLAIM: { tier: 'moderate', points: 2, group: 'claim' },
    TECH_SUPPORT_CLAIM: { tier: 'moderate', points: 2, group: 'claim' },
    FAMILY_EMERGENCY: { tier: 'moderate', points: 3, group: 'claim' },
    PAYMENT_METHOD_REQUEST: { tier: 'moderate', points: 3, group: 'request' },
    PAY_TO_CLAIM: { tier: 'moderate', points: 3, group: 'request' },
    PERSONAL_INFO_REQUEST: { tier: 'moderate', points: 2, group: 'request' },
    CALL_THIS_NUMBER: { tier: 'moderate', points: 3, group: 'request' },
    SECRECY_REQUEST: { tier: 'moderate', points: 3, group: 'pressure' },
    PRIZE_WITH_PRESSURE: { tier: 'moderate', points: 2, group: 'combo' },

    BRAND_NAME_MISMATCH: { tier: 'weak', points: 2, group: 'destination' },
    COMPANY_ON_FREE_EMAIL: { tier: 'weak', points: 2, group: 'identity' },
    INSECURE_FORM: { tier: 'weak', points: 2, group: 'page' },
    SHORTENED_LINK: { tier: 'weak', points: 1, group: 'destination' },
    RISKY_DOMAIN_ENDING: { tier: 'weak', points: 1, group: 'destination' },
    PRESSURE_TACTICS: { tier: 'weak', points: 1, group: 'pressure' },
    UNVERIFIED_PRIZE_CLAIM: { tier: 'weak', points: 0, group: 'destination' },
  };

  const TEXT_GROUPS = new Set(['claim', 'request', 'pressure']);

  // Signs that are much stronger together than apart.
  const COMBOS = [
    { needs: ['PRIZE_CLAIM', 'PRESSURE_TACTICS'], adds: 'PRIZE_WITH_PRESSURE' },
  ];

  // Some findings are stronger (or weaker) than their code's usual tier.
  function tierFor(finding) {
    const rule = RULES[finding.code];
    if (!rule) return 'weak';
    const d = finding.data || {};
    if (finding.code === 'KNOWN_THREAT' && !d.trusted) return 'strong';
    // Writing a company's real website in front of a fake one has no innocent use.
    if (finding.code === 'LOOKALIKE_DOMAIN' && d.technique === 'official_domain_in_front') return 'strong';
    // Neither does "paypal.com@evil.example".
    if (finding.code === 'MISLEADING_URL' && d.trick === 'before_at') return 'strong';
    // A sign-in name hidden in a link is odd, but not proof of anything.
    if (finding.code === 'MISLEADING_URL' && d.trick === 'hidden_login') return 'weak';
    return rule.tier;
  }

  function pointsFor(finding, source) {
    const rule = RULES[finding.code];
    if (!rule) return 0;
    const tier = tierFor(finding);
    if (tier === 'strong' && rule.tier !== 'strong') return STOP_AT;
    if (tier === 'weak' && rule.tier !== 'weak') return 2;
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
  // Returns { verdict, recommendedAction, confirmed, stops, score, reasons: [{ code, points, tier, findings }] }
  function decide(findings, source, { asksForSecrets = false } = {}) {
    const all = findings.slice();
    const codes = new Set(all.map(f => f.code));
    for (const combo of COMBOS) {
      if (combo.needs.every(code => codes.has(code)) && !codes.has(combo.adds)) {
        all.push({ code: combo.adds, subject: 'text', data: { needs: combo.needs }, evidence: null });
      }
    }

    // One reason per code. Its points and tier are the strongest of its findings.
    const RANK = { weak: 0, moderate: 1, strong: 2, confirmed: 3 };
    const byCode = new Map();
    for (const f of all) {
      const points = pointsFor(f, source);
      const tier = tierFor(f);
      const entry = byCode.get(f.code);
      if (!entry) byCode.set(f.code, { code: f.code, points, tier, findings: [f] });
      else {
        entry.findings.push(f);
        if (RANK[tier] > RANK[entry.tier] || (tier === entry.tier && points > entry.points)) {
          entry.points = points;
          entry.tier = tier;
          entry.findings.unshift(entry.findings.pop()); // the strongest finding explains the reason
        }
      }
    }
    const reasons = [...byCode.values()].sort((a, b) => RANK[b.tier] - RANK[a.tier] || b.points - a.points);
    const score = reasons.reduce((sum, r) => sum + r.points, 0);
    const tiers = new Set(reasons.map(r => r.tier));

    const confirmed = tiers.has('confirmed');
    const stops = confirmed || tiers.has('strong') || (score >= STOP_AT && tiers.has('moderate'));

    let verdict, recommendedAction;
    if (confirmed) {
      verdict = 'block';
      recommendedAction = 'GO_BACK';
    } else if (stops) {
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
      stops,
      score,
      reasons: verdict === 'no_warning_signs' ? [] : reasons,
    };
  }

  core.riskPolicy = { RULES, COMBOS, STOP_AT, SHOW_AT, tierFor, pointsFor, isText, keepText, decide };
  if (typeof module !== 'undefined') module.exports = core.riskPolicy;
})();
