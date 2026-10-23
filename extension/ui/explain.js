// explain.js: turns an analyzer result into the words the warning interface shows.
// ONE place for headlines, icons, and advice, so the same result always reads the same
// no matter which adapter (webpage, link click, email) supplied the evidence.
// It decides nothing about risk; it only describes the verdict it is given.

const Explain = (() => {
  const VERDICTS = {
    block: { icon: '🛑', label: 'DANGER', headline: 'Stop. This is dangerous.', why: 'Why we stopped you' },
    warn: { icon: '⚠️', label: 'CAUTION', headline: 'Stop and check this first', why: 'Why we\'re warning you' },
    // "warn" with VERIFY_INDEPENDENTLY: weaker signs. Shown, but it never stops a click.
    check: { icon: '⚠️', label: 'BE CAREFUL', headline: 'Be careful: check this first', why: 'What we noticed' },
    no_warning_signs: {
      icon: '✅', label: 'NO WARNING SIGNS', headline: 'No warning signs found', why: 'What we checked',
      note: 'This does not prove it is safe. Never share passwords or bank details unless you are sure.',
    },
    unknown: { icon: '❔', label: 'NOT CHECKED', headline: 'We could not check this', why: 'What happened', note: 'Be careful, and ask someone you trust if you are unsure.' },
  };

  const ACTIONS = {
    GO_BACK: 'Close this page and go back to safety.',
    VERIFY_INDEPENDENTLY: 'Check with the company or a person you trust, using a phone number or website you already know.',
    DO_NOT_ENTER_INFO: 'Do not enter passwords, card numbers, or other private information.',
    NONE: '',
  };
  // In Gmail there is no page to close: what to do with an email instead.
  const EMAIL_ACTIONS = {
    GO_BACK: 'Do not click any links in this email. Do not reply, and never send money, gift cards, or passwords. Ask someone you trust before doing anything.',
    VERIFY_INDEPENDENTLY: 'Do not click links unless you were expecting this email. If it says it is from a company, call them using the number on your card or bill, not a number in this email.',
  };

  // The analyzer's result (docs/interfaces.md), with anything malformed made harmless.
  const VERDICT_NAMES = ['block', 'warn', 'no_warning_signs', 'unknown'];
  function normalize(result) {
    if (!result || typeof result !== 'object') return { verdict: 'unknown', reasons: [], recommendedAction: 'NONE' };
    const verdict = VERDICT_NAMES.includes(result.verdict) ? result.verdict : 'unknown';
    const reasons = (Array.isArray(result.reasons) ? result.reasons : []).filter(r => r && typeof r === 'object')
      .map(r => ({ code: String(r.code || ''), title: String(r.title || ''), explanation: String(r.explanation || r.title || '') }));
    return { verdict, reasons, recommendedAction: typeof result.recommendedAction === 'string' ? result.recommendedAction : '' };
  }

  // describe(result) -> everything the interface needs.
  // Only the most important `maxTop` reasons are in `top`; the rest are in `more`.
  // where: 'email' for the Gmail panel (different advice: there is no page to leave).
  function describe(result, maxTop = 3, where = '') {
    const r = normalize(result);
    const v = r.verdict === 'warn' && r.recommendedAction === 'VERIFY_INDEPENDENTLY' ? VERDICTS.check : VERDICTS[r.verdict];
    const actions = where === 'email' ? { ...ACTIONS, ...EMAIL_ACTIONS } : ACTIONS;
    const action = Object.prototype.hasOwnProperty.call(actions, r.recommendedAction) ? actions[r.recommendedAction] : '';
    return {
      verdict: r.verdict,
      icon: v.icon,
      label: v.label,
      headline: v.headline,
      whyHeading: v.why,
      top: r.reasons.slice(0, maxTop),
      more: r.reasons.slice(maxTop),
      advice: action || v.note || '',
      note: v.note || '',
      canContinue: r.verdict === 'warn', // never for "block"
      severity: r.verdict === 'block' ? 'high' : r.verdict === 'warn' ? 'medium' : r.verdict === 'no_warning_signs' ? 'low' : 'unknown',
    };
  }

  // The words read aloud: headline, the top reasons, then what to do.
  function spokenText(model) {
    return [model.headline + '.', ...model.top.map(r => r.explanation), model.advice].filter(Boolean).join(' ');
  }

  return { describe, normalize, spokenText, VERDICTS, ACTIONS };
})();

// Lets tests load this file with Node. Chrome ignores this.
if (typeof module !== 'undefined') {
  module.exports = Explain;
}
