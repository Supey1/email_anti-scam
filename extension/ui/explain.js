// explain.js: turns an analyzer result into the words the warning interface shows.
// ONE place for headlines, icons, and advice, so the same result always reads the same
// no matter which adapter (webpage, link click, email) supplied the evidence.
// It decides nothing about risk; it only describes the verdict it is given.

const Explain = (() => {
  const VERDICTS = {
    block: { icon: '🛑', label: 'DANGER', headline: 'Stop. This is dangerous.', why: 'Why we stopped you' },
    warn: { icon: '⚠️', label: 'CAUTION', headline: 'Stop and check this first', why: 'Why we\'re warning you' },
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

  // TEMPORARY (see docs/integration-checklist.md): the analyzer still returns the old shape
  // (verdict "allow", reasons as plain strings). Accept both so the interface works with either.
  function normalize(result) {
    if (!result || typeof result !== 'object') return { verdict: 'unknown', reasons: [], recommendedAction: 'NONE' };
    const verdict = result.verdict === 'allow' ? 'no_warning_signs' : (VERDICTS[result.verdict] ? result.verdict : 'unknown');
    const reasons = (result.reasons || []).map(r => typeof r === 'string'
      ? { code: '', title: '', explanation: r }
      : { code: r.code || '', title: r.title || '', explanation: r.explanation || r.title || '' });
    return { verdict, reasons, recommendedAction: result.recommendedAction || '' };
  }

  // describe(result) -> everything the interface needs.
  // Only the most important `maxTop` reasons are in `top`; the rest are in `more`.
  function describe(result, maxTop = 3) {
    const r = normalize(result);
    const v = VERDICTS[r.verdict];
    const action = Object.prototype.hasOwnProperty.call(ACTIONS, r.recommendedAction) ? ACTIONS[r.recommendedAction] : r.recommendedAction;
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
