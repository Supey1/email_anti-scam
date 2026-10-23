// explain.js: turns an analyzer result (docs/interfaces.md) into the words the warning interface shows.
// ONE place for headlines, icons, and advice, so the same result reads the same no matter which
// adapter (webpage, link click, email) supplied the evidence.
// It decides nothing about risk and nothing about whether to interrupt: the engine's verdict and
// recommendedAction do that. This only describes them.

const Explain = (() => {
  const VERDICTS = {
    block: { icon: '🛑', label: 'DANGER', headline: 'Stop. This is dangerous.', why: 'Why we stopped you', primary: 'Go back to safety' },
    warn: { icon: '⚠️', label: 'CAUTION', headline: 'Stop and check this first', why: 'Why we\'re warning you', primary: 'Go back to safety' },
    no_warning_signs: {
      icon: '✅', label: 'NO WARNING SIGNS', headline: 'No warning signs found', why: 'What we checked', primary: 'Got it',
      note: 'This does not prove it is safe. Never share passwords or bank details unless you are sure.',
    },
    unknown: { icon: '❔', label: 'NOT CHECKED', headline: 'We could not check this', why: 'What happened', primary: 'Got it', note: 'Be careful, and ask someone you trust if you are unsure.' },
  };

  // How strongly to speak depends on what the engine recommends. A weak warning that does not
  // interrupt anyone reads differently from one that stops a click.
  const WARN_BY_ACTION = {
    GO_BACK: {},
    DO_NOT_ENTER_INFO: { headline: 'Do not type anything on this page', primary: 'Leave this page' },
    VERIFY_INDEPENDENTLY: { headline: 'Be careful: check this first', primary: 'Got it' },
  };

  const ACTIONS = {
    GO_BACK: 'Do not go there. Go back to safety.',
    DO_NOT_ENTER_INFO: 'Do not type passwords, card numbers, or other private information here.',
    VERIFY_INDEPENDENTLY: 'Check with the company or a person you trust, using a phone number or website you already know.',
    NONE: '',
  };

  // The engine decides whether to interrupt. Only these two actions stop a click or cover a page.
  const interrupts = result => !!result && (result.recommendedAction === 'GO_BACK' || result.recommendedAction === 'DO_NOT_ENTER_INFO');

  // Anything that is not a well-formed result is treated as "unknown", never as "no warning signs".
  function normalize(result) {
    if (!result || typeof result !== 'object' || !VERDICTS[result.verdict]) return { verdict: 'unknown', reasons: [], recommendedAction: 'NONE' };
    const reasons = (Array.isArray(result.reasons) ? result.reasons : []).map(r => ({
      code: String((r && r.code) || ''),
      title: String((r && r.title) || ''),
      explanation: String((r && (r.explanation || r.title)) || ''),
    }));
    return { verdict: result.verdict, reasons, recommendedAction: result.recommendedAction || 'NONE' };
  }

  // describe(result) -> everything the interface needs.
  // Only the most important `maxTop` reasons are in `top` (the engine lists the strongest first); the rest are in `more`.
  function describe(result, maxTop = 3) {
    const r = normalize(result);
    const v = { ...VERDICTS[r.verdict], ...(r.verdict === 'warn' ? WARN_BY_ACTION[r.recommendedAction] : {}) };
    return {
      verdict: r.verdict,
      action: r.recommendedAction,
      icon: v.icon,
      label: v.label,
      headline: v.headline,
      whyHeading: v.why,
      primaryLabel: v.primary,
      top: r.reasons.slice(0, maxTop),
      more: r.reasons.slice(maxTop),
      advice: ACTIONS[r.recommendedAction] || v.note || '',
      note: v.note || '',
      canContinue: r.verdict === 'warn', // never for "block"
      interrupts: interrupts(r),
      severity: r.verdict === 'block' ? 'high' : r.verdict === 'warn' ? 'medium' : r.verdict === 'no_warning_signs' ? 'low' : 'unknown',
    };
  }

  // The words read aloud: headline, the top reasons, then what to do.
  function spokenParts(model) {
    return [model.headline + '.', ...model.top.map(r => r.explanation), model.advice].filter(Boolean);
  }

  return { describe, normalize, spokenParts, interrupts, VERDICTS, ACTIONS };
})();

// Lets tests load this file with Node. Chrome ignores this.
if (typeof module !== 'undefined') {
  module.exports = Explain;
}
