// panel.js: the in-page warning card (shadow DOM, so the website's styles can't change it).
// Used by page.js for page-level warnings, and by click-guard.js only as a fallback.
//
// An in-page panel is NOT a security boundary: the page it sits on could hide or remove it.
// For high-confidence blocks the extension's own warning page (ui/warning.html) is used instead.

const EmailAntiScamPanel = (() => {
  let host = null;
  let chip = null;
  let previousFocus = null;
  let lastOptions = null;

  function removeChip() {
    if (chip) chip.remove();
    chip = null;
  }

  function close(settings = {}) {
    window.speechSynthesis.cancel();
    if (host) host.remove();
    host = null;
    if (previousFocus && previousFocus.isConnected) previousFocus.focus();
    previousFocus = null;
    if (settings.removeChip) { removeChip(); lastOptions = null; }
  }

  // A small button that brings a hidden card back (used by the Gmail panel).
  function showChip(model) {
    removeChip();
    chip = document.createElement('div');
    chip.id = 'email-anti-scam-chip';
    const shadow = chip.attachShadow({ mode: 'open' });
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(PANEL_CSS);
    shadow.adoptedStyleSheets = [sheet];
    const button = document.createElement('button');
    button.className = `reopen ${model.severity === 'unknown' ? 'low' : model.severity}`;
    button.textContent = `${model.icon} Safety check`;
    button.addEventListener('click', () => { removeChip(); showWarning(lastOptions); });
    shadow.append(button);
    document.documentElement.append(chip);
  }

  // options = {
  //   result: the analyzer's result,
  //   destination: text shown above the reasons (optional),
  //   modal: true to cover the page, false for a card in the corner,
  //   onBack, onContinue (shown only for "warn"), onReport (optional)
  // }
  function showWarning(options) {
    close();
    removeChip();
    lastOptions = options;
    previousFocus = document.activeElement;
    const model = Explain.describe(options.result);
    const done = fn => () => { close(); if (options.leaveChip) showChip(model); if (fn) fn(); };

    const { card, primary } = WarningView.render(model, {
      destination: options.destination,
      extras: options.extras,
      primaryLabel: options.primaryLabel,
      corner: !options.modal,
      onBack: done(options.onBack),
      onContinue: options.onContinue ? done(options.onContinue) : null,
      onReport: options.onReport,
      onHide: options.modal ? null : done(),
    });

    host = document.createElement('div');
    host.id = 'email-anti-scam-warning';
    const shadow = host.attachShadow({ mode: 'open' });
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(PANEL_CSS + WARNING_CSS);
    shadow.adoptedStyleSheets = [sheet];
    if (options.modal) {
      const backdrop = document.createElement('div');
      backdrop.className = 'backdrop';
      backdrop.append(card);
      shadow.append(backdrop);
    } else {
      shadow.append(card);
    }
    shadow.addEventListener('keydown', e => { if (e.key === 'Escape') done(options.modal ? options.onBack : null)(); });
    document.documentElement.append(host);
    // A corner card does not take focus from the page; a covering card must.
    if (options.modal) primary.focus();
  }

  return { showWarning, close };
})();
