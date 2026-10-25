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
    GranblockSpeech.stop();
    if (host) host.remove();
    host = null;
    if (previousFocus && previousFocus.isConnected) previousFocus.focus();
    previousFocus = null;
    if (settings.removeChip) { removeChip(); lastOptions = null; }
  }

  // Lets the person move the chip out of the way (it can sit on top of Gmail's own buttons): press on it, drag, let go.
  // A drag of a few pixels is a move, not a click, so moving it never opens the panel. The place is remembered.
  const inExtension = typeof chrome !== 'undefined' && !!chrome.storage && !!chrome.storage.local && !!chrome.runtime && !!chrome.runtime.id;

  function placeChip(x, y) {
    if (!chip) return;
    const box = chip.getBoundingClientRect();
    const left = Math.min(Math.max(0, x), Math.max(0, window.innerWidth - box.width));
    const top = Math.min(Math.max(0, y), Math.max(0, window.innerHeight - box.height));
    chip.style.left = `${left}px`;
    chip.style.top = `${top}px`;
    chip.style.right = 'auto';
    return { x: left, y: top };
  }

  function makeChipMovable(handle) {
    let start = null;
    let moved = false;
    handle.style.cursor = 'grab';
    handle.style.touchAction = 'none';
    handle.title = 'Click to open. Press and drag to move this button.';
    handle.addEventListener('pointerdown', e => {
      if (e.button !== 0) return;
      const box = chip.getBoundingClientRect();
      start = { x: e.clientX, y: e.clientY, left: box.left, top: box.top };
      moved = false;
      handle.setPointerCapture(e.pointerId);
    });
    handle.addEventListener('pointermove', e => {
      if (!start) return;
      const dx = e.clientX - start.x;
      const dy = e.clientY - start.y;
      if (!moved && Math.hypot(dx, dy) < 5) return;
      moved = true;
      handle.style.cursor = 'grabbing';
      placeChip(start.left + dx, start.top + dy);
    });
    handle.addEventListener('pointerup', e => {
      if (!start) return;
      start = null;
      handle.style.cursor = 'grab';
      try { handle.releasePointerCapture(e.pointerId); } catch (err) { /* already released */ }
      if (moved && inExtension) {
        const box = chip.getBoundingClientRect();
        // After the extension is reloaded or updated, an open tab's old copy of this script throws
        // "Extension context invalidated" here, so guard the call as well as the promise.
        try { chrome.storage.local.set({ chipPosition: { x: box.left, y: box.top } }).catch(() => {}); } catch { /* extension was reloaded */ }
      }
    });
    // Runs before the click that opens the panel, and cancels it if the press was really a move.
    handle.addEventListener('click', e => {
      if (moved) { e.stopImmediatePropagation(); e.preventDefault(); moved = false; }
    }, true);
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
    button.style.fontSize = `${Settings.TEXT_PX[Settings.current.textSize]}px`;
    button.addEventListener('click', () => { removeChip(); showWarning(lastOptions); });
    shadow.append(button);
    document.documentElement.append(chip);
    makeChipMovable(button);
    if (inExtension) {
      try {
        chrome.storage.local.get('chipPosition').then(({ chipPosition }) => {
          if (chip && chipPosition && Number.isFinite(chipPosition.x) && Number.isFinite(chipPosition.y)) placeChip(chipPosition.x, chipPosition.y);
        }).catch(() => {});
      } catch { /* extension was reloaded; the chip just stays in its default spot */ }
    }
  }

  // options = {
  //   result: the analyzer's result,
  //   destination: text shown above the reasons (optional),
  //   modal: true to cover the page, false for a card in the corner,
  //   onBack, onContinue (shown only for "warn"), onReport (optional),
  //   where: 'email' in the Gmail panel (email advice instead of "close this page")
  // }
  function showWarning(options) {
    close();
    removeChip();
    lastOptions = options;
    previousFocus = document.activeElement;
    const model = Explain.describe(options.result, 3, options.where);
    const done = fn => () => { close(); if (options.leaveChip) showChip(model); if (fn) fn(); };

    const prefs = Settings.current;
    const { card, primary, startReading } = WarningView.render(model, {
      textSizePx: Settings.TEXT_PX[prefs.textSize],
      speechRate: Settings.SPEECH_RATE[prefs.speechSpeed],
      showRead: prefs.readAloud !== 'off',
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
    // Reading out loud on its own is the person's choice, and only for warnings.
    if (prefs.readAloud === 'auto' && (model.verdict === 'warn' || model.verdict === 'block')) startReading();
  }

  return { showWarning, close };
})();
