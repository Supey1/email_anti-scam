// warning-view.js: builds the warning interface from an Explain.describe() model.
// Used by the extension-owned warning page and by the in-page panel, so both look and behave the same.
//
// Accessibility: dialog role with a label, announced when it appears, focus moves to the safe
// action and is kept inside the card, visible focus outlines, every severity shown as an icon
// AND a word (never colour alone), and a keyboard-reachable "read to me".
// Safety: everything from the web is added with textContent, never innerHTML.

const WarningView = (() => {
  function el(tag, props = {}, children = []) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value);
    }
    for (const child of [].concat(children)) if (child) node.append(child);
    return node;
  }

  function speak(text, onEnd, rate = 0.9) {
    window.speechSynthesis.cancel();
    const speech = new SpeechSynthesisUtterance(text);
    speech.rate = rate;
    speech.onend = speech.onerror = onEnd;
    window.speechSynthesis.speak(speech);
  }

  // Keeps Tab and Shift+Tab inside `root`. Works inside a shadow root too.
  function trapFocus(root) {
    root.addEventListener('keydown', event => {
      if (event.key !== 'Tab') return;
      const items = [...root.querySelectorAll('button, summary, a[href]')].filter(n => !n.disabled && !n.hidden);
      if (!items.length) return;
      const active = root.getRootNode().activeElement;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && (active === first || !items.includes(active))) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && active === last) { event.preventDefault(); first.focus(); }
    });
  }

  // model = Explain.describe(result)
  // options = {
  //   textSizePx: the person's text size, speechRate: how fast to read aloud, showRead: false hides "Read to me",
  //   primaryLabel: text of the main button (default "Go back to safety"),
  //   extras: [{ heading, lines: [{ text, muted?, flag? }] }] shown after the advice,
  //   destination: a line (or array of lines) shown above the reasons, such as what a link says and where it really goes,
  //   corner: true for a small card in the corner instead of a centered one,
  //   onBack, onContinue (only used when model.canContinue), onReport (optional), onHide (optional)
  // }
  // Returns { card, primary, startReading } where primary is the button to focus.
  function render(model, options = {}) {
    const announce = el('p', { class: 'sr-only', role: 'status', 'aria-live': 'polite' });
    const reasons = model.top.map(r => el('li', {}, [
      r.title ? el('strong', { text: r.title + '. ' }) : null,
      document.createTextNode(r.explanation),
    ]));
    const moreReasons = model.more.length
      ? el('details', { class: 'more' }, [
          el('summary', { text: `Show ${model.more.length} more detail${model.more.length === 1 ? '' : 's'}` }),
          el('ul', {}, model.more.map(r => el('li', { text: r.explanation }))),
        ])
      : null;

    const primary = el('button', { class: 'primary', text: options.primaryLabel || 'Go back to safety', onclick: () => options.onBack && options.onBack() });
    const read = el('button', { text: '🔊 Read to me', 'aria-pressed': 'false' });
    let reading = false;
    const toggleReading = () => {
      if (reading) { window.speechSynthesis.cancel(); return; }
      reading = true;
      read.setAttribute('aria-pressed', 'true');
      read.textContent = '⏹ Stop reading';
      speak(Explain.spokenText(model), () => {
        reading = false;
        read.setAttribute('aria-pressed', 'false');
        read.textContent = '🔊 Read to me';
      }, options.speechRate);
    };
    read.addEventListener('click', toggleReading);

    const report = options.onReport ? el('button', { class: 'quiet', text: 'This is a false alarm', onclick: () => {
      options.onReport();
      report.disabled = true;
      report.textContent = 'Thanks. Saved for testing.';
      announce.textContent = 'Thanks. Your false alarm report was saved for testing.';
    } }) : null;

    const secondary = [];
    if (model.canContinue && options.onContinue) {
      secondary.push(el('button', { class: 'quiet', text: 'I understand the risk. Continue anyway', onclick: () => options.onContinue() }));
    }
    if (options.onHide) secondary.push(el('button', { class: 'quiet', text: 'Hide', onclick: () => options.onHide() }));

    const card = el('div', {
      class: `card ${model.severity}${options.corner ? ' corner' : ''}`,
      role: model.verdict === 'block' || model.verdict === 'warn' ? 'alertdialog' : 'dialog',
      'aria-modal': options.corner ? 'false' : 'true',
      'aria-labelledby': 'warning-headline',
      'aria-describedby': 'warning-why',
    }, [
      el('div', { class: `verdict ${model.severity === 'high' ? 'high' : model.severity === 'medium' ? 'medium' : 'low'}` }, [
        el('span', { class: 'icon', 'aria-hidden': 'true', text: model.icon }),
        el('div', {}, [
          el('div', { class: 'label', text: model.label }),
          el('h1', { id: 'warning-headline', text: model.headline }),
        ]),
      ]),
      el('div', { class: 'section', id: 'warning-why' }, [
        ...[].concat(options.destination || []).map(line => el('p', { class: 'dest', text: line })),
        model.top.length ? el('h2', { text: model.whyHeading }) : null,
        model.top.length ? el('ul', {}, reasons) : null,
        moreReasons,
        model.advice ? el('h2', { text: 'What you should do' }) : null,
        model.advice ? el('p', { text: model.advice }) : null,
        ...(options.extras || []).map(extra => el('div', { class: 'extra' }, [
          el('h2', { text: extra.heading }),
          ...extra.lines.filter(Boolean).map(line => el('p', { class: line.flag ? 'flag' : line.muted ? 'muted' : '', text: line.text })),
        ])),
      ]),
      el('div', { class: 'actions' }, [primary, options.showRead === false ? null : read, ...secondary, report]),
      announce,
    ]);
    announce.textContent = `${model.label}. ${model.headline}`;
    if (options.textSizePx) card.style.fontSize = `${options.textSizePx}px`;
    trapFocus(card);
    return { card, primary, startReading: toggleReading };
  }

  return { render, el, speak };
})();
