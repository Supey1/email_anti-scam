// panel.js: the big, plain-language warning card.
// Used by guard.js (when someone clicks a risky link) and page.js (when a risky page is found).
//
// Safety note: everything from the web is added with textContent, never innerHTML.

const EmailAntiScamPanel = (() => {
  const TITLES = {
    block: { icon: '🛑', text: 'Stop. This is dangerous.' },
    warn: { icon: '⚠️', text: 'Stop and check this first' },
  };
  let host = null;

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

  function close() {
    window.speechSynthesis.cancel();
    if (host) host.remove();
    host = null;
  }

  function speak(text) {
    window.speechSynthesis.cancel();
    const speech = new SpeechSynthesisUtterance(text);
    speech.rate = 0.9;
    window.speechSynthesis.speak(speech);
  }

  // options = {
  //   verdict: 'block' | 'warn', reasons: [...], advice: 'what to do', destination: 'optional address',
  //   modal: true to cover the page, false for a card in the corner,
  //   onBack: () => ..., onContinue: () => ... (leave out for "block": there is no way past it)
  // }
  function showWarning(options) {
    close();
    const title = TITLES[options.verdict] || TITLES.warn;
    const done = fn => () => { close(); if (fn) fn(); };

    const read = () => speak([title.text, ...options.reasons, options.advice].filter(Boolean).join(' '));
    const back = el('button', { class: 'primary', text: 'Go back to safety', onclick: done(options.onBack) });
    const actions = el('div', { class: 'actions' }, [
      back,
      el('button', { text: '🔊 Read to me', onclick: read }),
      options.onContinue ? el('button', { text: options.continueLabel || 'Continue anyway', onclick: done(options.onContinue) }) : null,
      !options.modal ? el('button', { text: 'Hide', onclick: done() }) : null,
    ]);

    const card = el('div', { class: `card${options.modal ? '' : ' corner'}`, role: 'alertdialog', 'aria-modal': options.modal ? 'true' : 'false', 'aria-label': title.text }, [
      el('div', { class: `verdict ${options.verdict === 'block' ? 'high' : 'medium'}`, role: 'status' }, [
        el('span', { class: 'icon', 'aria-hidden': 'true', text: title.icon }),
        el('span', { text: title.text }),
      ]),
      el('div', { class: 'section' }, [
        options.destination ? el('p', { class: 'dest', text: options.destination }) : null,
        el('h3', { text: options.verdict === 'block' ? 'Why we stopped you' : 'Why we\'re warning you' }),
        el('ul', {}, options.reasons.map(r => el('li', { text: r }))),
        options.advice ? el('h3', { text: 'What you should do' }) : null,
        options.advice ? el('p', { text: options.advice }) : null,
      ]),
      actions,
    ]);

    host = el('div', { id: 'email-anti-scam-warning' });
    const shadow = host.attachShadow({ mode: 'open' });
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(PANEL_CSS + WARNING_CSS);
    shadow.adoptedStyleSheets = [sheet];
    shadow.append(options.modal ? el('div', { class: 'backdrop' }, card) : card);
    shadow.addEventListener('keydown', e => { if (e.key === 'Escape') done(options.onBack)(); });
    document.documentElement.append(host);
    back.focus();
  }

  return { showWarning, close };
})();
