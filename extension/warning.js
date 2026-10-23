// warning.js: the big "Stop and check" warning that covers the page.
// guard.js shows it before opening a risky link. page.js shows it when the
// website itself looks like a scam.
//
// Safety note: like the Gmail panel, every word is added with textContent,
// never innerHTML, so a scam page can't sneak code into our warning.

const WARNING_TEXT = {
  block: {
    icon: '🛑',
    title: 'Stop. This website is known to be dangerous.',
    advice: [
      'Do not open it.',
      'Never type a password, bank details, or a card number on a website you reached from a link like this.',
      'If you were worried about your account, go to the company\'s website yourself, or call the number on your card or bill.',
    ],
  },
  link: {
    icon: '🛑',
    title: 'Stop and check this link',
    advice: [
      'Go back unless you are sure this is safe.',
      'If it says it is from a company, go to that company\'s website yourself, or call the number on your card or bill.',
      'Never pay with gift cards, crypto, or wire transfers.',
    ],
  },
  page: {
    icon: '⚠️',
    title: 'Be careful on this page',
    advice: [
      'Do not type passwords, card numbers, or personal details here.',
      'Do not call any phone number shown on this page.',
      'If you are worried, leave this page and ask someone you trust.',
    ],
  },
};

// Reads sentences out loud at the person's chosen speed (speech.js, settings-sync.js).
function speakAloud(parts, key) {
  return GranblockSpeech.speak(parts, { rate: GranblockSettings.get().speechRate, key });
}

// Shows the warning. Only one at a time.
//   kind        'block' | 'link' | 'page'
//   result      the answer from analyzeLink() or analyzePage()
//   onBack      what "Go back to safety" does
//   onContinue  what "open it anyway" does. Leave it out to offer no way through.
const showWarning = (() => {
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

  return function showWarning({ kind, result, onBack, onContinue }) {
    if (host) host.remove();
    const text = WARNING_TEXT[kind];
    const reasons = result.reasons.slice(0, 4);
    const previousFocus = document.activeElement;

    host = el('div', { id: 'email-anti-scam-warning' });
    const shadow = host.attachShadow({ mode: 'open' });
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(WARNING_CSS);
    shadow.adoptedStyleSheets = [sheet];

    function close() {
      GranblockSpeech.stop();
      document.removeEventListener('keydown', onKey, true);
      if (host) host.remove();
      host = null;
      if (previousFocus && previousFocus.focus) previousFocus.focus();
    }
    function onKey(event) {
      if (event.key === 'Escape') {
        event.preventDefault();
        close();
        onBack();
      }
    }

    // The verdict, why, and the safe next step.
    const spoken = () => [
      text.title + '.',
      result.host && kind !== 'page' ? `This link really goes to ${result.host}.` : '',
      ...reasons,
      'Here is what to do.',
      ...text.advice,
    ];
    const speechKey = `warning|${kind}|${text.title}|${reasons.join('|')}`;

    const back = el('button', {
      class: 'back',
      text: '⬅ Go back to safety',
      onclick: () => { close(); onBack(); },
    });

    const dialog = el('div', { class: `dialog ${kind}`, role: 'alertdialog', 'aria-modal': 'true', 'aria-labelledby': 'warning-title' }, [
      el('div', { class: 'verdict' }, [
        el('span', { class: 'icon', 'aria-hidden': 'true', text: text.icon }),
        el('span', { id: 'warning-title', text: text.title }),
      ]),
      result.host && kind !== 'page'
        ? el('p', { class: 'where' }, [el('span', { text: 'This link really goes to: ' }), el('strong', { text: result.host })])
        : null,
      reasons.length
        ? el('div', { class: 'section' }, [
            el('h3', { text: 'Why we stopped you' }),
            el('ul', {}, reasons.map(r => el('li', { text: r }))),
          ])
        : null,
      el('div', { class: 'section' }, [
        el('h3', { text: 'What you should do' }),
        el('ul', {}, text.advice.map(a => el('li', { text: a }))),
      ]),
      el('div', { class: 'buttons' }, [
        back,
        GranblockSpeech.makeButton(document, { getParts: spoken, key: speechKey, rate: () => GranblockSettings.get().speechRate, className: 'read' }),
      ]),
      onContinue
        ? el('button', {
            class: 'continue',
            text: kind === 'page' ? 'Stay on this page (I understand the risk)' : 'Open it anyway (I understand the risk)',
            onclick: () => { close(); onContinue(); },
          })
        : null,
    ]);

    dialog.style.zoom = GranblockSettings.zoom(); // the person's text size
    shadow.append(el('div', { class: 'backdrop' }, [dialog]));
    document.documentElement.append(host);
    document.addEventListener('keydown', onKey, true);
    back.focus();
    if (GranblockSettings.get().autoRead) speakAloud(spoken(), speechKey);
  };
})();
