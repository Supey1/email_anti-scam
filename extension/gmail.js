// gmail.js: runs inside Gmail.
// 1. Notices when an email is opened.
// 2. Reads the sender, subject, text, and links.
// 3. Checks it with analyzeEmail() from rules.js.
// 4. Shows the big-text safety panel.
// 5. Tells guard.js when an email looks like a scam, so clicking ANY link in it
//    brings up the "Stop and check" warning first.
//
// Safety note: email content is ALWAYS added with textContent, never innerHTML,
// so a scam email can't sneak code into our panel.

(() => {
  'use strict';

  // Where Gmail keeps things on the page. Gmail changes these class names now and then.
  // If the panel stops finding emails, check these first (right-click > Inspect in Gmail).
  const SELECTORS = {
    subject: 'h2.hP',
    sender: 'span.gD', // has email="..." and name="..." attributes
    body: 'div.a3s',   // the message text (one per opened message in a thread)
  };

  const VERDICTS = {
    high: {
      icon: '🛑',
      title: 'Warning: this looks like a SCAM',
      advice: [
        'Do not click any links in this email.',
        'Do not reply, and never send money, gift cards, or passwords.',
        'Call a family member or someone you trust before doing anything.',
      ],
    },
    medium: {
      icon: '⚠️',
      title: 'Be careful with this email',
      advice: [
        'Don\'t click links unless you were expecting this email.',
        'If it says it\'s from a company, call them using the number on your card or bill, not a number in this email.',
      ],
    },
    low: {
      icon: '✅',
      title: 'No warning signs found',
      advice: ['This email looks normal. Still, never share passwords or bank details by email.'],
    },
  };

  let shadow, panel, reopenButton;
  let lastSignature = '';
  let current = null; // { email, result } for the email on screen

  // Small helper to build page elements safely.
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

  function isVisible(node) {
    return node && node.offsetParent !== null;
  }

  // Reads the email that's open on screen. Returns null if no email is open.
  function readOpenEmail() {
    const bodies = [...document.querySelectorAll(SELECTORS.body)].filter(isVisible);
    if (!bodies.length) return null;
    const body = bodies[bodies.length - 1]; // newest opened message in a thread

    const subjectEl = [...document.querySelectorAll(SELECTORS.subject)].find(isVisible);
    const senders = [...document.querySelectorAll(SELECTORS.sender)].filter(isVisible);
    const senderEl = senders[senders.length - 1];

    const links = [...body.querySelectorAll('a[href]')]
      .map(a => ({ text: a.textContent.trim(), href: a.href }))
      .filter(link => /^https?:/i.test(link.href));

    return {
      subject: subjectEl ? subjectEl.textContent.trim() : '',
      senderName: senderEl ? (senderEl.getAttribute('name') || senderEl.textContent.trim()) : '',
      senderEmail: senderEl ? (senderEl.getAttribute('email') || '') : '',
      bodyText: body.innerText.trim(),
      links,
    };
  }

  // Builds the panel once and adds it to the page.
  function ensurePanel() {
    if (shadow) return;
    const host = el('div', { id: 'email-anti-scam-host' });
    shadow = host.attachShadow({ mode: 'open' });
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(PANEL_CSS);
    shadow.adoptedStyleSheets = [sheet];

    panel = el('div', { class: 'panel', role: 'region', 'aria-label': 'Email safety check' });
    reopenButton = el('button', { class: 'reopen', hidden: '', onclick: showPanel });
    shadow.append(panel, reopenButton);
    document.body.append(host);
  }

  function showPanel() {
    panel.hidden = false;
    reopenButton.hidden = true;
  }

  function hidePanel() {
    if (!panel) return;
    panel.hidden = true;
    if (current) {
      const v = VERDICTS[current.result.level];
      reopenButton.textContent = `${v.icon} Safety check`;
      reopenButton.className = `reopen ${current.result.level}`;
      reopenButton.hidden = false;
    }
  }

  function removeAll() {
    if (!panel) return;
    panel.hidden = true;
    reopenButton.hidden = true;
    current = null;
    GranblockSpeech.stop();
  }

  // The verdict, why, and what to do: what "Read to me" says.
  function spokenParts() {
    if (!current) return [];
    const { email, result } = current;
    const v = VERDICTS[result.level];
    return [
      v.title + '.',
      email.senderName ? `This email is from ${email.senderName}.` : '',
      email.subject ? `It is about: ${email.subject}.` : '',
      ...result.reasons,
      'Here is what to do.',
      ...v.advice,
    ];
  }
  const speechKey = () => `gmail|${lastSignature}`;

  function render(email, result) {
    ensurePanel();
    current = { email, result };
    const v = VERDICTS[result.level];

    const header = el('div', { class: 'header' }, [
      el('span', { class: 'title', text: 'Email Safety Check' }),
      GranblockSpeech.makeButton(document, { getParts: spokenParts, key: speechKey(), rate: () => GranblockSettings.get().speechRate }),
      el('button', { text: 'Hide', 'aria-label': 'Hide safety panel', onclick: hidePanel }),
    ]);

    const verdict = el('div', { class: `verdict ${result.level}`, role: 'status' }, [
      el('span', { class: 'icon', 'aria-hidden': 'true', text: v.icon }),
      el('span', { text: v.title }),
    ]);

    const who = el('div', { class: 'section' }, [
      el('h3', { text: 'Who sent this' }),
      el('p', { text: email.senderName || 'Unknown sender' }),
      email.senderEmail ? el('p', { class: 'muted', text: email.senderEmail }) : null,
    ]);

    // TODO (Step 5): replace the preview with an AI-written plain-language summary.
    const preview = email.bodyText.replace(/\s+/g, ' ').slice(0, 240);
    const about = el('div', { class: 'section' }, [
      el('h3', { text: 'What it\'s about' }),
      el('p', { text: email.subject || '(No subject)' }),
      preview ? el('p', { class: 'preview', text: preview + (email.bodyText.length > 240 ? '…' : '') }) : null,
    ]);

    const why = result.reasons.length
      ? el('div', { class: 'section' }, [
          el('h3', { text: 'Why we\'re warning you' }),
          el('ul', {}, result.reasons.map(r => el('li', { text: r }))),
        ])
      : null;

    const linkItems = result.links.filter(l => l.host).slice(0, 10).map(l =>
      el('li', {}, [
        el('div', { text: l.text || '(picture or button)' }),
        el('div', { class: 'muted', text: `Really goes to: ${l.host}` }),
        l.flags.length ? el('div', { class: 'flag', text: `⚠ ${l.flags.join(', ')}` }) : null,
      ])
    );
    const links = linkItems.length
      ? el('div', { class: 'section' }, [el('h3', { text: 'Links in this email' }), el('ul', {}, linkItems)])
      : null;

    const todo = el('div', { class: 'section' }, [
      el('h3', { text: 'What you should do' }),
      el('ul', {}, v.advice.map(a => el('li', { text: a }))),
    ]);

    panel.replaceChildren(...[header, verdict, who, about, why, links, todo].filter(Boolean));
    panel.style.zoom = GranblockSettings.zoom(); // the person's text size
    panel.scrollTop = 0;
    showPanel(); // always show the panel again for each new email
    // Read a warning aloud once per email, if the person asked for that. render()
    // runs once per new email, and speak() won't restart what's already being read.
    if (GranblockSettings.get().autoRead && result.level !== 'low') {
      GranblockSpeech.speak(spokenParts(), { rate: GranblockSettings.get().speechRate, key: speechKey() });
    }
  }

  function scan() {
    const email = readOpenEmail();
    if (!email) {
      lastSignature = '';
      removeAll();
      return;
    }
    const signature = `${email.senderEmail}|${email.subject}|${email.bodyText.length}`;
    if (signature === lastSignature) return;
    lastSignature = signature;
    render(email, analyzeEmail(email));
  }

  // A link inside the open email that looks like a scam gets stopped by guard.js,
  // even if the link itself looks fine.
  GUARD_CONTEXT_PROVIDERS.push(anchor => {
    if (!current || current.result.level !== 'high' || !anchor.closest(SELECTORS.body)) return null;
    return { surroundingLevel: 'high' };
  });

  // Gmail changes the page without reloading, so watch for changes
  // and re-check at most a few times per second.
  let pending = null;
  const observer = new MutationObserver(() => {
    if (pending) return;
    pending = setTimeout(() => { pending = null; scan(); }, 400);
  });
  observer.observe(document.body, { childList: true, subtree: true });
  scan();
})();
