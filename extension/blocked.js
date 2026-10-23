// blocked.js: the page people see when the service worker stops a known-dangerous website.
// Same big-text look as the warning card, but no way past it.

(() => {
  'use strict';

  const style = document.createElement('style');
  style.textContent = PANEL_CSS + WARNING_CSS + 'body { margin: 0; background: #f4f4f4; } .card { margin: 40px auto; }';
  document.head.append(style);

  let host = 'this website';
  try {
    host = new URL(location.search.slice('?url='.length)).hostname;
  } catch (e) { /* keep the generic wording */ }

  const reason = `${host} has been reported as a dangerous website. It may try to steal your passwords or money.`;
  const advice = 'Close this page. If a message sent you here, do not trust that message.';

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

  function leave() {
    if (history.length > 1) history.back(); else location.replace('about:blank');
  }

  function read() {
    window.speechSynthesis.cancel();
    const speech = new SpeechSynthesisUtterance(`Stop. This is dangerous. ${reason} ${advice}`);
    speech.rate = 0.9;
    window.speechSynthesis.speak(speech);
  }

  document.getElementById('root').append(
    el('div', { class: 'card', role: 'alertdialog', 'aria-label': 'Dangerous website blocked' }, [
      el('div', { class: 'verdict high', role: 'status' }, [
        el('span', { class: 'icon', 'aria-hidden': 'true', text: '🛑' }),
        el('span', { text: 'Stop. This website is dangerous.' }),
      ]),
      el('div', { class: 'section' }, [
        el('h3', { text: 'Why we stopped you' }),
        el('p', { text: reason }),
        el('h3', { text: 'What you should do' }),
        el('p', { text: advice }),
      ]),
      el('div', { class: 'actions' }, [
        el('button', { class: 'primary', text: 'Go back to safety', onclick: leave }),
        el('button', { text: '🔊 Read to me', onclick: read }),
      ]),
    ])
  );
})();
