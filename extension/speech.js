// speech.js: reads warnings aloud, the same way everywhere (the warning, the
// Gmail panel, and the extension's warning page).
//
//   speak(parts, { rate, key })  read these sentences. If the same thing (key)
//                                is already being read, carry on instead of
//                                starting again: a panel that redraws itself
//                                must not restart the speech every time.
//   stop()                       stop reading
//   isSpeaking(key?)             is something (or this) being read right now?
//   failed(key)                  did reading this fail (no voices, no sound)? The
//                                browser can have the speech feature but no voices.
//   available()                  can this browser read aloud at all?
//   onChange(fn)                 called when reading starts or stops (to update buttons)
//
// Uses the browser's built-in speech (speechSynthesis), which needs no extra
// permission. The warning's text is always on screen too: reading aloud is an
// extra, never the only way to get the message.

const GranblockSpeech = (() => {
  'use strict';
  let currentKey = null;
  let failedKey = null;
  // Not failures: we stopped it, or another warning replaced it.
  const NORMAL_ENDINGS = ['interrupted', 'canceled'];
  const listeners = new Set();
  const notify = () => listeners.forEach(fn => { try { fn(currentKey); } catch (e) { /* a broken listener mustn't stop speech */ } });

  function synth() {
    return typeof window !== 'undefined' && window.speechSynthesis && typeof window.SpeechSynthesisUtterance === 'function'
      ? window.speechSynthesis : null;
  }

  function available() {
    return !!synth();
  }

  function speak(parts, { rate = 0.9, key } = {}) {
    const s = synth();
    if (!s) return false;
    const text = [].concat(parts).filter(Boolean).join(' ');
    if (!text) return false;
    const k = key || text;
    if (k === currentKey && (s.speaking || s.pending)) return true; // already reading this
    s.cancel();
    const utterance = new window.SpeechSynthesisUtterance(text);
    utterance.rate = rate;
    // Only for THIS reading: a late report from one we replaced must not stop the new one.
    utterance.onend = () => { if (currentKey === k) { currentKey = null; notify(); } };
    utterance.onerror = event => {
      if (currentKey !== k) return;
      currentKey = null;
      if (!NORMAL_ENDINGS.includes(event && event.error)) failedKey = k;
      notify();
    };
    currentKey = k;
    failedKey = null;
    s.speak(utterance);
    notify();
    return true;
  }

  function stop() {
    const s = synth();
    const wasSpeaking = currentKey !== null;
    currentKey = null;
    if (s) s.cancel();
    if (wasSpeaking) notify();
  }

  function isSpeaking(key) {
    return currentKey !== null && (key === undefined || key === currentKey);
  }

  function failed(key) {
    return failedKey !== null && failedKey === key;
  }

  function onChange(fn) {
    listeners.add(fn);
    return () => listeners.delete(fn);
  }

  // A "Read to me" / "Stop reading" button for any screen.
  //   getParts()  the sentences to read (asked each time, so they're current)
  //   key         what this button reads (so two buttons don't fight)
  //   rate()      the speed setting
  function makeButton(doc, { getParts, key, rate = () => 0.9, className = '' }) {
    const button = doc.createElement('button');
    button.type = 'button';
    if (className) button.className = className;
    let wasShown = false;
    const draw = () => {
      // Once the button has been on screen and is gone, stop listening.
      if (button.isConnected) wasShown = true;
      else if (wasShown) { unsubscribe(); return; }
      if (!available()) {
        button.textContent = '🔇 Reading aloud isn\'t available here';
        button.disabled = true;
        return;
      }
      const reading = isSpeaking(key);
      button.textContent = reading ? '⏹ Stop reading'
        : failed(key) ? '🔇 Couldn\'t read aloud. The warning is written on screen. Try again'
          : '🔊 Read to me';
      button.setAttribute('aria-pressed', String(reading));
    };
    button.addEventListener('click', () => {
      if (isSpeaking(key)) stop();
      else speak(getParts(), { rate: rate(), key });
    });
    const unsubscribe = onChange(draw);
    draw();
    return button;
  }

  return { available, speak, stop, isSpeaking, failed, onChange, makeButton };
})();

if (typeof module !== 'undefined') {
  module.exports = GranblockSpeech;
}
