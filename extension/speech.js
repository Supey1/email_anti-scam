// speech.js: reads warnings aloud, the same way everywhere (the in-page card, the Gmail panel, the warning page,
// the popup, and the settings page's "Test the voice").
//
// Why not just speechSynthesis? Two real problems, both found in testing:
//   1. Chrome will not speak on a web page until the person has clicked or typed on it, so "read warnings out loud on
//      their own" never started.
//   2. Chrome's online voices ignore the speed setting, so slow, normal, and fast sounded the same.
// Chrome's extension speech (chrome.tts) has neither problem: it uses the computer's own voices and needs no click.
// Extension pages call it directly. Pages we run inside (the card and the Gmail panel) ask the service worker to speak
// over a small connection (background/speech-relay.js). If none of that is possible, it falls back to speechSynthesis.
//
//   speak(text, { rate, onEnd })   read this. onEnd(ok) runs when reading ends (ok is false if it could not read at all)
//   stop()                         stop reading
//   isSpeaking()                   is something being read right now?

const GranblockSpeech = (() => {
  'use strict';

  const PORT_NAME = 'granblock-speech';
  const hasChrome = typeof chrome !== 'undefined';
  const direct = hasChrome && !!chrome.tts && typeof chrome.tts.speak === 'function'; // extension pages
  const viaWorker = hasChrome && !!chrome.runtime && !!chrome.runtime.id && typeof chrome.runtime.connect === 'function'; // inside web pages
  const synth = () => (typeof window !== 'undefined' && window.speechSynthesis && typeof window.SpeechSynthesisUtterance === 'function' ? window.speechSynthesis : null);

  let current = null; // the reading in progress: { id, text, rate, onEnd, finished, triedFallback }
  let port = null;
  let nextId = 1;

  function finish(job, ok) {
    if (job.finished) return;
    job.finished = true;
    if (current === job) current = null;
    if (job.onEnd) { try { job.onEnd(ok); } catch (e) { /* a broken callback must not stop anything */ } }
  }

  // The browser's own speech: the last resort.
  function speakWithBrowser(job) {
    const s = synth();
    if (!s || job.triedFallback) { finish(job, false); return; }
    job.triedFallback = true;
    try {
      s.cancel();
      const utterance = new window.SpeechSynthesisUtterance(job.text);
      utterance.rate = job.rate;
      utterance.onend = () => finish(job, true);
      utterance.onerror = event => finish(job, !!event && (event.error === 'interrupted' || event.error === 'canceled'));
      s.speak(utterance);
    } catch (e) {
      finish(job, false);
    }
  }

  // An event from Chrome's speech: end and interruptions are normal endings; an error means try the browser's speech.
  function onSpeechEvent(job, event) {
    if (job.finished) return;
    if (event === 'end' || event === 'interrupted' || event === 'cancelled') finish(job, true);
    else if (event === 'error') speakWithBrowser(job);
  }

  function getPort() {
    if (port) return port;
    port = chrome.runtime.connect({ name: PORT_NAME });
    port.onMessage.addListener(message => {
      if (message && message.type === 'event' && current && current.id === message.id) onSpeechEvent(current, message.event);
    });
    port.onDisconnect.addListener(() => {
      port = null;
      if (current && current.viaWorker) speakWithBrowser(current);
    });
    return port;
  }

  function stop() {
    const job = current;
    if (direct) { try { chrome.tts.stop(); } catch (e) { /* nothing to stop */ } }
    if (port) { try { port.postMessage({ type: 'stop' }); } catch (e) { port = null; } }
    const s = synth();
    if (s) { try { s.cancel(); } catch (e) { /* nothing to cancel */ } }
    if (job) finish(job, true);
  }

  function speak(text, { rate = 0.9, onEnd } = {}) {
    stop();
    const clean = String(text || '').replace(/\s+/g, ' ').trim();
    if (!clean) { if (onEnd) onEnd(false); return; }
    const job = { id: nextId++, text: clean, rate, onEnd, finished: false, triedFallback: false, viaWorker: false };
    current = job;
    if (direct) {
      chrome.tts.speak(clean, { rate, enqueue: false, onEvent: e => onSpeechEvent(job, e.type) }, () => {
        if (chrome.runtime.lastError) onSpeechEvent(job, 'error');
      });
    } else if (viaWorker) {
      try {
        job.viaWorker = true;
        getPort().postMessage({ type: 'speak', id: job.id, text: clean, rate });
      } catch (e) {
        job.viaWorker = false;
        port = null;
        speakWithBrowser(job);
      }
    } else {
      speakWithBrowser(job);
    }
  }

  return { speak, stop, isSpeaking: () => current !== null, PORT_NAME };
})();

// Lets tests load this file with Node. Chrome ignores this.
if (typeof module !== 'undefined') {
  module.exports = GranblockSpeech;
}
