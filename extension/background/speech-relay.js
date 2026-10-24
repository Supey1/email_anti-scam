// speech-relay.js: lets the warning cards inside web pages speak with Chrome's extension speech (chrome.tts).
// Web pages can't call chrome.tts, so speech.js opens a connection to the service worker and asks it to speak.
// Chrome's speech needs no click first, and honours the speed setting, unlike the page's own speechSynthesis.
//
// A message on the connection is { type: 'speak', id, text, rate } or { type: 'stop' }. Answers are
// { type: 'event', id, event: 'end' | 'interrupted' | 'cancelled' | 'error' | ... }.
// Only our own content scripts can connect (the extension does not allow other websites to), but the text and the
// speed are still checked. No chrome.* calls here: the service worker passes chrome.tts in, so tests can run it.

(function () {
  'use strict';
  const bg = globalThis.GranblockBackground = globalThis.GranblockBackground || {};

  const PORT_NAME = 'granblock-speech';
  const MAX_TEXT = 3000;

  function clampRate(rate) {
    return typeof rate === 'number' && rate >= 0.5 && rate <= 2 ? rate : 0.9;
  }

  // port: a chrome.runtime Port.  tts: chrome.tts ({ speak, stop }).  lastError: () => the last Chrome error, if any.
  function handlePort(port, tts, lastError = () => null) {
    if (!port || port.name !== PORT_NAME) return false;
    const post = message => { try { port.postMessage(message); } catch (e) { /* the page went away */ } };

    port.onMessage.addListener(message => {
      if (!message || typeof message !== 'object') return;
      if (message.type === 'stop') { tts.stop(); return; }
      if (message.type !== 'speak' || typeof message.text !== 'string' || !message.text.trim()) return;
      const id = message.id;
      tts.speak(message.text.slice(0, MAX_TEXT), {
        rate: clampRate(message.rate),
        enqueue: false,
        onEvent: event => post({ type: 'event', id, event: event && event.type }),
      }, () => { if (lastError()) post({ type: 'event', id, event: 'error' }); });
    });
    // A page that is closed or reloaded must not leave a voice talking.
    port.onDisconnect.addListener(() => tts.stop());
    return true;
  }

  bg.speechRelay = { PORT_NAME, MAX_TEXT, clampRate, handlePort };
  if (typeof module !== 'undefined') module.exports = bg.speechRelay;
})();
