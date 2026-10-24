// Tests for extension/speech.js (reading aloud) and extension/background/speech-relay.js.
// Run with:  node tests/speech.test.js
// Chrome's speech is replaced by fakes, so this checks OUR logic: which path is used, what speed is asked for,
// what happens at the end or on an error, and that nothing keeps talking when it should stop.

const assert = require('assert');
const path = require('path');
const SRC = path.join(__dirname, '..', 'extension');

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

// Loads a fresh copy of speech.js with the given pretend browser around it.
function loadSpeech(env) {
  for (const key of ['chrome', 'window']) delete globalThis[key];
  Object.assign(globalThis, env);
  delete require.cache[require.resolve(path.join(SRC, 'speech.js'))];
  return require(path.join(SRC, 'speech.js'));
}

// A pretend chrome.tts. spoken: what it was asked to say; end(i, type) lets a test finish or break a reading.
function fakeTts() {
  const spoken = [];
  return {
    spoken, stops: 0,
    speak(text, options, callback) { spoken.push({ text, ...options }); if (callback) callback(); },
    stop() { this.stops++; },
    emit(i, type) { spoken[i].onEvent({ type }); },
  };
}

// A pretend connection between a page and the service worker, with the real relay on the other end.
function connectedWorld(tts) {
  const relay = require(path.join(SRC, 'background', 'speech-relay.js'));
  const listeners = { page: [], worker: [], pageClose: [], workerClose: [] };
  const pagePort = { name: 'granblock-speech', postMessage: m => listeners.worker.forEach(fn => fn(JSON.parse(JSON.stringify(m)))), onMessage: { addListener: fn => listeners.page.push(fn) }, onDisconnect: { addListener: fn => listeners.pageClose.push(fn) } };
  const workerPort = { name: 'granblock-speech', postMessage: m => listeners.page.forEach(fn => fn(JSON.parse(JSON.stringify(m)))), onMessage: { addListener: fn => listeners.worker.push(fn) }, onDisconnect: { addListener: fn => listeners.workerClose.push(fn) } };
  relay.handlePort(workerPort, tts, () => null);
  return { pagePort, closePage: () => listeners.workerClose.forEach(fn => fn()) };
}

test('extension pages: speak with chrome.tts at the chosen speed, no click needed', () => {
  const tts = fakeTts();
  const Speech = loadSpeech({ chrome: { tts, runtime: { lastError: null } } });
  let ended = null;
  Speech.speak('Stop and check this first.', { rate: 1.5, onEnd: ok => { ended = ok; } });
  assert.strictEqual(tts.spoken.length, 1);
  assert.strictEqual(tts.spoken[0].rate, 1.5);
  assert.strictEqual(tts.spoken[0].enqueue, false);
  assert.strictEqual(Speech.isSpeaking(), true);
  tts.emit(0, 'end');
  assert.strictEqual(ended, true);
  assert.strictEqual(Speech.isSpeaking(), false);
});

test('speeds are far enough apart to hear', () => {
  delete globalThis.chrome;
  delete require.cache[require.resolve(path.join(SRC, 'settings.js'))];
  const Settings = require(path.join(SRC, 'settings.js'));
  const { slow, normal, fast } = Settings.SPEECH_RATE;
  assert.ok(fast / normal >= 1.5, `fast ${fast} vs normal ${normal}`);
  assert.ok(normal / slow >= 1.5, `normal ${normal} vs slow ${slow}`);
  assert.ok(slow >= 0.5 && fast <= 2, "inside the range the relay accepts");
});

test('stop() stops chrome.tts and ends the reading', () => {
  const tts = fakeTts();
  const Speech = loadSpeech({ chrome: { tts, runtime: { lastError: null } } });
  let ended = null;
  Speech.speak('hello', { rate: 1, onEnd: ok => { ended = ok; } });
  Speech.stop();
  assert.ok(tts.stops >= 1);
  assert.strictEqual(ended, true, 'stopping is a normal ending, not a failure');
  assert.strictEqual(Speech.isSpeaking(), false);
});

test('a new reading replaces the one in progress', () => {
  const tts = fakeTts();
  const Speech = loadSpeech({ chrome: { tts, runtime: { lastError: null } } });
  const ends = [];
  Speech.speak('one', { rate: 1, onEnd: ok => ends.push(['one', ok]) });
  Speech.speak('two', { rate: 1, onEnd: ok => ends.push(['two', ok]) });
  assert.deepStrictEqual(ends, [['one', true]]);
  tts.emit(0, 'interrupted'); // the first one's late report must not end the second
  assert.strictEqual(Speech.isSpeaking(), true);
  tts.emit(1, 'end');
  assert.deepStrictEqual(ends, [['one', true], ['two', true]]);
});

test('inside web pages: asks the service worker, which speaks with chrome.tts, and the end comes back', () => {
  const tts = fakeTts();
  const world = connectedWorld(tts);
  const Speech = loadSpeech({ chrome: { runtime: { id: 'x', connect: () => world.pagePort } } });
  let ended = null;
  Speech.speak('Be careful: check this first.', { rate: 0.55, onEnd: ok => { ended = ok; } });
  assert.strictEqual(tts.spoken.length, 1);
  assert.strictEqual(tts.spoken[0].text, 'Be careful: check this first.');
  assert.strictEqual(tts.spoken[0].rate, 0.55);
  assert.strictEqual(ended, null);
  tts.emit(0, 'end');
  assert.strictEqual(ended, true);
});

test('the relay checks what it is asked: text length, speed range, shape, the right connection name', () => {
  const relay = require(path.join(SRC, 'background', 'speech-relay.js'));
  assert.strictEqual(relay.clampRate(9), 0.9);
  assert.strictEqual(relay.clampRate('fast'), 0.9);
  assert.strictEqual(relay.clampRate(1.5), 1.5);
  const tts = fakeTts();
  assert.strictEqual(relay.handlePort({ name: 'something-else' }, tts), false);
  const world = connectedWorld(tts);
  world.pagePort.postMessage({ type: 'speak', id: 1, text: 'x'.repeat(10000), rate: 99 });
  world.pagePort.postMessage({ type: 'speak', id: 2, text: '   ' });
  world.pagePort.postMessage({ type: 'speak', id: 3, text: 42 });
  world.pagePort.postMessage('nonsense');
  assert.strictEqual(tts.spoken.length, 1, 'only the first, valid request is spoken');
  assert.strictEqual(tts.spoken[0].text.length, relay.MAX_TEXT);
  assert.strictEqual(tts.spoken[0].rate, 0.9);
});

test('a page that closes or reloads stops the voice', () => {
  const tts = fakeTts();
  const world = connectedWorld(tts);
  world.pagePort.postMessage({ type: 'speak', id: 1, text: 'hello', rate: 1 });
  const before = tts.stops;
  world.closePage();
  assert.strictEqual(tts.stops, before + 1);
});

test('if Chrome has no voice (an error), it falls back to the browser\'s speech, and reports failure only if that fails too', () => {
  const tts = fakeTts();
  const synthSpoken = [];
  const synth = { cancel() {}, speak(u) { synthSpoken.push(u); } };
  class Utterance { constructor(text) { this.text = text; } }
  const Speech = loadSpeech({ chrome: { tts, runtime: { lastError: null } }, window: { speechSynthesis: synth, SpeechSynthesisUtterance: Utterance } });
  let ended = null;
  Speech.speak('hello', { rate: 1.2, onEnd: ok => { ended = ok; } });
  tts.emit(0, 'error');
  assert.strictEqual(synthSpoken.length, 1, 'the browser voice was tried');
  assert.strictEqual(synthSpoken[0].rate, 1.2);
  synthSpoken[0].onerror({ error: 'not-allowed' });
  assert.strictEqual(ended, false, 'both failed: the card says it could not read aloud');

  const Speech2 = loadSpeech({ chrome: { tts, runtime: { lastError: null } } }); // no browser speech either
  let ended2 = null;
  Speech2.speak('hello', { rate: 1, onEnd: ok => { ended2 = ok; } });
  tts.emit(tts.spoken.length - 1, 'error');
  assert.strictEqual(ended2, false);
});

test('nothing to say, or nothing to speak with: no crash', () => {
  const Speech = loadSpeech({});
  let ended = 'unset';
  Speech.speak('hello', { rate: 1, onEnd: ok => { ended = ok; } });
  assert.strictEqual(ended, false, 'no speech at all: reports failure');
  let empty = 'unset';
  Speech.speak('   ', { rate: 1, onEnd: ok => { empty = ok; } });
  assert.strictEqual(empty, false);
  Speech.stop();
});

(async () => {
  let passed = 0;
  for (const t of tests) {
    try { t.fn(); passed++; console.log(`PASS  ${t.name}`); }
    catch (err) { console.log(`FAIL  ${t.name}: ${err.message.split('\n')[0]}`); process.exitCode = 1; }
  }
  console.log(`\n${passed}/${tests.length} speech tests passed`);
})();
