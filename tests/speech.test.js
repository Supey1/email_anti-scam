// Tests for reading warnings aloud (extension/speech.js).
// Run with:  node tests/speech.test.js
// Uses a pretend speech engine; tests/browser/acceptance.test.js checks the buttons in Chrome.

const assert = require('assert');
const path = require('path');
const SPEECH = path.join(__dirname, '..', 'extension', 'speech.js');

// A pretend window.speechSynthesis. Like Chrome, cancel() reports "error" on
// the sentence it interrupted, a moment later.
function fakeWindow() {
  const synth = {
    spoken: [],
    current: null,
    get speaking() { return !!this.current; },
    pending: false,
    speak(u) { this.spoken.push(u); this.current = u; },
    cancel() {
      const u = this.current;
      this.current = null;
      if (u) setTimeout(() => u.onerror && u.onerror({ error: 'interrupted' }), 0);
    },
    finish() { const u = this.current; this.current = null; if (u && u.onend) u.onend(); },
  };
  function SpeechSynthesisUtterance(text) { this.text = text; }
  return { speechSynthesis: synth, SpeechSynthesisUtterance };
}

// A fresh copy of speech.js for each test.
function load(window) {
  delete require.cache[require.resolve(SPEECH)];
  if (window) global.window = window; else delete global.window;
  return require(SPEECH);
}

// Just enough of a page for makeButton().
const fakeDocument = () => ({
  createElement: () => {
    const handlers = {};
    return {
      attributes: {}, textContent: '', disabled: false, isConnected: true,
      setAttribute(k, v) { this.attributes[k] = v; },
      addEventListener(type, fn) { handlers[type] = fn; },
      click() { handlers.click(); },
    };
  },
});
const tick = () => new Promise(r => setTimeout(r, 5));

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

test('reads the sentences together, at the chosen speed', () => {
  const w = fakeWindow();
  const speech = load(w);
  assert.strictEqual(speech.speak(['Stop.', '', 'Do not click.'], { rate: 0.7, key: 'a' }), true);
  assert.deepStrictEqual([w.speechSynthesis.spoken[0].text, w.speechSynthesis.spoken[0].rate], ['Stop. Do not click.', 0.7]);
  assert.ok(speech.isSpeaking('a'));
});

test('the same warning again (a panel redrawing) does not restart the speech', () => {
  const w = fakeWindow();
  const speech = load(w);
  speech.speak(['Stop.'], { key: 'warning-1' });
  speech.speak(['Stop.'], { key: 'warning-1' });
  speech.speak(['Stop.'], { key: 'warning-1' });
  assert.strictEqual(w.speechSynthesis.spoken.length, 1);
});

test('a different warning replaces the one being read', async () => {
  const w = fakeWindow();
  const speech = load(w);
  speech.speak(['First.'], { key: 'one' });
  speech.speak(['Second.'], { key: 'two' });
  assert.strictEqual(w.speechSynthesis.spoken.length, 2);
  await tick(); // the first one's late "interrupted" report arrives now
  assert.ok(speech.isSpeaking('two'), 'the old sentence\'s "interrupted" report stopped the new one');
});

test('stop() stops it, and the next press reads again', () => {
  const w = fakeWindow();
  const speech = load(w);
  speech.speak(['Stop.'], { key: 'k' });
  speech.stop();
  assert.strictEqual(speech.isSpeaking(), false);
  assert.strictEqual(w.speechSynthesis.speaking, false);
  speech.speak(['Stop.'], { key: 'k' });
  assert.strictEqual(w.speechSynthesis.spoken.length, 2);
});

test('when reading finishes, buttons are told', () => {
  const w = fakeWindow();
  const speech = load(w);
  const seen = [];
  speech.onChange(k => seen.push(k));
  speech.speak(['Stop.'], { key: 'k' });
  w.speechSynthesis.finish();
  assert.deepStrictEqual(seen, ['k', null]);
  assert.strictEqual(speech.isSpeaking(), false);
});

test('the button says "Read to me", then "Stop reading", then "Read to me" again', () => {
  const w = fakeWindow();
  const speech = load(w);
  const button = speech.makeButton(fakeDocument(), { getParts: () => ['Stop.'], key: 'b', rate: () => 1.1 });
  assert.match(button.textContent, /Read to me/);
  button.click();
  assert.match(button.textContent, /Stop reading/);
  assert.strictEqual(button.attributes['aria-pressed'], 'true');
  assert.strictEqual(w.speechSynthesis.spoken[0].rate, 1.1);
  button.click();
  assert.match(button.textContent, /Read to me/);
  assert.strictEqual(w.speechSynthesis.speaking, false);
});

test('speech that fails (no voices): the button says so, instead of going quiet', async () => {
  const w = fakeWindow();
  w.speechSynthesis.speak = function (u) { this.spoken.push(u); setTimeout(() => u.onerror({ error: 'synthesis-failed' }), 0); };
  const speech = load(w);
  const button = speech.makeButton(fakeDocument(), { getParts: () => ['Stop.'], key: 'b' });
  button.click();
  await tick();
  assert.ok(speech.failed('b'));
  assert.match(button.textContent, /Couldn't read aloud\. The warning is written on screen/);
  assert.strictEqual(button.disabled, false, 'the person should be able to try again');
});

test('being interrupted by another warning is not a failure', async () => {
  const w = fakeWindow();
  const speech = load(w);
  speech.speak(['First.'], { key: 'one' });
  speech.speak(['Second.'], { key: 'two' });
  await tick();
  assert.strictEqual(speech.failed('one'), false);
});

test('no speech on this computer: nothing breaks, and the button says so instead of failing silently', () => {
  const speech = load(null);
  assert.strictEqual(speech.available(), false);
  assert.strictEqual(speech.speak(['Stop.']), false);
  speech.stop();
  const button = speech.makeButton(fakeDocument(), { getParts: () => ['Stop.'], key: 'b' });
  assert.strictEqual(button.disabled, true);
  assert.match(button.textContent, /isn't available/);
});

(async () => {
  let passed = 0;
  for (const t of tests) {
    try {
      await t.fn();
      passed++;
      console.log(`PASS  ${t.name}`);
    } catch (err) {
      console.log(`FAIL  ${t.name}: ${err.message.split('\n')[0]}`);
      process.exitCode = 1;
    }
  }
  delete global.window;
  console.log(`\n${passed}/${tests.length} speech tests passed`);
})();
