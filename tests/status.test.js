// Tests for the popup's plain answer to "is this page being checked?" (extension/ui/status.js).
// Run with:  node tests/status.test.js
const assert = require('assert');
const path = require('path');
const PopupStatus = require(path.join(__dirname, '..', 'extension', 'ui', 'status.js'));

const say = (over) => PopupStatus.describePage({ protectionEnabled: true, access: 'all', url: 'https://news.example/a', reply: { checking: true }, ...over });

assert.strictEqual(say({}).state, 'yes');
assert.strictEqual(say({ reply: undefined }).state, 'unknown', 'if the page never answered, we do not claim it is checked');
assert.match(say({ reply: undefined }).detail, /Reload/);
assert.strictEqual(say({ protectionEnabled: false }).state, 'no');
assert.match(say({ protectionEnabled: false }).detail, /turned off/);
assert.match(say({ url: undefined, access: 'none' }).detail, /not allowed website access/, 'with no access the address is hidden, so say why');
for (const url of ['chrome://extensions', undefined, 'about:blank', 'file:///x.html']) assert.match(say({ url }).text, /cannot be checked/, String(url));
assert.strictEqual(say({ access: 'none' }).state, 'no');
assert.strictEqual(say({ access: 'none' }).openSettings, true, 'the way to fix it is one button away');
assert.match(say({ access: 'gmail' }).detail, /only Gmail/);
assert.strictEqual(say({ url: 'https://mail.google.com/mail/u/0/' }).state, 'yes');
assert.match(say({ url: 'https://mail.google.com/mail/u/0/' }).text, /Gmail/);
assert.strictEqual(say({ url: 'https://mail.google.com/mail/u/0/', access: 'gmail' }).state, 'yes', 'Gmail-only access covers Gmail');
assert.strictEqual(say({ url: 'https://mail.google.com/mail/u/0/', access: 'none' }).state, 'no');
for (const url of ['https://news.example/', 'https://mail.google.com/']) assert.ok(!/score|rule|weight/i.test(JSON.stringify(say({ url }))));
console.log('PASS  popup status words\n\nAll tests passed');
