// Tests for extension/settings.js and extension/ui/status.js.
// Run with:  node tests/settings.test.js

const assert = require('assert');
const path = require('path');
const Settings = require(path.join(__dirname, '..', 'extension', 'settings.js'));
const PopupStatus = require(path.join(__dirname, '..', 'extension', 'ui', 'status.js'));

const D = Settings.DEFAULTS;
const s = (over = {}) => Settings.normalize({ ...D, ...over });

// ---- normalizing ----
assert.deepStrictEqual(Settings.normalize(undefined), { ...D, offSites: [], onSites: [] }, 'missing settings fall back to the defaults');
assert.deepStrictEqual(Settings.normalize('junk'), Settings.normalize(null));
assert.strictEqual(Settings.normalize({ enabled: 'no' }).enabled, true, 'a damaged value cannot switch protection off');
assert.strictEqual(Settings.normalize({ textSize: 'huge' }).textSize, D.textSize);
assert.strictEqual(Settings.normalize({ readAloud: 'auto' }).readAloud, 'auto');
assert.deepStrictEqual(Settings.normalize({ offSites: ['HTTPS://www.Example.com/a?b', 'example.com', '<script>', '', 5, 'localhost'] }).offSites, ['example.com', 'localhost']);
assert.strictEqual(Settings.normalize({ offSites: Array.from({ length: 500 }, (_, i) => `site${i}.example`) }).offSites.length, 200);

// ---- website names ----
for (const [input, host] of [['example.com', 'example.com'], ['https://www.Example.com/path', 'example.com'], ['  mail.example.org  ', 'mail.example.org'], ['not a site', ''], ['', ''], ['http://', ''], ['a', ''], ['bad_host.com', '']]) {
  assert.strictEqual(Settings.normalizeHost(input), host, `normalizeHost(${JSON.stringify(input)})`);
}

// ---- which websites are checked ----
assert.strictEqual(Settings.shouldCheckSite(s(), 'news.example'), true, 'default: every website');
assert.strictEqual(Settings.shouldCheckSite(s({ enabled: false }), 'news.example'), false, 'off means off everywhere');
assert.strictEqual(Settings.shouldCheckSite(s({ offSites: ['news.example'] }), 'news.example'), false);
assert.strictEqual(Settings.shouldCheckSite(s({ offSites: ['news.example'] }), 'www.news.example'), false, 'www and subdomains follow the site');
assert.strictEqual(Settings.shouldCheckSite(s({ offSites: ['news.example'] }), 'other.example'), true);
assert.strictEqual(Settings.shouldCheckSite(s({ offSites: ['news.example'] }), 'notnews.example'), true, 'a similar name is a different site');
assert.strictEqual(Settings.shouldCheckSite(s({ siteMode: 'chosen' }), 'news.example'), false, 'chosen mode starts with nothing checked');
assert.strictEqual(Settings.shouldCheckSite(s({ siteMode: 'chosen', onSites: ['news.example'] }), 'a.news.example'), true);
assert.strictEqual(Settings.shouldCheckSite(s(), ''), false);

// ---- Gmail ----
assert.strictEqual(Settings.shouldCheckEmail(s()), true);
assert.strictEqual(Settings.shouldCheckEmail(s({ checkEmail: false })), false);
assert.strictEqual(Settings.shouldCheckEmail(s({ enabled: false })), false);

// ---- the popup's per-site button ----
assert.deepStrictEqual(Settings.withSiteToggled(s(), 'www.news.example', false), { offSites: ['news.example'] });
assert.deepStrictEqual(Settings.withSiteToggled(s({ offSites: ['news.example'] }), 'news.example', true), { offSites: [] });
assert.deepStrictEqual(Settings.withSiteToggled(s({ siteMode: 'chosen' }), 'news.example', true), { onSites: ['news.example'] });
assert.deepStrictEqual(Settings.withSiteToggled(s({ siteMode: 'chosen', onSites: ['news.example'] }), 'news.example', false), { onSites: [] });

// ---- the popup's answer to "is this page being checked?" ----
const say = (settings, url, reply) => PopupStatus.describePage({ settings, url, reply });
const yes = { checking: true };
assert.strictEqual(say(s(), 'https://news.example/a', yes).state, 'yes');
assert.strictEqual(say(s(), 'https://news.example/a', yes).toggle.label, 'Turn off for this website');
assert.strictEqual(say(s(), 'https://news.example/a', undefined).state, 'unknown', 'if the page never answered, we do not claim it is checked');
assert.match(say(s(), 'https://news.example/a', undefined).detail, /Reload/);
assert.strictEqual(say(s({ enabled: false }), 'https://news.example/a', yes).state, 'no');
assert.match(say(s({ enabled: false }), 'https://news.example/a', yes).detail, /turned off/);
assert.strictEqual(say(s(), 'chrome://extensions', undefined).state, 'no');
assert.match(say(s(), 'chrome://extensions').text, /cannot be checked/);
assert.strictEqual(say(s(), undefined, undefined).state, 'no');
assert.strictEqual(say(s({ offSites: ['news.example'] }), 'https://news.example/', yes).toggle.on, true);
assert.match(say(s({ siteMode: 'chosen' }), 'https://news.example/', yes).detail, /only some websites/);
assert.strictEqual(say(s(), 'https://mail.google.com/mail/u/0/', yes).state, 'yes');
assert.match(say(s(), 'https://mail.google.com/mail/u/0/', yes).text, /Gmail/);
assert.strictEqual(say(s({ checkEmail: false }), 'https://mail.google.com/mail/u/0/', yes).state, 'no');
// Nothing the popup says uses scores or rules.
for (const url of ['https://news.example/', 'https://mail.google.com/']) assert.ok(!/score|rule|weight/i.test(JSON.stringify(say(s(), url, yes))));

// Website access Chrome hasn't given (yet): the popup says so instead of "Yes" or "reload".
const withAccess = (access, url) => PopupStatus.describePage({ settings: s(), url, reply: yes, access });
assert.strictEqual(withAccess('all', 'https://news.example/').state, 'yes');
assert.strictEqual(withAccess('gmail', 'https://news.example/').state, 'no');
assert.match(withAccess('gmail', 'https://news.example/').detail, /Settings/);
assert.strictEqual(withAccess('gmail', 'https://mail.google.com/mail/u/0/').state, 'yes');
assert.strictEqual(withAccess('none', 'https://mail.google.com/mail/u/0/').state, 'no');

// "Is this website on a list?": says what was checked, why it could not, and never "safe".
const on = { remoteLookups: true, providers: ['phishing-database'] };
const lk = (engine, lookup) => PopupStatus.describeLookup({ engine, lookup });
assert.match(lk({ remoteLookups: false, providers: [] }).text, /off/);
assert.match(lk(on, { type: 'LOOKUP_RESULT', status: 'match', source: { name: 'Phishing.Database list' } }).text, /on a list of dangerous/);
assert.strictEqual(lk(on, { type: 'LOOKUP_RESULT', status: 'match', source: { name: 'x' } }).state, 'no');
const missed = lk(on, { type: 'LOOKUP_RESULT', status: 'no_match', checked: ['local list', 'Phishing.Database list'] });
assert.match(missed.text, /Not on Phishing\.Database list/);
assert.match(missed.detail, /does not mean a website is safe/);
const broke = lk(on, { type: 'LOOKUP_RESULT', status: 'error', reason: 'x', details: [{ name: 'Google Safe Browsing', outcome: 'error', reason: 'Google Safe Browsing: no key saved yet' }] });
assert.deepStrictEqual([broke.state, /Could not check/.test(broke.text), /no key saved/.test(broke.detail)], ['unknown', true, true]);
assert.strictEqual(lk(on, undefined).state, 'unknown');

console.log('PASS  settings normalize, site matching, popup status\n\nAll tests passed');
