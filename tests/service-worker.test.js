// Tests for the service worker's threat lookup and browser-level blocking.
// Run with:  node tests/service-worker.test.js
//
// These run the real background code (extension/background/) against a pretend
// Chrome: storage, tabs, and a network-blocking API that keeps rules like
// Chrome does and can say whether a rule would match an address.
// tests/browser/ (blocking.test.js and the others) check the same things in real Chrome.
//
// Only made-up .example addresses. Never real dangerous links.

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { createBackground, DEFAULT_SETTINGS } = require(path.join(__dirname, '..', 'extension', 'background', 'messages.js'));
const threatRules = require(path.join(__dirname, '..', 'extension', 'background', 'threat-rules.js'));
const threatList = require(path.join(__dirname, '..', 'extension', 'data', 'threat-list.js'));
const { analyze, checkLinkClick } = require(path.join(__dirname, '..', 'extension', 'rules.js'));
const urlRules = require(path.join(__dirname, '..', 'extension', 'core', 'url-rules.js'));

// ---------- a pretend Chrome ----------

const WARNING_PAGE = 'chrome-extension://test-id/ui/warning.html';
const BLOCK_PAGE = `${WARNING_PAGE}?kind=dnr&url=`;
const EXTENSION_PAGE = { id: 'test-id', url: 'chrome-extension://test-id/ui/options.html' };
const ON_WARNING_PAGE = { id: 'test-id', url: `${WARNING_PAGE}?kind=click&url=https://x.example/`, tab: { id: 7 }, frameId: 0 };
const CONTENT_SCRIPT = { id: 'test-id', url: 'https://news.example/today', tab: { id: 7 }, frameId: 0 };

function fakeStorage() {
  const data = new Map();
  return {
    data,
    get: async key => (data.has(key) ? JSON.parse(JSON.stringify(data.get(key))) : undefined),
    set: async items => { for (const [k, v] of Object.entries(items)) data.set(k, JSON.parse(JSON.stringify(v))); },
    remove: async keys => { for (const k of [].concat(keys)) data.delete(k); },
  };
}

// Keeps rules like Chrome: ids must be unique, removing an unknown id is fine.
function fakeDnr() {
  let rules = [];
  return {
    calls: 0,
    getDynamicRules: async () => rules.map(r => ({ ...r })),
    async updateDynamicRules({ removeRuleIds = [], addRules = [] }) {
      this.calls++;
      await new Promise(r => setTimeout(r, 1)); // let other updates try to run in between
      const kept = rules.filter(r => !removeRuleIds.includes(r.id));
      const ids = new Set(kept.map(r => r.id));
      for (const r of addRules) {
        if (ids.has(r.id)) throw new Error(`Rule with id ${r.id} already exists`);
        ids.add(r.id);
      }
      rules = kept.concat(addRules);
    },
    get rules() { return rules; },
  };
}

// Does a rule match this address? Supports what our rules use: requestDomains,
// resourceTypes, and urlFilter with "|" anchors and "*". (Chrome's real matching
// is checked by the browser test.)
function ruleMatches(rule, url, resourceType) {
  const u = new URL(url);
  const c = rule.condition;
  if (c.resourceTypes && !c.resourceTypes.includes(resourceType)) return false;
  if (c.requestDomains && !c.requestDomains.some(d => u.hostname === d || u.hostname.endsWith('.' + d))) return false;
  if (c.urlFilter) {
    let f = c.urlFilter;
    const start = f.startsWith('|'); if (start) f = f.slice(1);
    const end = f.endsWith('|'); if (end) f = f.slice(0, -1);
    const re = new RegExp(`${start ? '^' : ''}${f.split('*').map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*')}${end ? '$' : ''}`, 'i');
    if (!re.test(u.href)) return false;
  }
  return true;
}
const blockedBy = (dnr, url, type = 'main_frame') => dnr.rules.find(r => ruleMatches(r, url, type)) || null;

// Website access the person has given: a set of granted origin patterns.
function fakePermissions(granted) {
  return {
    granted: new Set(granted),
    contains: async function ({ origins }) { return origins.every(o => this.granted.has(o)); },
  };
}

// Registers page scripts like Chrome: the same id twice is an error.
function fakeScripting() {
  let scripts = [];
  return {
    registerCalls: 0,
    getRegisteredContentScripts: async () => scripts.map(s => ({ ...s })),
    async registerContentScripts(list) {
      this.registerCalls++;
      for (const s of list) if (scripts.some(r => r.id === s.id)) throw new Error(`Duplicate script ID '${s.id}'`);
      scripts = scripts.concat(list.map(s => ({ ...s })));
    },
    async unregisterContentScripts({ ids }) { scripts = scripts.filter(s => !ids.includes(s.id)); },
    get scripts() { return scripts; },
  };
}
const ALL = ['http://*/*', 'https://*/*'];
const GMAIL_ONLY = ['https://mail.google.com/*'];

const bundled = () => [
  ...threatList.KNOWN_THREAT_DOMAINS.map(value => ({ type: 'domain', value, source: threatList.KNOWN_THREAT_SOURCE.name, trusted: true })),
  ...threatList.KNOWN_THREAT_URLS.map(value => ({ type: 'url', value, source: threatList.KNOWN_THREAT_SOURCE.name, trusted: true })),
];

function setup({ bundledEntries = bundled, start = 1_000_000, access = null, storage = fakeStorage(), dnr = fakeDnr(), scripting = null } = {}) {
  const permissions = access ? fakePermissions(access) : null;
  const tabUpdates = [];
  const tabsCreated = [];
  const badges = [];
  let time = start;
  const background = createBackground({
    storage, dnr,
    tabs: {
      update: async (tabId, props) => { tabUpdates.push({ tabId, ...props }); },
      create: async props => { tabsCreated.push(props); },
    },
    ...(permissions ? { permissions, scripting: scripting || fakeScripting() } : {}),
    bundled: bundledEntries,
    warningPage: WARNING_PAGE,
    // As service-worker.js does it: the engine, with the service worker's list.
    checkLink: ({ url, text, entries }) => { urlRules.useThreatEntries(entries); return checkLinkClick({ url, text }); },
    badge: on => { badges.push(on); },
    extensionOrigin: 'chrome-extension://test-id/',
    now: () => time,
  });
  return { background, storage, dnr, tabUpdates, tabsCreated, badges, permissions, advance: ms => { time += ms; } };
}
const send = (env, message, sender = CONTENT_SCRIPT) => env.background.handleMessage({ schemaVersion: 1, ...message }, sender);

// Addresses that are NOT on any list, but look a lot like ones that are.
// None of these may ever be blocked.
const NORMAL_ADDRESSES = [
  'https://known-phish-news.example/',
  'https://known-phish.example.other.example/',
  'https://notknown-phish.example/',
  'https://hacked-blog.example/',
  'https://hacked-blog.example/2024/recipes',
  'https://hacked-blog.example/wp-content/uploads/secure-ish/page',
  'https://hacked-blog.example/wp-content/uploads/',
  'https://www.paypal.com/signin',
  'https://other-news.example/lottery',
  'https://www.google.com/search?q=known-phish.example',
  'https://news.example/?next=https://known-phish.example/',
];

// ---------- tests ----------

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

// --- staged: a tiny synthetic list, then a matching test address is blocked ---

test('the bundled synthetic list becomes rules, and a matching test address is blocked', async () => {
  const env = setup();
  const result = await env.background.refreshRules();
  assert.ok(result.installedRules > 0);
  for (const url of ['https://known-phish.example/', 'https://login.known-phish.example/x', 'http://fake-bank-login.example/a',
    'https://hacked-blog.example/wp-content/uploads/secure/login.html']) {
    const rule = blockedBy(env.dnr, url);
    assert.ok(rule, `not blocked: ${url}`);
    assert.strictEqual(rule.action.type, 'redirect');
    assert.ok(rule.action.redirect.url.startsWith(BLOCK_PAGE));
  }
  assert.strictEqual(blockedBy(env.dnr, 'https://known-phish.example/ad', 'sub_frame').action.type, 'block');
});

test('normal addresses that look like listed ones are NOT blocked', async () => {
  const env = setup();
  await env.background.refreshRules();
  for (const url of NORMAL_ADDRESSES) {
    for (const type of ['main_frame', 'sub_frame']) assert.strictEqual(blockedBy(env.dnr, url, type), null, `wrongly blocked (${type}): ${url}`);
  }
});

test('a single-address entry without a trailing "/" covers that address and below, nothing beside it', async () => {
  const env = setup();
  await send(env, { type: 'UPDATE_THREAT_RULES', add: [{ type: 'url', value: 'https://lure.example/promo', source: 'test', trusted: true }] }, EXTENSION_PAGE);
  for (const url of ['https://lure.example/promo', 'https://lure.example/promo/win', 'https://lure.example/promo?id=1', 'http://lure.example/promo']) {
    assert.ok(blockedBy(env.dnr, url), `not blocked: ${url}`);
  }
  for (const url of ['https://lure.example/', 'https://lure.example/promos', 'https://lure.example/promo-ended', 'https://lure.example/other/promo']) {
    assert.strictEqual(blockedBy(env.dnr, url), null, `wrongly blocked: ${url}`);
  }
});

// --- updates, duplicates, stale entries, false positives ---

test('updates: added entries are blocked, removed ones are not', async () => {
  const env = setup();
  await send(env, { type: 'UPDATE_THREAT_RULES', add: [{ type: 'domain', value: 'new-threat.example', source: 'test', trusted: true }] }, EXTENSION_PAGE);
  assert.ok(blockedBy(env.dnr, 'https://new-threat.example/'));
  await send(env, { type: 'UPDATE_THREAT_RULES', remove: ['new-threat.example'] }, EXTENSION_PAGE);
  assert.strictEqual(blockedBy(env.dnr, 'https://new-threat.example/'), null);
  assert.ok(blockedBy(env.dnr, 'https://known-phish.example/'), 'removing one entry must not remove the others');
});

test('duplicates (same website written differently, or listed twice) become ONE rule', async () => {
  const env = setup({ bundledEntries: () => [] });
  const reply = await send(env, { type: 'UPDATE_THREAT_RULES', add: [
    { type: 'domain', value: 'dup-threat.example', source: 'a', trusted: true },
    { type: 'domain', value: 'DUP-THREAT.example.', source: 'b', trusted: true },
    { type: 'domain', value: 'dup-threat.example', source: 'c', trusted: false },
    { type: 'url', value: 'https://dup-threat.example/inside/', source: 'd', trusted: true }, // already covered by the whole website
  ] }, EXTENSION_PAGE);
  assert.strictEqual(reply.activeEntries, 1);
  assert.strictEqual(env.dnr.rules.filter(r => r.condition.resourceTypes.includes('main_frame')).length, 1);
});

test('rules are replaced, never stacked: many updates at once leave exactly one copy of each rule', async () => {
  const env = setup();
  await Promise.all([env.background.refreshRules(), env.background.refreshRules(), env.background.refreshRules(),
    send(env, { type: 'UPDATE_THREAT_RULES', add: [{ type: 'domain', value: 'burst.example', source: 'test', trusted: true }] }, EXTENSION_PAGE)]);
  const once = (await env.background.refreshRules()).installedRules;
  assert.strictEqual(env.dnr.rules.length, once);
  assert.strictEqual(new Set(env.dnr.rules.map(r => r.id)).size, env.dnr.rules.length, 'duplicate rule ids');
  const keys = env.dnr.rules.map(r => JSON.stringify(r.condition));
  assert.strictEqual(new Set(keys).size, keys.length, 'the same rule twice');
});

test('stale entries: an entry stops counting when it expires (rules, engine list, and lookups)', async () => {
  const env = setup();
  await send(env, { type: 'UPDATE_THREAT_RULES', add: [{ type: 'domain', value: 'short-lived.example', source: 'test', trusted: true, expiresAt: 1_000_000 + 60_000 }] }, EXTENSION_PAGE);
  assert.ok(blockedBy(env.dnr, 'https://short-lived.example/'));
  assert.strictEqual((await send(env, { type: 'LOOKUP_URL', url: 'https://short-lived.example/' })).status, 'match');
  env.advance(61_000);
  const after = await send(env, { type: 'LOOKUP_URL', url: 'https://short-lived.example/' });
  assert.strictEqual(after.status, 'no_match');
  assert.strictEqual(blockedBy(env.dnr, 'https://short-lived.example/'), null, 'the expired rule is still installed');
  assert.ok(!(await env.storage.get('activeThreats')).some(e => e.value === 'short-lived.example'), 'the pages still have it');
});

test('false positives: removing one unblocks it everywhere, and is remembered', async () => {
  const env = setup();
  await env.background.refreshRules();
  assert.ok(blockedBy(env.dnr, 'https://fake-bank-login.example/'));
  const reply = await send(env, { type: 'UPDATE_THREAT_RULES', falsePositives: ['fake-bank-login.example'] }, EXTENSION_PAGE);
  assert.ok(reply.rejected.some(r => r.value === 'fake-bank-login.example' && /false positive/.test(r.reason)));
  assert.strictEqual(blockedBy(env.dnr, 'https://fake-bank-login.example/'), null);
  assert.ok(!(await env.storage.get('activeThreats')).some(e => e.value === 'fake-bank-login.example'), 'the click guard would still block it');
  const lookup = await send(env, { type: 'LOOKUP_URL', url: 'https://fake-bank-login.example/' });
  assert.strictEqual(lookup.status, 'no_match');
  assert.deepStrictEqual((await env.storage.get('engineSettings')).allowlist, ['fake-bank-login.example']);
  assert.ok(blockedBy(env.dnr, 'https://known-phish.example/'), 'other entries must stay');
});

test('entries that would block far too much, or an official company website, are refused', async () => {
  const env = setup({ bundledEntries: () => [] });
  const bad = ['com', 'co.uk', 'github.io', 'localhost', 'paypal.com', 'www.chase.com', 'not a website', 'https://evil.example/'];
  const reply = await send(env, { type: 'UPDATE_THREAT_RULES', add: bad.map(value => ({ type: value.startsWith('https') ? 'url' : 'domain', value, source: 'feed', trusted: true })) }, EXTENSION_PAGE);
  assert.strictEqual(reply.activeEntries, 0);
  assert.strictEqual(reply.rejected.length, bad.length, JSON.stringify(reply.rejected));
  assert.strictEqual(env.dnr.rules.length, 0);
  assert.strictEqual(blockedBy(env.dnr, 'https://www.paypal.com/'), null);
});

test('untrusted entries warn (click guard) but are never hard-blocked by Chrome', async () => {
  const env = setup({ bundledEntries: () => [] });
  await send(env, { type: 'UPDATE_THREAT_RULES', add: [{ type: 'domain', value: 'maybe-bad.example', source: 'unchecked feed', trusted: false }] }, EXTENSION_PAGE);
  assert.strictEqual(blockedBy(env.dnr, 'https://maybe-bad.example/'), null);
  assert.ok((await env.storage.get('activeThreats')).some(e => e.value === 'maybe-bad.example' && !e.trusted));
  const lookup = await send(env, { type: 'LOOKUP_URL', url: 'https://maybe-bad.example/x' });
  assert.deepStrictEqual([lookup.status, lookup.source.trusted], ['match', false]);
});

test('a very long list: one rule covers them all (Chrome limits redirect rules)', async () => {
  const many = Array.from({ length: threatRules.PER_SITE_RULE_LIMIT + 5 }, (_, i) => ({ type: 'domain', value: `threat-${i}.example`, source: 'test', trusted: true }));
  const env = setup({ bundledEntries: () => many });
  const result = await env.background.refreshRules();
  assert.ok(result.installedRules <= 4, `${result.installedRules} rules`);
  assert.ok(blockedBy(env.dnr, 'https://threat-1003.example/'));
  assert.strictEqual(blockedBy(env.dnr, 'https://threat-1003-news.example/'), null);
});

test('protection turned off: no rules at all; turned back on: rules return', async () => {
  const env = setup();
  await env.background.refreshRules();
  await send(env, { type: 'SET_SETTINGS', settings: { protectionEnabled: false } }, EXTENSION_PAGE);
  assert.strictEqual(env.dnr.rules.length, 0);
  assert.deepStrictEqual(await env.storage.get('activeThreats'), []);
  await send(env, { type: 'SET_SETTINGS', settings: { protectionEnabled: true } }, EXTENSION_PAGE);
  assert.ok(blockedBy(env.dnr, 'https://known-phish.example/'));
});

test('after Chrome restarts the service worker (memory lost), lookups still know the list', async () => {
  const env = setup();
  // No refreshRules() first: a freshly started service worker gets a lookup straight away.
  const r = await send(env, { type: 'LOOKUP_URL', url: 'https://known-phish.example/' });
  assert.strictEqual(r.status, 'match');
});

// --- lookups: match, no match, and error are never confused ---

test('LOOKUP_URL: on the local list -> match, with its source', async () => {
  const env = setup();
  const r = await send(env, { type: 'LOOKUP_URL', url: 'https://login.known-phish.example/x' });
  assert.deepStrictEqual([r.type, r.status, r.source.trusted], ['LOOKUP_RESULT', 'match', true]);
});

test('LOOKUP_URL: not on any list -> no_match, says what was checked, never "safe"', async () => {
  const env = setup();
  const r = await send(env, { type: 'LOOKUP_URL', url: 'https://other-news.example/lottery' });
  assert.strictEqual(r.status, 'no_match');
  assert.deepStrictEqual(r.checked, ['local list']);
  assert.ok(!/safe/i.test(JSON.stringify(r)), 'a no_match answer must never claim the address is safe');
});

test('LOOKUP_URL: the remote mock finds a match the local list doesn\'t know (untrusted: warn, never block)', async () => {
  const env = setup();
  await send(env, { type: 'SET_SETTINGS', settings: { remoteLookups: true, provider: 'mock' } }, EXTENSION_PAGE);
  const r = await send(env, { type: 'LOOKUP_URL', url: 'https://remote-only-phish.example/start' });
  assert.deepStrictEqual([r.status, r.source.trusted], ['match', false]);
  assert.deepStrictEqual(r.checked, ['local list', r.source.name]);
  const input = { source: 'link', pageUrl: 'https://news.example/', pageTitle: '', visibleText: '', links: [{ text: 'Open', url: r.url }], forms: [], context: {} };
  const verdict = analyze(input, { lookup: r });
  assert.deepStrictEqual([verdict.verdict, verdict.recommendedAction], ['warn', 'GO_BACK']);
});

test('LOOKUP_URL: a remote no_match is reused for a while (cache)', async () => {
  const env = setup();
  await send(env, { type: 'SET_SETTINGS', settings: { remoteLookups: true, provider: 'mock' } }, EXTENSION_PAGE);
  const first = await send(env, { type: 'LOOKUP_URL', url: 'https://other-news.example/a' });
  const second = await send(env, { type: 'LOOKUP_URL', url: 'https://other-news.example/a' });
  assert.deepStrictEqual([first.status, first.fromCache, second.status, second.fromCache], ['no_match', false, 'no_match', true]);
});

test('LOOKUP_URL: a failing service -> error (not no_match), and the error is never reused', async () => {
  const env = setup();
  await send(env, { type: 'SET_SETTINGS', settings: { remoteLookups: true, provider: 'mock', providerOptions: { fail: true } } }, EXTENSION_PAGE);
  const r = await send(env, { type: 'LOOKUP_URL', url: 'https://other-news.example/a' });
  assert.strictEqual(r.status, 'error');
  assert.match(r.reason, /could not be reached/);
  const again = await send(env, { type: 'LOOKUP_URL', url: 'https://other-news.example/a' });
  assert.strictEqual(again.fromCache, false);
});

test('LOOKUP_URL: a slow service -> error after the timeout, not a silent pass', async () => {
  const env = setup();
  await send(env, { type: 'SET_SETTINGS', settings: { remoteLookups: true, provider: 'mock', providerOptions: { delayMs: 500 }, lookupTimeoutMs: 100 } }, EXTENSION_PAGE);
  const started = Date.now();
  const r = await send(env, { type: 'LOOKUP_URL', url: 'https://remote-only-phish.example/' });
  assert.strictEqual(r.status, 'error');
  assert.match(r.reason, /no answer within 100 ms/);
  assert.ok(Date.now() - started < 400, 'waited for the slow service anyway');
});

test('a lookup error never makes a link look verified: the analyzer result is unchanged', async () => {
  const env = setup();
  await send(env, { type: 'SET_SETTINGS', settings: { remoteLookups: true, provider: 'mock', providerOptions: { fail: true } } }, EXTENSION_PAGE);
  for (const url of ['https://other-news.example/a', 'https://bit.ly/abc']) {
    const r = await send(env, { type: 'LOOKUP_URL', url });
    const input = { source: 'link', pageUrl: 'https://news.example/', pageTitle: '', visibleText: '', links: [{ text: 'Open', url }], forms: [], context: {} };
    assert.deepStrictEqual(analyze(input, { lookup: r }), analyze(input));
  }
});

test('LOOKUP_URL: not a web address -> error', async () => {
  const env = setup();
  assert.strictEqual((await send(env, { type: 'LOOKUP_URL', url: 'javascript:alert(1)' })).status, 'error');
  assert.strictEqual((await send(env, { type: 'LOOKUP_URL' })).type, 'ERROR');
});

// --- the message contract ---

test('websites can\'t change the rules or the settings (only the extension\'s own pages can)', async () => {
  const env = setup();
  await env.background.refreshRules();
  const a = await send(env, { type: 'UPDATE_THREAT_RULES', falsePositives: ['known-phish.example'] }, CONTENT_SCRIPT);
  const b = await send(env, { type: 'SET_SETTINGS', settings: { protectionEnabled: false } }, CONTENT_SCRIPT);
  assert.deepStrictEqual([a.type, b.type], ['ERROR', 'ERROR']);
  assert.ok(blockedBy(env.dnr, 'https://known-phish.example/'));
});

test('GET_SETTINGS works from a page; SET_SETTINGS checks every value', async () => {
  const env = setup();
  const got = await send(env, { type: 'GET_SETTINGS' });
  assert.deepStrictEqual(got.settings, { ...DEFAULT_SETTINGS });
  assert.strictEqual(got.settings.remoteLookups, false, 'remote lookups must be off unless someone turns them on');
  for (const bad of [{ protectionEnabled: 'no' }, { provider: 'safe-browsing-with-my-key' }, { lookupTimeoutMs: 5 }, { allowlist: 'x' }, { surprise: 1 }]) {
    assert.strictEqual((await send(env, { type: 'SET_SETTINGS', settings: bad }, EXTENSION_PAGE)).type, 'ERROR', JSON.stringify(bad));
  }
});

test('SHOW_WARNING opens the extension\'s own warning page: in the same tab, or a new one for a new-tab click', async () => {
  const env = setup();
  const same = await send(env, { type: 'SHOW_WARNING', url: 'https://chase-secure.example/verify', text: 'www.chase.com', adText: '' });
  assert.deepStrictEqual(same, { ok: true });
  assert.strictEqual(env.tabUpdates.length, 1);
  const opened = new URL(env.tabUpdates[0].url);
  assert.ok(env.tabUpdates[0].url.startsWith(`${WARNING_PAGE}?`));
  assert.strictEqual(opened.searchParams.get('kind'), 'click');
  assert.strictEqual(opened.searchParams.get('text'), 'www.chase.com');
  assert.ok(env.tabUpdates[0].url.endsWith(`&url=${encodeURIComponent('https://chase-secure.example/verify')}`), 'the address must come last');
  await send(env, { type: 'SHOW_WARNING', url: 'https://x.example/', newTab: true, fromScamEmail: true });
  assert.strictEqual(env.tabsCreated.length, 1);
  assert.strictEqual(env.tabsCreated[0].openerTabId, 7);
  assert.strictEqual(new URL(env.tabsCreated[0].url).searchParams.get('from'), 'scam-email');
});

test('SHOW_WARNING: only web addresses, only from a tab, and the page address carries little text', async () => {
  const env = setup();
  for (const url of ['javascript:alert(1)', 'chrome://settings/', '', 42]) {
    assert.deepStrictEqual(await send(env, { type: 'SHOW_WARNING', url }), { ok: false }, String(url));
  }
  assert.deepStrictEqual(await send(env, { type: 'SHOW_WARNING', url: 'https://x.example/' }, EXTENSION_PAGE), { ok: false }, 'no tab');
  await send(env, { type: 'SHOW_WARNING', url: 'https://x.example/', text: 'a'.repeat(5000), adText: 'b'.repeat(5000) });
  const opened = new URL(env.tabUpdates[0].url);
  assert.deepStrictEqual([opened.searchParams.get('text').length, opened.searchParams.get('adtext').length], [200, 400]);
});

test('CONTINUE: only from the warning page, checked again, and never to a known dangerous website', async () => {
  const env = setup();
  await env.background.refreshRules();
  // A website (content script) can't make the tab "continue" anywhere.
  assert.deepStrictEqual(await send(env, { type: 'CONTINUE', url: 'https://chase-secure.example/' }, CONTENT_SCRIPT), { ok: false });
  assert.deepStrictEqual(await send(env, { type: 'CONTINUE', url: 'https://known-phish.example/' }, ON_WARNING_PAGE), { ok: false });
  // An address added by an update is known too, not just the bundled list.
  await send(env, { type: 'UPDATE_THREAT_RULES', add: [{ type: 'domain', value: 'added-later.example', source: 'test', trusted: true }] }, EXTENSION_PAGE);
  assert.deepStrictEqual(await send(env, { type: 'CONTINUE', url: 'https://added-later.example/' }, ON_WARNING_PAGE), { ok: false });
  assert.strictEqual(env.tabUpdates.length, 0);
  // A warning ("check first" or "stop") can be continued past, if the person chooses to.
  assert.deepStrictEqual(await send(env, { type: 'CONTINUE', url: 'https://chase-secure.example/', text: 'www.chase.com' }, ON_WARNING_PAGE), { ok: true });
  assert.deepStrictEqual(env.tabUpdates, [{ tabId: 7, url: 'https://chase-secure.example/' }]);
  assert.deepStrictEqual(await send(env, { type: 'CONTINUE', url: 'javascript:alert(1)' }, ON_WARNING_PAGE), { ok: false });
});

test('REPORT_FALSE_ALARM keeps at most 100 short reports, with no page text', async () => {
  const env = setup();
  for (let i = 0; i < 105; i++) {
    await send(env, { type: 'REPORT_FALSE_ALARM', report: { host: `site${i}.example`, verdict: 'warn', source: 'click-guard', reasons: ['r1', 'r2', 'r3', 'r4', 'r5', 'r6'], pageText: 'private words' } });
  }
  const saved = await env.storage.get('falseAlarms');
  assert.strictEqual(saved.length, 100);
  assert.strictEqual(saved[0].host, 'site5.example');
  assert.strictEqual(saved[99].reasons.length, 5);
  assert.ok(!JSON.stringify(saved).includes('private words'));
  assert.deepStrictEqual(await send(env, { type: 'REPORT_FALSE_ALARM' }), { ok: false });
});

test('unknown messages and other schema versions are refused', async () => {
  const env = setup();
  assert.strictEqual((await send(env, { type: 'DELETE_EVERYTHING' })).type, 'ERROR');
  assert.strictEqual((await env.background.handleMessage({ type: 'GET_SETTINGS', schemaVersion: 2 }, CONTENT_SCRIPT)).type, 'ERROR');
  assert.strictEqual((await env.background.handleMessage(null, CONTENT_SCRIPT)).type, 'ERROR');
});

test('the engine and Chrome use the SAME list: everything Chrome blocks, the click guard knows', async () => {
  const env = setup();
  await send(env, { type: 'UPDATE_THREAT_RULES', add: [{ type: 'domain', value: 'shared-list.example', source: 'test', trusted: true }] }, EXTENSION_PAGE);
  const urlRules = require(path.join(__dirname, '..', 'extension', 'core', 'url-rules.js'));
  urlRules.useThreatEntries(await env.storage.get('activeThreats'));
  try {
    const r = analyze({ source: 'link', pageUrl: 'https://news.example/', pageTitle: '', visibleText: '', links: [{ text: 'Open', url: 'https://shared-list.example/' }], forms: [], context: {} });
    assert.strictEqual(r.verdict, 'block');
  } finally {
    urlRules.useThreatEntries(null);
  }
});

// --- Phase 6: website access, settings, and restarts ---

const scriptsOf = async env => (await env.background.refreshRules()).scripts;

test('page scripts match the website access given: none, Gmail only, or all websites', async () => {
  assert.deepStrictEqual(await scriptsOf(setup({ access: [] })), []);
  assert.deepStrictEqual(await scriptsOf(setup({ access: GMAIL_ONLY })), ['granblock-guard', 'granblock-gmail']);
  assert.deepStrictEqual(await scriptsOf(setup({ access: ALL })), ['granblock-guard', 'granblock-page', 'granblock-gmail']);
});

test('Gmail-only access never registers scripts for other websites', async () => {
  const scripting = fakeScripting();
  const env = setup({ access: GMAIL_ONLY, scripting });
  await env.background.refreshRules();
  for (const s of scripting.scripts) assert.deepStrictEqual(s.matches, GMAIL_ONLY, s.id);
});

test('without website access, known dangerous websites are still blocked (Chrome\'s own block, no redirect)', async () => {
  const env = setup({ access: [] });
  await env.background.refreshRules();
  const rule = blockedBy(env.dnr, 'https://known-phish.example/');
  assert.ok(rule, 'not blocked');
  assert.strictEqual(rule.action.type, 'block');
  for (const url of NORMAL_ADDRESSES) assert.strictEqual(blockedBy(env.dnr, url), null, url);
});

test('access taken away (in Chrome\'s settings): scripts stop, blocking falls back, nothing breaks', async () => {
  const scripting = fakeScripting();
  const env = setup({ access: ALL, scripting });
  await env.background.refreshRules();
  assert.strictEqual(blockedBy(env.dnr, 'https://known-phish.example/').action.type, 'redirect');
  env.permissions.granted.clear(); // the person revoked access
  const status = await send(env, { type: 'ACCESS_CHANGED' }, EXTENSION_PAGE);
  assert.deepStrictEqual([status.type, status.access], ['STATUS', 'none']);
  assert.deepStrictEqual(scripting.scripts, []);
  assert.strictEqual(blockedBy(env.dnr, 'https://known-phish.example/').action.type, 'block');
  assert.strictEqual((await send(env, { type: 'LOOKUP_URL', url: 'https://known-phish.example/' })).status, 'match', 'lookups must keep working');
});

test('turning protection off stops the page scripts too; on again starts them', async () => {
  const scripting = fakeScripting();
  const env = setup({ access: ALL, scripting });
  await env.background.refreshRules();
  await send(env, { type: 'SET_SETTINGS', settings: { protectionEnabled: false } }, EXTENSION_PAGE);
  assert.deepStrictEqual([scripting.scripts.length, env.dnr.rules.length], [0, 0]);
  await send(env, { type: 'SET_SETTINGS', settings: { protectionEnabled: true } }, EXTENSION_PAGE);
  assert.strictEqual(scripting.scripts.length, 3);
});

test('applying protection again and again never registers a script twice', async () => {
  const scripting = fakeScripting();
  const env = setup({ access: ALL, scripting });
  await Promise.all([env.background.refreshRules(), env.background.refreshRules(), env.background.refreshRules()]);
  await env.background.refreshRules();
  assert.strictEqual(scripting.scripts.length, 3);
  assert.strictEqual(scripting.registerCalls, 1, 'scripts that were already right were registered again');
});

test('a restart (all memory lost) keeps the settings, the rules, and the scripts', async () => {
  const storage = fakeStorage();
  const dnr = fakeDnr();
  const scripting = fakeScripting();
  const first = setup({ access: ALL, storage, dnr, scripting });
  await send(first, { type: 'SET_SETTINGS', settings: { lookupTimeoutMs: 2500, allowlist: ['kept.example'] } }, EXTENSION_PAGE);
  await send(first, { type: 'UPDATE_THREAT_RULES', add: [{ type: 'domain', value: 'kept-after-restart.example', source: 'test', trusted: true }] }, EXTENSION_PAGE);
  // A brand-new service worker on the same storage, rules, and scripts (as after a browser restart).
  const second = setup({ access: ALL, storage, dnr, scripting });
  const got = await send(second, { type: 'GET_SETTINGS' });
  assert.deepStrictEqual([got.settings.lookupTimeoutMs, got.settings.allowlist], [2500, ['kept.example']]);
  assert.strictEqual((await send(second, { type: 'LOOKUP_URL', url: 'https://kept-after-restart.example/' })).status, 'match');
  await second.background.refreshRules();
  assert.ok(blockedBy(dnr, 'https://kept-after-restart.example/'));
  assert.strictEqual(scripting.scripts.length, 3);
});

test('ONE on/off switch: the popup\'s choice (settings.enabled) and SET_SETTINGS protectionEnabled are the same', async () => {
  const storage = fakeStorage();
  // The person's other choices (extension/settings.js) are left exactly as they were.
  await storage.set({ settings: { enabled: false, checkEmail: true, textSize: 'xlarge', offSites: ['bank.example'] } });
  const env = setup({ storage });
  await env.background.refreshRules();
  assert.strictEqual((await send(env, { type: 'GET_SETTINGS' })).settings.protectionEnabled, false);
  assert.strictEqual(env.dnr.rules.length, 0, 'protection is off: no blocking rules');
  assert.deepStrictEqual(env.badges.slice(-1), [false], 'the toolbar button says OFF');
  await send(env, { type: 'SET_SETTINGS', settings: { protectionEnabled: true } }, EXTENSION_PAGE);
  assert.deepStrictEqual(await storage.get('settings'), { enabled: true, checkEmail: true, textSize: 'xlarge', offSites: ['bank.example'] });
  assert.ok(env.dnr.rules.length > 0);
  // Turned off in the popup (written straight to storage), then the service worker is told.
  await storage.set({ settings: { ...(await storage.get('settings')), enabled: false } });
  await env.background.settingsChanged();
  assert.strictEqual(env.dnr.rules.length, 0);
  assert.strictEqual((await storage.get('engineSettings')).protectionEnabled, undefined, 'the switch is stored in one place only');
});

test('the old reading settings (now in extension/settings.js) are refused here', async () => {
  const env = setup();
  for (const bad of [{ textSize: 'larger' }, { autoRead: true }, { speechRate: 0.9 }]) {
    assert.strictEqual((await send(env, { type: 'SET_SETTINGS', settings: bad }, EXTENSION_PAGE)).type, 'ERROR', JSON.stringify(bad));
  }
});

test('the manifest asks only for what is used: no website access at install, no cookies or history', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'extension', 'manifest.json'), 'utf8'));
  assert.strictEqual(manifest.manifest_version, 3);
  assert.deepStrictEqual(manifest.permissions.slice().sort(), ['declarativeNetRequest', 'scripting', 'storage']);
  assert.ok(!manifest.host_permissions, 'website access must be optional, asked for during onboarding');
  assert.ok(!manifest.content_scripts, 'page scripts are registered only after access is given');
  assert.deepStrictEqual(manifest.optional_host_permissions, ['http://*/*', 'https://*/*']);
  // The warning page must be reachable by Chrome's redirect of a known dangerous website.
  assert.deepStrictEqual(manifest.web_accessible_resources.flatMap(r => r.resources), ['ui/warning.html']);
  for (const page of [manifest.action.default_popup, manifest.options_ui.page]) {
    assert.ok(fs.existsSync(path.join(__dirname, '..', 'extension', page)), page);
  }
});

test('every page script the service worker registers exists', () => {
  const { desiredScripts } = require(path.join(__dirname, '..', 'extension', 'background', 'content-scripts.js'));
  for (const script of desiredScripts('all', true)) {
    for (const file of script.js) assert.ok(fs.existsSync(path.join(__dirname, '..', 'extension', file)), `${script.id}: missing ${file}`);
  }
});

test('every script an extension page or the service worker loads exists', () => {
  const ext = path.join(__dirname, '..', 'extension');
  for (const page of ['ui/warning.html', 'ui/options.html', 'ui/popup.html']) {
    const html = fs.readFileSync(path.join(ext, page), 'utf8');
    for (const [, src] of html.matchAll(/<script src="([^"]+)"/g)) assert.ok(fs.existsSync(path.join(ext, path.dirname(page), src)), `${page}: missing ${src}`);
  }
  const worker = fs.readFileSync(path.join(ext, 'service-worker.js'), 'utf8');
  const imports = worker.slice(worker.indexOf('importScripts('), worker.indexOf(');', worker.indexOf('importScripts(')));
  for (const [, file] of imports.matchAll(/'([^']+\.js)'/g)) assert.ok(fs.existsSync(path.join(ext, file)), `service-worker.js: missing ${file}`);
});

// ---------- run ----------

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
  console.log(`\n${passed}/${tests.length} service worker tests passed`);
})();
