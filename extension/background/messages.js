// messages.js: everything the service worker does, as answers to messages.
// The message formats are in docs/interfaces.md ("Service worker messages").
//
//   LOOKUP_URL           is this address on a known-dangerous list?  -> LOOKUP_RESULT
//   UPDATE_THREAT_RULES  add or remove entries, mark false positives -> THREAT_RULES_UPDATED
//   OPEN_WARNING_PAGE    show the extension's own warning page       -> WARNING_PAGE_OPENED
//   GET_SETTINGS         read the protection settings                -> SETTINGS
//   SET_SETTINGS         change them                                 -> SETTINGS
//   GET_STATUS           settings + website access + what's active   -> STATUS
//   ACCESS_CHANGED       website access was granted or taken away    -> STATUS
//   REPORT_FALSE_ALARM   save a "this is a false alarm" note, for testing -> FALSE_ALARM_SAVED
//   SHOW_WARNING         pass a warning from a frame to the main page (also the older "granblock-warning")
// Anything else gets { type: "ERROR" }.
//
// Changing the threat rules or the settings is only allowed from the
// extension's own pages, never from a content script running inside a website.
//
// createBackground() takes the Chrome APIs as plain functions, so tests can
// run all of this without Chrome. service-worker.js passes in the real ones.

(function () {
  'use strict';
  const bg = globalThis.GranblockBackground = globalThis.GranblockBackground || {};
  if (typeof require !== 'undefined' && !bg.threatRules) require('./threat-rules.js');
  if (typeof require !== 'undefined' && !bg.threatLookup) require('./threat-lookup.js');
  if (typeof require !== 'undefined' && !bg.contentScripts) require('./content-scripts.js');

  const SCHEMA_VERSION = 1;

  const DEFAULT_SETTINGS = Object.freeze({
    protectionEnabled: true,  // false: no blocking rules, and pages are told protection is off
    remoteLookups: false,     // true sends addresses to a lookup service: see docs/threat-intelligence.md
    provider: 'none',         // 'none' | 'mock' (development only)
    providerOptions: {},      // for the mock: { entries, delayMs, fail, trusted }
    lookupTimeoutMs: 1500,
    allowlist: [],            // website names or addresses removed as false positives
    // Reading and text (warnings, the Gmail panel, the warning page)
    textSize: 'large',        // 'large' | 'larger' | 'largest'
    autoRead: false,          // read each new warning aloud without pressing the button
    speechRate: 0.9,          // 0.5 (slow) to 1.5 (fast)
  });
  const TEXT_SIZES = ['large', 'larger', 'largest'];
  // Warnings kept for the warning page: enough to go back and forth, not a history.
  const WARNING_KEEP_MS = 60 * 60 * 1000;
  const WARNING_KEEP_MAX = 20;
  const VERDICTS = ['block', 'warn', 'no_warning_signs', 'unknown'];
  // "This is a false alarm" notes, kept on this computer for testing. Only what the person saw: never page text.
  const FALSE_ALARMS_KEEP = 100;

  // Checks a settings change. Returns { settings } or { error }.
  function validateSettings(current, change) {
    if (!change || typeof change !== 'object' || Array.isArray(change)) return { error: 'settings must be an object' };
    const next = { ...current };
    for (const [key, value] of Object.entries(change)) {
      switch (key) {
        case 'protectionEnabled':
        case 'remoteLookups':
        case 'autoRead':
          if (typeof value !== 'boolean') return { error: `${key} must be true or false` };
          break;
        case 'provider':
          if (value !== 'none' && !bg.threatLookup.PROVIDERS[value]) return { error: `unknown provider: ${value}` };
          break;
        case 'providerOptions':
          if (!value || typeof value !== 'object' || Array.isArray(value)) return { error: 'providerOptions must be an object' };
          break;
        case 'lookupTimeoutMs':
          if (!Number.isInteger(value) || value < 100 || value > 10000) return { error: 'lookupTimeoutMs must be between 100 and 10000' };
          break;
        case 'textSize':
          if (!TEXT_SIZES.includes(value)) return { error: `textSize must be one of ${TEXT_SIZES.join(', ')}` };
          break;
        case 'speechRate':
          if (typeof value !== 'number' || !(value >= 0.5 && value <= 1.5)) return { error: 'speechRate must be between 0.5 and 1.5' };
          break;
        case 'allowlist':
          if (!Array.isArray(value) || value.length > 500 || value.some(v => typeof v !== 'string')) return { error: 'allowlist must be a list of up to 500 addresses' };
          break;
        default:
          return { error: `unknown setting: ${key}` };
      }
      next[key] = value;
    }
    return { settings: next };
  }

  // deps:
  //   storage        { get(key) -> Promise<value>, set(object) -> Promise }  (chrome.storage.local)
  //   session        same, plus remove(keys), for short-lived data         (chrome.storage.session)
  //   dnr            { getDynamicRules(), updateDynamicRules({ removeRuleIds, addRules }) }
  //   tabs           { update(tabId, { url }), sendMessage(tabId, message, { frameId }) }
  //   permissions    { contains({ origins }) }  (chrome.permissions). Left out in tests: full access.
  //   scripting      { getRegisteredContentScripts, registerContentScripts, unregisterContentScripts }. Optional.
  //   bundled()      the bundled list (threat-list.js) as raw entries
  //   blockPage      address of blocked.html
  //   extensionOrigin  "chrome-extension://<id>/"
  //   now()          current time (ms)
  //   newToken()     a random id
  function createBackground(deps) {
    const now = deps.now || (() => Date.now());
    let settings = { ...DEFAULT_SETTINGS };
    let active = { entries: [], rejected: [] };
    let nextExpiry = null;
    let access = 'none';
    let ready = null;
    let built = null; // has the active list been built since this service worker started?
    let queue = Promise.resolve(); // rule updates run one at a time, never on top of each other

    const reply = (type, body = {}) => ({ type, schemaVersion: SCHEMA_VERSION, ...body });
    const fail = error => reply('ERROR', { error });
    const lookup = bg.threatLookup.createLookup({ getEntries: () => bg.threatRules.forEngine(active.entries), getSettings: () => settings, now });

    async function load() {
      const saved = await deps.storage.get('settings');
      settings = { ...DEFAULT_SETTINGS, ...(saved && typeof saved === 'object' ? saved : {}) };
    }
    const whenReady = () => (ready = ready || load());

    // Applies protection as it should be right now, in one step: rebuilds the
    // active list, replaces ALL our Chrome rules, and registers the page
    // scripts for the website access the person has given. Safe to run any
    // number of times (each run replaces, never adds).
    function refreshRules() {
      queue = queue.then(async () => {
        await whenReady();
        access = deps.permissions ? await bg.contentScripts.currentAccess(deps.permissions) : 'all';
        const updates = (await deps.storage.get('threatEntries')) || [];
        active = bg.threatRules.activeEntries([deps.bundled(), updates], { allowlist: settings.allowlist, now: now() });
        const expiries = active.entries.map(e => e.expiresAt).filter(Boolean);
        nextExpiry = expiries.length ? Math.min(...expiries) : null;
        const rules = settings.protectionEnabled ? bg.threatRules.buildRules(active.entries, deps.blockPage, { canRedirect: access === 'all' }) : [];
        const old = await deps.dnr.getDynamicRules();
        await deps.dnr.updateDynamicRules({ removeRuleIds: old.map(r => r.id), addRules: rules });
        // The pages' engines use the same list as Chrome (threat-sync.js).
        await deps.storage.set({ activeThreats: settings.protectionEnabled ? bg.threatRules.forEngine(active.entries) : [] });
        const scripts = deps.scripting
          ? await bg.contentScripts.syncScripts(deps.scripting, bg.contentScripts.desiredScripts(access, settings.protectionEnabled))
          : [];
        return { installedRules: rules.length, activeEntries: active.entries.length, rejected: active.rejected, access, scripts };
      });
      const result = queue;
      queue = queue.catch(() => {}); // one failed update doesn't stop the next one
      return result;
    }

    // Chrome stops idle service workers and starts them again when needed, and
    // everything in memory is lost. So the active list is rebuilt on first use
    // after every start, not only when the extension is installed.
    async function ensureActive() {
      if (!built) built = refreshRules().catch(err => { built = null; throw err; });
      await built;
      if (nextExpiry !== null && nextExpiry <= now()) await refreshRules();
    }

    function isPrivileged(sender) {
      return !!sender && typeof sender.url === 'string' && sender.url.startsWith(deps.extensionOrigin);
    }

    const handlers = {
      async LOOKUP_URL(message) {
        if (typeof message.url !== 'string' || !message.url) return fail('LOOKUP_URL needs a url');
        await ensureActive();
        return reply('LOOKUP_RESULT', await lookup.lookup(message.url));
      },

      async UPDATE_THREAT_RULES(message, sender) {
        if (!isPrivileged(sender)) return fail('only the extension\'s own pages can change the threat rules');
        const add = Array.isArray(message.add) ? message.add : [];
        const remove = new Set((Array.isArray(message.remove) ? message.remove : []).map(v => String(v).toLowerCase()));
        const falsePositives = Array.isArray(message.falsePositives) ? message.falsePositives.map(String) : [];

        let updates = (await deps.storage.get('threatEntries')) || [];
        if (message.replaceAll) updates = [];
        updates = updates.filter(e => !remove.has(String(e.value).toLowerCase()));
        for (const e of add) updates.push({ addedAt: now(), ...e });
        await deps.storage.set({ threatEntries: updates });
        if (falsePositives.length) {
          await whenReady();
          settings = { ...settings, allowlist: [...new Set([...settings.allowlist, ...falsePositives])] };
          await deps.storage.set({ settings });
        }
        lookup.clearCache();
        return reply('THREAT_RULES_UPDATED', await refreshRules());
      },

      async OPEN_WARNING_PAGE(message, sender) {
        const result = message.result;
        if (!result || !VERDICTS.includes(result.verdict) || !Array.isArray(result.reasons)) return fail('OPEN_WARNING_PAGE needs an analyzer result');
        if (!sender || !sender.tab) return fail('OPEN_WARNING_PAGE must come from a tab');
        const token = deps.newToken();
        const text = (value, max) => (typeof value === 'string' ? value.slice(0, max) : '');
        // Session storage: gone when the browser closes. Only what the warning
        // page shows: no evidence snippets, no page text.
        const shown = {
          verdict: result.verdict,
          recommendedAction: result.recommendedAction,
          reasons: result.reasons.slice(0, 10).map(r => ({ code: String(r.code || ''), title: String(r.title || ''), explanation: String(r.explanation || '') })),
        };
        // Keep the last hour's warnings, at most WARNING_KEEP_MAX; remove the rest.
        const before = (await deps.session.get('warningIndex')) || [];
        const kept = [...before.filter(w => w.createdAt > now() - WARNING_KEEP_MS), { token, createdAt: now() }].slice(-WARNING_KEEP_MAX);
        const dropped = before.filter(w => !kept.some(k => k.token === w.token)).map(w => `warning:${w.token}`);
        if (dropped.length) await deps.session.remove(dropped);
        await deps.session.set({ warningIndex: kept, [`warning:${token}`]: { result: shown, url: text(message.url, 2000), linkText: text(message.linkText, 200), createdAt: now() } });
        const page = `${deps.blockPage}?t=${token}`;
        // A click that would have opened a new tab gets the warning in a new tab; otherwise it replaces this page.
        if (message.newTab === true && deps.tabs.create) await deps.tabs.create({ url: page, active: true, index: sender.tab.index + 1, openerTabId: sender.tab.id });
        else await deps.tabs.update(sender.tab.id, { url: page });
        return reply('WARNING_PAGE_OPENED', { token });
      },

      async GET_SETTINGS() {
        await whenReady();
        return reply('SETTINGS', { settings });
      },

      async SET_SETTINGS(message, sender) {
        if (!isPrivileged(sender)) return fail('only the extension\'s own pages can change the settings');
        await whenReady();
        const checked = validateSettings(settings, message.settings);
        if (checked.error) return fail(checked.error);
        settings = checked.settings;
        await deps.storage.set({ settings });
        lookup.clearCache();
        await refreshRules();
        return reply('SETTINGS', { settings });
      },

      async GET_STATUS() {
        await ensureActive();
        return reply('STATUS', { settings, access, rules: (await deps.dnr.getDynamicRules()).length, activeEntries: active.entries.length });
      },

      // Chrome said website access changed (chrome.permissions.onAdded / onRemoved).
      async ACCESS_CHANGED() {
        await refreshRules();
        return handlers.GET_STATUS();
      },

      // A person says a warning was a false alarm. For testing: saved here, never sent anywhere.
      async REPORT_FALSE_ALARM(message) {
        const r = message.report;
        if (!r || typeof r !== 'object') return fail('REPORT_FALSE_ALARM needs a report');
        const clip = (v, n) => String(v === undefined ? '' : v).slice(0, n);
        const saved = (await deps.storage.get('falseAlarms')) || [];
        saved.push({
          at: new Date(now()).toISOString(),
          host: clip(r.host, 100),
          verdict: clip(r.verdict, 20),
          source: clip(r.source, 30),
          reasons: (Array.isArray(r.reasons) ? r.reasons : []).slice(0, 5).map(x => clip(x, 300)),
        });
        await deps.storage.set({ falseAlarms: saved.slice(-FALSE_ALARMS_KEEP) });
        return reply('FALSE_ALARM_SAVED', { count: Math.min(saved.length, FALSE_ALARMS_KEEP) });
      },

      async SHOW_WARNING(message, sender) {
        if (!sender || !sender.tab || sender.frameId === 0) return reply('SHOW_WARNING_RESULT', { shown: false });
        try {
          const answer = await deps.tabs.sendMessage(sender.tab.id, message, { frameId: 0 });
          return reply('SHOW_WARNING_RESULT', { shown: !!(answer && answer.shown) });
        } catch (e) {
          return reply('SHOW_WARNING_RESULT', { shown: false }); // e.g. the main page is one we can't run on
        }
      },
    };

    // Answers one message. Always resolves, never throws.
    async function handleMessage(message, sender) {
      try {
        if (!message || typeof message !== 'object') return fail('a message must be an object');
        if (message.schemaVersion !== undefined && message.schemaVersion !== SCHEMA_VERSION) return fail(`unsupported schemaVersion: ${message.schemaVersion}`);
        const type = message.type === 'granblock-warning' ? 'SHOW_WARNING' : message.type; // older name, from guard.js
        const handler = Object.prototype.hasOwnProperty.call(handlers, type) ? handlers[type] : null;
        if (!handler) return fail(`unknown message type: ${message.type}`);
        const answer = await handler(message, sender);
        // The older guard.js reads { shown } straight from the answer.
        return message.type === 'granblock-warning' ? { ...answer, shown: !!answer.shown } : answer;
      } catch (err) {
        return fail(`something went wrong: ${err && err.message}`);
      }
    }

    return { handleMessage, refreshRules, getSettings: () => settings, getActive: () => active };
  }

  bg.DEFAULT_SETTINGS = DEFAULT_SETTINGS;
  bg.validateSettings = validateSettings;
  bg.createBackground = createBackground;
  if (typeof module !== 'undefined') module.exports = { DEFAULT_SETTINGS, validateSettings, createBackground };
})();
