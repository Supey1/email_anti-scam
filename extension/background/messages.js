// messages.js: everything the service worker does, as answers to messages.
// The message formats are in docs/interfaces.md ("Service worker messages").
//
//   LOOKUP_URL           is this address on a known-dangerous list?  -> LOOKUP_RESULT
//   UPDATE_THREAT_RULES  add or remove entries, mark false positives -> THREAT_RULES_UPDATED
//   OPEN_WARNING_PAGE    show the extension's own warning page       -> WARNING_PAGE_OPENED
//   GET_SETTINGS         read the protection settings                -> SETTINGS
//   SET_SETTINGS         change them                                 -> SETTINGS
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

  const SCHEMA_VERSION = 1;

  const DEFAULT_SETTINGS = Object.freeze({
    protectionEnabled: true,  // false: no blocking rules, and pages are told protection is off
    remoteLookups: false,     // true sends addresses to a lookup service: see docs/threat-intelligence.md
    provider: 'none',         // 'none' | 'mock' (development only)
    providerOptions: {},      // for the mock: { entries, delayMs, fail, trusted }
    lookupTimeoutMs: 1500,
    allowlist: [],            // website names or addresses removed as false positives
  });
  const VERDICTS = ['block', 'warn', 'no_warning_signs', 'unknown'];

  // Checks a settings change. Returns { settings } or { error }.
  function validateSettings(current, change) {
    if (!change || typeof change !== 'object' || Array.isArray(change)) return { error: 'settings must be an object' };
    const next = { ...current };
    for (const [key, value] of Object.entries(change)) {
      switch (key) {
        case 'protectionEnabled':
        case 'remoteLookups':
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
  //   session        same, for short-lived data                            (chrome.storage.session)
  //   dnr            { getDynamicRules(), updateDynamicRules({ removeRuleIds, addRules }) }
  //   tabs           { update(tabId, { url }), sendMessage(tabId, message, { frameId }) }
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

    // Rebuilds the active list and replaces ALL our Chrome rules in one step.
    function refreshRules() {
      queue = queue.then(async () => {
        await whenReady();
        const updates = (await deps.storage.get('threatEntries')) || [];
        active = bg.threatRules.activeEntries([deps.bundled(), updates], { allowlist: settings.allowlist, now: now() });
        const expiries = active.entries.map(e => e.expiresAt).filter(Boolean);
        nextExpiry = expiries.length ? Math.min(...expiries) : null;
        const rules = settings.protectionEnabled ? bg.threatRules.buildRules(active.entries, deps.blockPage) : [];
        const old = await deps.dnr.getDynamicRules();
        await deps.dnr.updateDynamicRules({ removeRuleIds: old.map(r => r.id), addRules: rules });
        // The pages' engines use the same list as Chrome (threat-sync.js).
        await deps.storage.set({ activeThreats: settings.protectionEnabled ? bg.threatRules.forEngine(active.entries) : [] });
        return { installedRules: rules.length, activeEntries: active.entries.length, rejected: active.rejected };
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
        await deps.session.set({ [`warning:${token}`]: { result, url: typeof message.url === 'string' ? message.url : '', createdAt: now() } });
        await deps.tabs.update(sender.tab.id, { url: `${deps.blockPage}?t=${token}` });
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
