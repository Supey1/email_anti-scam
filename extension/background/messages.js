// messages.js: everything the service worker does, as answers to messages.
// The message formats are in docs/interfaces.md ("Service worker messages").
//
//   LOOKUP_URL           is this address on a known-dangerous list?  -> LOOKUP_RESULT
//   UPDATE_THREAT_RULES  add or remove entries, mark false positives -> THREAT_RULES_UPDATED
//   GET_SETTINGS         read the protection settings                -> SETTINGS
//   SET_SETTINGS         change them                                 -> SETTINGS
//   GET_STATUS           settings + website access + what's active   -> STATUS
//   ACCESS_CHANGED       website access was granted or taken away    -> STATUS
//   SHOW_WARNING         the click guard stopped a link: open the warning page (ui/warning.html) -> { ok }
//   CONTINUE             the person chose "continue" on the warning page: checked again here,
//                        and never allowed for a known dangerous website         -> { ok }
//   REPORT_FALSE_ALARM   save a "this is a false alarm" report on this computer   -> { ok }
// Anything else gets { type: "ERROR" }.
//
// Changing the threat rules or the settings is only allowed from the
// extension's own pages, never from a content script running inside a website.
// CONTINUE is only accepted from the warning page itself.
//
// Two kinds of settings, in chrome.storage.local:
//   "settings"        the person's choices (extension/settings.js: on/off, Gmail, websites,
//                     text size, reading aloud). Saved by the popup and the settings page.
//   "engineSettings"  threat lookups and false positives (below). Only through SET_SETTINGS.
// protectionEnabled here is the person's on/off switch (settings.enabled), not a copy.
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
    protectionEnabled: true,  // the person's on/off switch; false: no blocking rules, no page scripts
    remoteLookups: false,     // true sends addresses to a lookup service: see docs/threat-intelligence.md
    provider: 'none',         // 'none' | 'safe-browsing' (Google, hash prefixes only) | 'mock' (development only)
    providerOptions: {},      // safe-browsing: { apiKey } (the person's own, never returned to pages); mock: { entries, delayMs, fail, trusted }
    lookupTimeoutMs: 1500,
    allowlist: [],            // website names or addresses removed as false positives
  });
  const MAX_REPORTS = 100; // false-alarm reports kept on this computer
  const MAX_TEXT = { text: 200, adText: 400 }; // what the warning page's address may carry

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
          if ('apiKey' in value && (typeof value.apiKey !== 'string' || (value.apiKey && !/^[A-Za-z0-9_-]{20,100}$/.test(value.apiKey)))) return { error: 'that does not look like a Safe Browsing key (letters, numbers, - and _ only)' };
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
  //   dnr            { getDynamicRules(), updateDynamicRules({ removeRuleIds, addRules }) }
  //   tabs           { update(tabId, { url }), create({ url, active, index, openerTabId }) }
  //   permissions    { contains({ origins }) }  (chrome.permissions). Left out in tests: full access.
  //   scripting      { getRegisteredContentScripts, registerContentScripts, unregisterContentScripts }. Optional.
  //   bundled()      the bundled list (data/threat-list.js) as raw entries
  //   warningPage    address of ui/warning.html
  //   checkLink({ url, text, entries })  the scam checks for one link (rules.js checkLinkClick),
  //                  using these known-dangerous entries. Used before CONTINUE.
  //   badge(on)      optional: show "OFF" on the toolbar button when protection is off
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
    // The key is the person's secret: no reply ever carries it, only whether one is saved.
    const publicSettings = s => {
      const { apiKey, ...options } = s.providerOptions || {};
      return { ...s, providerOptions: { ...options, apiKeySet: !!apiKey } };
    };
    const fail = error => reply('ERROR', { error });
    const lookup = bg.threatLookup.createLookup({ getEntries: () => bg.threatRules.forEngine(active.entries), getSettings: () => settings, now });

    const asObject = value => (value && typeof value === 'object' && !Array.isArray(value) ? value : {});
    async function load() {
      const engine = asObject(await deps.storage.get('engineSettings'));
      const user = asObject(await deps.storage.get('settings'));
      const known = Object.fromEntries(Object.entries(engine).filter(([key]) => key in DEFAULT_SETTINGS && key !== 'protectionEnabled'));
      // The first version asked PhishTank about each address. It was replaced by Google Safe Browsing: switch it off.
      if (known.provider === 'phishtank') Object.assign(known, { provider: 'none', remoteLookups: false });
      settings = { ...DEFAULT_SETTINGS, ...known, protectionEnabled: user.enabled !== false };
    }
    async function store(next) {
      const { protectionEnabled, ...engine } = next;
      const user = asObject(await deps.storage.get('settings'));
      const changes = { engineSettings: engine };
      if ((user.enabled !== false) !== protectionEnabled) changes.settings = { ...user, enabled: protectionEnabled };
      await deps.storage.set(changes);
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
        if (deps.badge) await Promise.resolve(deps.badge(settings.protectionEnabled)).catch(() => {});
        const blockPage = `${deps.warningPage}?kind=dnr&url=`;
        const rules = settings.protectionEnabled ? bg.threatRules.buildRules(active.entries, blockPage, { canRedirect: access === 'all' }) : [];
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
    function fromWarningPage(sender) {
      return !!sender && !!sender.tab && typeof sender.url === 'string' && sender.url.startsWith(deps.warningPage);
    }
    function isWebAddress(url) {
      try { return typeof url === 'string' && /^https?:$/.test(new URL(url).protocol); } catch (e) { return false; }
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
          await store(settings);
        }
        lookup.clearCache();
        return reply('THREAT_RULES_UPDATED', await refreshRules());
      },

      async GET_SETTINGS() {
        await whenReady();
        return reply('SETTINGS', { settings: publicSettings(settings) });
      },

      async SET_SETTINGS(message, sender) {
        if (!isPrivileged(sender)) return fail('only the extension\'s own pages can change the settings');
        await whenReady();
        const checked = validateSettings(settings, message.settings);
        if (checked.error) return fail(checked.error);
        settings = checked.settings;
        await store(settings);
        lookup.clearCache();
        await refreshRules();
        return reply('SETTINGS', { settings: publicSettings(settings) });
      },

      async GET_STATUS() {
        await ensureActive();
        return reply('STATUS', { settings: publicSettings(settings), access, rules: (await deps.dnr.getDynamicRules()).length, activeEntries: active.entries.length });
      },

      // Chrome said website access changed (chrome.permissions.onAdded / onRemoved).
      async ACCESS_CHANGED() {
        await refreshRules();
        return handlers.GET_STATUS();
      },

      // The click guard stopped a link. A click that would have opened a new tab gets the
      // warning in a new tab; otherwise the warning replaces the page (from any frame:
      // the whole tab, so an ad frame can't hide it).
      async SHOW_WARNING(message, sender) {
        if (!sender || !sender.tab || !isWebAddress(message.url)) return { ok: false };
        const url = `${deps.warningPage}?kind=click` +
          `&text=${encodeURIComponent(String(message.text || '').slice(0, MAX_TEXT.text))}` +
          `&adtext=${encodeURIComponent(String(message.adText || '').slice(0, MAX_TEXT.adText))}` +
          (message.inAd ? '&inad=1' : '') +
          (message.fromScamEmail ? '&from=scam-email' : '') +
          `&url=${encodeURIComponent(message.url)}`; // last: the page reads everything after "&url="
        try {
          if (message.newTab) await deps.tabs.create({ url, active: true, index: sender.tab.index + 1, openerTabId: sender.tab.id });
          else await deps.tabs.update(sender.tab.id, { url });
          return { ok: true };
        } catch (e) {
          return { ok: false }; // the click guard then shows its own in-page warning
        }
      },

      // "Continue" on the warning page. Checked again here, whatever the page asked:
      // a known dangerous website can never be continued to.
      async CONTINUE(message, sender) {
        if (!fromWarningPage(sender) || !isWebAddress(message.url)) return { ok: false };
        await ensureActive();
        const result = deps.checkLink({ url: message.url, text: String(message.text || ''), entries: bg.threatRules.forEngine(active.entries) });
        if (!result || result.verdict === 'block') return { ok: false };
        try {
          await deps.tabs.update(sender.tab.id, { url: message.url });
          return { ok: true };
        } catch (e) {
          return { ok: false };
        }
      },

      // Kept on this computer only, for the testing period: the website's name, what we said,
      // where, and when. Never page text or anything typed.
      async REPORT_FALSE_ALARM(message) {
        const report = message.report && typeof message.report === 'object' ? message.report : null;
        if (!report) return { ok: false };
        const saved = (await deps.storage.get('falseAlarms')) || [];
        saved.push({
          at: new Date(now()).toISOString(),
          host: String(report.host || '').slice(0, 253),
          verdict: String(report.verdict || '').slice(0, 20),
          source: String(report.source || '').slice(0, 20),
          reasons: (Array.isArray(report.reasons) ? report.reasons : []).slice(0, 5).map(r => String(r).slice(0, 300)),
        });
        await deps.storage.set({ falseAlarms: saved.slice(-MAX_REPORTS) });
        return { ok: true };
      },
    };

    // Answers one message. Always resolves, never throws.
    async function handleMessage(message, sender) {
      try {
        if (!message || typeof message !== 'object') return fail('a message must be an object');
        if (message.schemaVersion !== undefined && message.schemaVersion !== SCHEMA_VERSION) return fail(`unsupported schemaVersion: ${message.schemaVersion}`);
        const handler = Object.prototype.hasOwnProperty.call(handlers, message.type) ? handlers[message.type] : null;
        if (!handler) return fail(`unknown message type: ${message.type}`);
        return await handler(message, sender);
      } catch (err) {
        return fail(`something went wrong: ${err && err.message}`);
      }
    }

    // The person changed their choices (popup or settings page): read them again and apply.
    function settingsChanged() {
      ready = null;
      return refreshRules();
    }

    return { handleMessage, refreshRules, settingsChanged, getSettings: () => settings, getActive: () => active };
  }

  bg.DEFAULT_SETTINGS = DEFAULT_SETTINGS;
  bg.validateSettings = validateSettings;
  bg.createBackground = createBackground;
  if (typeof module !== 'undefined') module.exports = { DEFAULT_SETTINGS, validateSettings, createBackground };
})();
