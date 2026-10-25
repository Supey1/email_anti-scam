// threat-lookup.js: asks "is this address known to be dangerous?"
//
// Every answer is one of three, and they must never be confused:
//   match     on a known-dangerous list (from a named source, trusted or not)
//   no_match  not on any list we checked. This does NOT mean the address is
//             safe: new scam websites aren't on any list yet.
//   error     we couldn't find out (timeout, no connection, bad answer).
//             Never treat this as no_match, and never as "safe".
//
// Two places are checked, in order:
//   1. the active local list (threat-rules.js), always, instantly, on this computer
//   2. a remote provider, only if the settings turn one on. Off by default:
//      turning it on sends addresses away from this computer (docs/threat-intelligence.md).
//
// A provider is an adapter: { name, trusted, lookup(parsedUrl, { signal }) -> Promise<{ matched, threatType? }> }
// Three exist: Google Safe Browsing (real, opt-in; background/safe-browsing.js), a free downloaded
// list of phishing websites (background/domain-feed.js), and a development mock. Every source that is
// turned on is asked at the same time; any match wins. No secret key is ever written into the extension: the Safe Browsing key is the person's
// own, saved on the settings page on this computer only.
//
// No chrome.* calls here, so tests can run it directly.

(function () {
  'use strict';
  const core = globalThis.GranblockCore = globalThis.GranblockCore || {};
  const bg = globalThis.GranblockBackground = globalThis.GranblockBackground || {};
  if (typeof require !== 'undefined' && !core.urlNormalizer) require('../core/url-normalizer.js');
  if (typeof require !== 'undefined' && !core.urlRules) require('../core/url-rules.js');
  if (typeof require !== 'undefined' && !bg.safeBrowsing) require('./safe-browsing.js');
  if (typeof require !== 'undefined' && !bg.domainFeed) require('./domain-feed.js');
  if (typeof require !== 'undefined' && !bg.threatRules) require('./threat-rules.js');
  const { normalizeUrl } = core.urlNormalizer;

  const DEFAULT_TIMEOUT_MS = 1500;
  // How long an answer is reused. Errors are never reused: the next click asks again.
  const CACHE_MS = { match: 60 * 60 * 1000, no_match: 10 * 60 * 1000 };
  const CACHE_MAX = 500;

  // ---------- providers ----------

  // FOR DEVELOPMENT AND TESTS ONLY. Pretends to be a remote service, using
  // made-up .example entries, so the slow path (waiting, timeouts, errors)
  // can be tested without sending anything anywhere.
  //   entries  website names it "knows"
  //   delayMs  how long it takes to answer
  //   fail     true to always fail (like a network error)
  function mockProvider({ entries = ['remote-only-phish.example'], delayMs = 50, fail = false, trusted = false } = {}) {
    return {
      name: 'Development mock (made-up .example addresses)',
      trusted,
      lookup(parsed, { signal } = {}) {
        return new Promise((resolve, reject) => {
          const timer = setTimeout(() => {
            if (fail) reject(new Error('mock provider failure'));
            else resolve({ matched: entries.some(e => parsed.hostname === e || parsed.hostname.endsWith('.' + e)), threatType: 'SOCIAL_ENGINEERING' });
          }, delayMs);
          if (signal) signal.addEventListener('abort', () => { clearTimeout(timer); reject(new Error('aborted')); });
        });
      },
    };
  }

  // The free downloaded list (domain-feed.js). Untrusted: warns strongly, the person may continue.
  function feedProvider(id) {
    return (options, { feeds } = {}) => ({
      name: (feeds && feeds[id] && feeds[id].label) || id,
      trusted: false,
      async lookup(parsed) {
        if (!feeds || !feeds[id]) throw new Error('no list');
        return { matched: await feeds[id].match(parsed), threatType: 'PHISHING' };
      },
    });
  }

  const PROVIDERS = { mock: mockProvider, 'safe-browsing': bg.safeBrowsing.safeBrowsingProvider, 'phishing-database': feedProvider('phishing-database') };

  // ---------- lookups ----------

  // The online sources that are turned on: settings.providers (a list), or the older single settings.provider.
  function providerNames(settings) {
    const list = Array.isArray(settings.providers) && settings.providers.length ? settings.providers : [settings.provider];
    return [...new Set(list)].filter(name => PROVIDERS[name]);
  }

  // Creates a lookup service.
  //   feeds          the downloaded lists (domain-feed.js), by provider name
  //   getEntries()   the active local list (engine shape)
  //   getSettings()  { remoteLookups, providers, provider, providerOptions, lookupTimeoutMs, allowlist }
  //   now()          current time (ms)
  function createLookup({ getEntries, getSettings, now = () => Date.now(), feeds = {} }) {
    const cache = new Map();

    function cached(key) {
      const hit = cache.get(key);
      if (!hit) return null;
      if (hit.until <= now()) { cache.delete(key); return null; }
      return hit.answer;
    }
    function remember(key, answer) {
      if (!CACHE_MS[answer.status]) return;
      cache.set(key, { until: now() + CACHE_MS[answer.status], answer });
      if (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value);
    }

    // Looks up one address. Always resolves (never throws) to:
    //   { status, url, source: { name, trusted } | null, checked: [...], reason?, fromCache }
    async function lookup(rawUrl) {
      const parsed = normalizeUrl(String(rawUrl || ''));
      const answer = (status, extra = {}) => ({ status, url: parsed.ok ? parsed.href : String(rawUrl || ''), source: null, checked: [], fromCache: false, ...extra });
      if (!parsed.ok || !parsed.isWeb) return answer('error', { reason: 'not a web address' });

      const settings = getSettings();
      // 1. The local list, using exactly the engine's matching.
      const local = getEntries().filter(e => core.urlRules.entryMatches(e, parsed));
      if (local.length) {
        const best = local.find(e => e.trusted) || local[0];
        return answer('match', { source: { name: best.source, trusted: !!best.trusted }, checked: ['local list'] });
      }

      // Someone removed this address as a false positive: don't ask anyone else either.
      if (bg.threatRules && bg.threatRules.isAllowlisted({ type: 'url', value: parsed.href, hostname: parsed.hostname }, settings.allowlist)) {
        return answer('no_match', { checked: ['local list'], reason: 'removed as a false positive (allowlist)' });
      }

      // 2. The online sources the person turned on (all of them, at the same time).
      const names = settings.remoteLookups ? providerNames(settings) : [];
      if (!names.length) return answer('no_match', { checked: ['local list'] });

      const key = `${names.join('+')}|${parsed.href}`;
      const hit = cached(key);
      if (hit) return { ...hit, fromCache: true };

      const timeoutMs = settings.lookupTimeoutMs || DEFAULT_TIMEOUT_MS;
      const outcomes = await Promise.all(names.map(async name => {
        const provider = PROVIDERS[name](settings.providerOptions || {}, { feeds });
        const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
        let timer;
        const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), timeoutMs); });
        try {
          const reply = await Promise.race([provider.lookup(parsed, { signal: controller && controller.signal }), timeout]);
          if (!reply || typeof reply.matched !== 'boolean') throw new Error('unreadable answer');
          return { provider, matched: reply.matched, threatType: reply.threatType };
        } catch (err) {
          if (controller) controller.abort();
          // Messages we wrote ourselves for the person (a refused key, a list still downloading) are passed on.
          const reason = err && err.message === 'timeout' ? `no answer within ${timeoutMs} ms`
            : (err && err.userFacing ? err.message : 'the lookup service could not be reached');
          return { provider, error: reason };
        } finally {
          clearTimeout(timer);
        }
      }));

      const details = outcomes.map(o => ({ name: o.provider.name, outcome: o.error ? 'error' : o.matched ? 'match' : 'no_match', ...(o.error ? { reason: o.error } : {}) }));
      const matches = outcomes.filter(o => o.matched);
      const found = matches.find(o => o.provider.trusted) || matches[0];
      if (found) {
        const result = answer('match', { source: { name: found.provider.name, trusted: !!found.provider.trusted }, checked: ['local list', ...outcomes.filter(o => !o.error).map(o => o.provider.name)], threatType: found.threatType, details });
        remember(key, result);
        return result;
      }
      const worked = outcomes.filter(o => !o.error);
      if (!worked.length) return answer('error', { reason: outcomes[0].error, checked: ['local list'], details });
      const result = answer('no_match', { checked: ['local list', ...worked.map(o => o.provider.name)], details });
      if (worked.length === outcomes.length) remember(key, result); // never remember an answer that is missing a source
      return result;
    }

    return { lookup, clearCache: () => cache.clear() };
  }

  bg.threatLookup = { DEFAULT_TIMEOUT_MS, CACHE_MS, PROVIDERS, providerNames, mockProvider, createLookup };
  if (typeof module !== 'undefined') module.exports = bg.threatLookup;
})();
