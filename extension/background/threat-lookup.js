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
// Two exist: PhishTank (real, opt-in) and a development mock. No secret key is
// ever written into the extension; an optional PhishTank app key could only be
// something the person saved on their own computer.
//
// No chrome.* calls here, so tests can run it directly.

(function () {
  'use strict';
  const core = globalThis.GranblockCore = globalThis.GranblockCore || {};
  const bg = globalThis.GranblockBackground = globalThis.GranblockBackground || {};
  if (typeof require !== 'undefined' && !core.urlNormalizer) require('../core/url-normalizer.js');
  if (typeof require !== 'undefined' && !core.urlRules) require('../core/url-rules.js');
  if (typeof require !== 'undefined' && !core.domainRules) require('../core/domain-rules.js');
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

  // PhishTank (phishtank.org): a community list of web addresses people reported
  // as phishing and others verified. Its "check URL" service answers for ONE
  // address, so using it sends addresses away from this computer:
  //   - only the website and path are sent (never ?query or #fragment, which can hold
  //     login tokens or private ids), as a base64 form field over HTTPS
  //   - never sent: official company websites, number addresses, local or one-word names
  //   - only entries that are BOTH verified and still valid count as a match
  // Needs permission to talk to checkurl.phishtank.com (asked for on the settings page).
  const PHISHTANK_URL = 'https://checkurl.phishtank.com/checkurl/';
  const yes = v => v === true || v === 'true' || v === 'y' || v === 'yes';

  // The address as it is sent, or null when it must not be sent at all.
  function phishtankQuery(parsed) {
    const host = parsed.hostname || '';
    if (!parsed.isWeb || parsed.isIp || !host.includes('.') || host.includes(':') || host.endsWith('.localhost')) return null;
    if (core.domainRules && core.domainRules.officialBrandFor(host)) return null;
    return `${parsed.protocol}//${host}${encodeURI(parsed.pathname)}`;
  }

  // options: { appKey, fetch } (fetch is replaced in tests)
  function phishtankProvider({ appKey = '', fetch: fetchFn } = {}) {
    return {
      name: 'PhishTank',
      trusted: true, // a match is verified by people, so it may stop the person (the analyzer blocks it)
      async lookup(parsed, { signal } = {}) {
        const send = phishtankQuery(parsed);
        if (!send) return { matched: false };
        const body = new URLSearchParams({ url: btoa(send), format: 'json' });
        if (appKey) body.set('app_key', String(appKey));
        const response = await (fetchFn || globalThis.fetch)(PHISHTANK_URL, {
          method: 'POST',
          body,
          signal,
          credentials: 'omit',
          cache: 'no-store',
          referrerPolicy: 'no-referrer',
        });
        if (response.status === 509) throw new Error('PhishTank rate limit reached'); // over its free allowance
        if (!response.ok) throw new Error(`PhishTank answered ${response.status}`);
        const data = await response.json();
        const r = data && data.results;
        if (!r || typeof r !== 'object') throw new Error('unreadable answer');
        return { matched: yes(r.in_database) && yes(r.verified) && yes(r.valid), threatType: 'PHISHING' };
      },
    };
  }

  const PROVIDERS = { mock: mockProvider, phishtank: phishtankProvider };

  // ---------- lookups ----------

  // Creates a lookup service.
  //   getEntries()   the active local list (engine shape)
  //   getSettings()  { remoteLookups, provider, providerOptions, lookupTimeoutMs, allowlist }
  //   now()          current time (ms)
  function createLookup({ getEntries, getSettings, now = () => Date.now() }) {
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

      // 2. A remote provider, only if one is turned on.
      const makeProvider = settings.remoteLookups && PROVIDERS[settings.provider];
      if (!makeProvider) return answer('no_match', { checked: ['local list'] });

      const provider = makeProvider(settings.providerOptions || {});
      const key = `${settings.provider}|${parsed.href}`;
      const hit = cached(key);
      if (hit) return { ...hit, fromCache: true };

      const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
      const timeoutMs = settings.lookupTimeoutMs || DEFAULT_TIMEOUT_MS;
      let timer;
      const timeout = new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), timeoutMs); });
      try {
        const reply = await Promise.race([provider.lookup(parsed, { signal: controller && controller.signal }), timeout]);
        if (!reply || typeof reply.matched !== 'boolean') throw new Error('unreadable answer');
        const result = answer(reply.matched ? 'match' : 'no_match', {
          source: reply.matched ? { name: provider.name, trusted: !!provider.trusted } : null,
          checked: ['local list', provider.name],
          threatType: reply.threatType,
        });
        remember(key, result);
        return result;
      } catch (err) {
        if (controller) controller.abort();
        const reason = err && err.message === 'timeout' ? `no answer within ${timeoutMs} ms` : 'the lookup service could not be reached';
        return answer('error', { reason, checked: ['local list'] });
      } finally {
        clearTimeout(timer);
      }
    }

    return { lookup, clearCache: () => cache.clear() };
  }

  bg.threatLookup = { DEFAULT_TIMEOUT_MS, CACHE_MS, PROVIDERS, mockProvider, phishtankProvider, phishtankQuery, createLookup };
  if (typeof module !== 'undefined') module.exports = bg.threatLookup;
})();
