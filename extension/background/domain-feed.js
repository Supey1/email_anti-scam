// domain-feed.js: a free, public list of phishing website names (one per line) that is downloaded
// to this computer and checked here. Looking an address up sends NOTHING anywhere; the only network
// traffic is downloading the whole list, which is the same for everyone.
//
// Source: Phishing.Database (github.com/mitchellkrogza/Phishing.Database, MIT licence), "active
// phishing domains", no key needed. It is refreshed when older than REFRESH_MS, at most once per
// RETRY_MS; a failed download keeps the old copy. Entries are matched by exact website name (with or
// without "www."), never by parent, so one listed page on a big host does not condemn the whole host.
// Official company websites and whole website endings in the list are ignored (a feed listing
// paypal.com is a mistake). Matches come from a source we cannot vouch for, so they are "untrusted":
// a strong warning the person may continue past, never a hard block.
//
// No chrome.* calls here: storage and fetch are passed in, so tests can run it directly.

(function () {
  'use strict';
  const core = globalThis.GranblockCore = globalThis.GranblockCore || {};
  const bg = globalThis.GranblockBackground = globalThis.GranblockBackground || {};
  if (typeof require !== 'undefined' && !core.urlNormalizer) require('../core/url-normalizer.js');
  if (typeof require !== 'undefined' && !core.domainRules) require('../core/domain-rules.js');
  const { isPublicSuffix } = core.urlNormalizer;

  const SOURCES = {
    'phishing-database': {
      label: 'Phishing.Database list',
      url: 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
    },
  };
  const REFRESH_MS = 24 * 60 * 60 * 1000;
  const RETRY_MS = 60 * 60 * 1000;
  const MAX_ENTRIES = 1000000;

  const hostKey = hostname => hostname.toLowerCase().replace(/\.+$/, '').replace(/^www\./, '');

  // Text (one website name per line, "#" comments) -> the kept names, one per line.
  function cleanList(text) {
    const kept = [];
    for (const line of text.split(/\r?\n/)) {
      const raw = line.trim();
      if (!raw || raw.startsWith('#')) continue;
      const host = hostKey(raw.replace(/^[a-z]+:\/\//i, '').split(/[/?#:]/)[0]);
      if (!/^[a-z0-9.-]+\.[a-z0-9-]+$/.test(host) || host.length > 253) continue;
      if (isPublicSuffix(host) || core.domainRules.officialBrandFor(host)) continue;
      kept.push(host);
      if (kept.length >= MAX_ENTRIES) break;
    }
    return kept.join('\n');
  }

  // deps: { storage: { get(key), set(object) }, fetch, now(), id }
  function createFeed(deps) {
    const source = SOURCES[deps.id];
    const storageKey = `domainFeed:${deps.id}`;
    const now = deps.now || (() => Date.now());
    const doFetch = deps.fetch || (typeof fetch === 'function' ? (...a) => fetch(...a) : null);
    let index = null; // Set of website names, rebuilt from storage after a restart
    let meta = null;
    let loaded = null;
    let downloading = null;

    async function load() {
      if (!loaded) {
        loaded = (async () => {
          const saved = await deps.storage.get(storageKey);
          meta = { updatedAt: 0, lastAttempt: 0, lastError: '', entries: 0, ...((saved && saved.meta) || {}) };
          if (saved && typeof saved.text === 'string' && saved.text) index = new Set(saved.text.split('\n'));
        })();
      }
      return loaded;
    }

    async function download() {
      await load();
      meta.lastAttempt = now();
      try {
        if (!doFetch) throw new Error('no way to download');
        const response = await doFetch(source.url, { credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' });
        if (!response.ok) throw new Error(`${source.label}: the download answered ${response.status}`);
        const text = cleanList(await response.text());
        if (!text) throw new Error(`${source.label}: the list was empty`);
        meta = { updatedAt: now(), lastAttempt: now(), lastError: '', entries: text.split('\n').length };
        await deps.storage.set({ [storageKey]: { meta, text } });
        index = new Set(text.split('\n'));
      } catch (err) {
        meta.lastError = String((err && err.message) || err).slice(0, 200);
        const saved = (await deps.storage.get(storageKey)) || {};
        await deps.storage.set({ [storageKey]: { ...saved, meta } }).catch(() => {});
        throw err;
      }
    }

    function refreshIfNeeded(force = false) {
      if (downloading) return downloading;
      const due = force || !index || now() - meta.updatedAt >= REFRESH_MS;
      if (!due || (!force && meta.lastAttempt && now() - meta.lastAttempt < RETRY_MS)) return null;
      downloading = download().catch(() => {}).finally(() => { downloading = null; });
      return downloading;
    }

    return {
      label: source.label,
      // true / false, or throws when there is no list yet (still downloading, or it could not be downloaded).
      async match(parsed) {
        await load();
        refreshIfNeeded();
        if (!index) {
          if (downloading) await Promise.race([downloading, new Promise(r => setTimeout(r, 2500))]);
          if (!index) throw Object.assign(new Error(meta.lastError || `${source.label}: still downloading`), { userFacing: true });
        }
        return index.has(hostKey(parsed.hostname));
      },
      async refreshNow() {
        await load();
        await (refreshIfNeeded(true) || Promise.resolve());
        return this.status();
      },
      async status() {
        await load();
        return { ready: !!index, updatedAt: meta.updatedAt, entries: meta.entries, lastError: meta.lastError, downloading: !!downloading };
      },
    };
  }

  bg.domainFeed = { SOURCES, REFRESH_MS, RETRY_MS, cleanList, createFeed };
  if (typeof module !== 'undefined') module.exports = bg.domainFeed;
})();
