// phishtank-feed.js: PhishTank's downloadable list of verified phishing addresses, kept on this
// computer and checked here. Looking an address up sends NOTHING anywhere; the only network
// traffic is downloading the whole list (https://data.phishtank.com/data/online-valid.csv.gz),
// which is the same for everyone and says nothing about what you browse.
//
// The list is updated hourly by PhishTank. We refresh it when it is older than REFRESH_MS, at
// most once per RETRY_MS, and keep the old copy if a download fails (PhishTank allows only a
// few downloads a day without an application key, so errors are expected sometimes).
//
// Entries ("verified" and "online" are always yes in this file):
//   an address with no path ("https://evil.example/")  -> the whole website and its subdomains
//   an address with a path                             -> that address and anything after "?"
//   an address with a ?query                           -> only that exact query
// Official company websites are never a whole-site match (a feed listing paypal.com is a mistake).
//
// No chrome.* calls here: storage and fetch are passed in, so tests can run it directly.

(function () {
  'use strict';
  const core = globalThis.GranblockCore = globalThis.GranblockCore || {};
  const bg = globalThis.GranblockBackground = globalThis.GranblockBackground || {};
  if (typeof require !== 'undefined' && !core.urlNormalizer) require('../core/url-normalizer.js');
  if (typeof require !== 'undefined' && !core.domainRules) require('../core/domain-rules.js');
  const { isPublicSuffix, publicSuffix } = core.urlNormalizer;

  const FEED_URL = 'https://data.phishtank.com/data/online-valid.csv.gz';
  const REFRESH_MS = 6 * 60 * 60 * 1000;
  const RETRY_MS = 60 * 60 * 1000;
  const MAX_ENTRIES = 300000;
  const STORAGE_KEY = 'phishtankFeed';

  // CSV with quoted fields and commas or line breaks inside quotes. Returns an array of rows.
  function parseCsv(text) {
    const rows = [];
    let row = [];
    let field = '';
    let quoted = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (quoted) {
        if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else quoted = false; } else field += c;
      } else if (c === '"') quoted = true;
      else if (c === ',') { row.push(field); field = ''; }
      else if (c === '\n' || c === '\r') {
        if (c === '\r' && text[i + 1] === '\n') i++;
        row.push(field); field = '';
        if (row.length > 1 || row[0] !== '') rows.push(row);
        row = [];
      } else field += c;
    }
    if (field !== '' || row.length) { row.push(field); rows.push(row); }
    return rows;
  }

  const hostKey = hostname => hostname.replace(/^www\./, '');
  const cleanPath = pathname => (pathname.length > 1 ? pathname.replace(/\/+$/, '') : '') || '/';

  // Rows of the feed -> { hosts: [], urls: [] }.
  function buildIndex(rows) {
    const header = rows[0] || [];
    const col = name => header.indexOf(name);
    const urlCol = col('url');
    const verifiedCol = col('verified');
    const onlineCol = col('online');
    if (urlCol < 0) throw new Error('unreadable list');
    const hosts = new Set();
    const urls = new Set();
    for (let i = 1; i < rows.length && hosts.size + urls.size < MAX_ENTRIES; i++) {
      const row = rows[i];
      if ((verifiedCol >= 0 && row[verifiedCol] !== 'yes') || (onlineCol >= 0 && row[onlineCol] !== 'yes')) continue;
      let url;
      try { url = new URL(String(row[urlCol] || '').trim()); } catch (e) { continue; }
      if (url.protocol !== 'http:' && url.protocol !== 'https:') continue;
      const host = hostKey(url.hostname.toLowerCase().replace(/\.+$/, ''));
      if (!host.includes('.')) continue;
      const path = cleanPath(url.pathname);
      if (path === '/' && !url.search) {
        if (isPublicSuffix(host) || core.domainRules.officialBrandFor(host)) continue;
        hosts.add(host);
      } else {
        urls.add(`${host}${path}${url.search}`);
      }
    }
    return { hosts: [...hosts], urls: [...urls] };
  }

  // Is this address (parsed with urlNormalizer) in the index? { hosts: Set, urls: Set }
  function matchIn(index, parsed) {
    let url;
    try { url = new URL(parsed.href); } catch (e) { return false; }
    const host = hostKey(url.hostname.toLowerCase().replace(/\.+$/, ''));
    const path = cleanPath(url.pathname);
    if (index.urls.has(`${host}${path}${url.search}`) || index.urls.has(`${host}${path}`)) return true;
    // The website itself, or any website below a listed one ("login.evil.example" under "evil.example").
    const stop = publicSuffix(host);
    for (let h = host; h && h !== stop; h = h.includes('.') ? h.slice(h.indexOf('.') + 1) : '') {
      if (index.hosts.has(h)) return true;
    }
    return false;
  }

  async function gunzipIfNeeded(response) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes[0] === 0x1f && bytes[1] === 0x8b) {
      return new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
    }
    return new TextDecoder().decode(bytes);
  }

  // deps: { storage: { get(key), set(object) }, fetch, now() }
  function createFeed(deps) {
    const now = deps.now || (() => Date.now());
    const doFetch = deps.fetch || (typeof fetch === 'function' ? (...a) => fetch(...a) : null);
    let index = null;      // { hosts: Set, urls: Set } in memory, rebuilt from storage after a restart
    let meta = null;       // { updatedAt, lastAttempt, lastError, entries }
    let loaded = null;
    let downloading = null;

    async function load() {
      if (!loaded) {
        loaded = (async () => {
          const saved = await deps.storage.get(STORAGE_KEY);
          meta = { updatedAt: 0, lastAttempt: 0, lastError: '', entries: 0, ...((saved && saved.meta) || {}) };
          if (saved && Array.isArray(saved.hosts) && Array.isArray(saved.urls)) index = { hosts: new Set(saved.hosts), urls: new Set(saved.urls) };
        })();
      }
      return loaded;
    }
    async function saveMeta() {
      const saved = (await deps.storage.get(STORAGE_KEY)) || {};
      await deps.storage.set({ [STORAGE_KEY]: { ...saved, meta } });
    }

    // Downloads and replaces the list. Keeps the old one if anything goes wrong.
    async function download(appKey) {
      await load();
      meta.lastAttempt = now();
      try {
        if (!doFetch) throw new Error('no way to download');
        const url = appKey ? `https://data.phishtank.com/data/${encodeURIComponent(appKey)}/online-valid.csv.gz` : FEED_URL;
        const response = await doFetch(url, { credentials: 'omit', cache: 'no-store', referrerPolicy: 'no-referrer' });
        if (response.status === 429 || response.status === 509) throw new Error('PhishTank allows only a few downloads a day without an application key. It will try again later.');
        if (!response.ok) throw new Error(`PhishTank answered ${response.status}`);
        const built = buildIndex(parseCsv(await gunzipIfNeeded(response)));
        if (!built.hosts.length && !built.urls.length) throw new Error('the list was empty');
        meta = { updatedAt: now(), lastAttempt: now(), lastError: '', entries: built.hosts.length + built.urls.length };
        await deps.storage.set({ [STORAGE_KEY]: { meta, hosts: built.hosts, urls: built.urls } });
        index = { hosts: new Set(built.hosts), urls: new Set(built.urls) };
      } catch (err) {
        meta.lastError = String((err && err.message) || err).slice(0, 200);
        await saveMeta().catch(() => {});
        throw err;
      }
    }

    // Starts a download if the list is old and one hasn't just failed. Never throws.
    function refreshIfNeeded(appKey, force = false) {
      if (downloading) return downloading;
      const due = force || !index || now() - meta.updatedAt >= REFRESH_MS;
      if (!due || (!force && meta.lastAttempt && now() - meta.lastAttempt < RETRY_MS)) return null;
      downloading = download(appKey).catch(() => {}).finally(() => { downloading = null; });
      return downloading;
    }

    return {
      // true / false, or throws when there is no list yet (still downloading, or it could not be downloaded).
      async match(parsed, { appKey } = {}) {
        await load();
        refreshIfNeeded(appKey);
        if (!index) {
          if (downloading) await Promise.race([downloading, new Promise(r => setTimeout(r, 2500))]);
          if (!index) throw new Error(meta.lastError || 'the PhishTank list is still downloading');
        }
        return matchIn(index, parsed);
      },
      async refreshNow(appKey) {
        await load();
        await (refreshIfNeeded(appKey, true) || Promise.resolve());
        return this.status();
      },
      async status() {
        await load();
        return { ready: !!index, updatedAt: meta.updatedAt, entries: meta.entries, lastError: meta.lastError, downloading: !!downloading };
      },
      forget: async () => { await load(); index = null; meta = { updatedAt: 0, lastAttempt: 0, lastError: '', entries: 0 }; await deps.storage.set({ [STORAGE_KEY]: { meta } }); },
    };
  }

  bg.phishtankFeed = { FEED_URL, REFRESH_MS, RETRY_MS, parseCsv, buildIndex, matchIn, createFeed };
  if (typeof module !== 'undefined') module.exports = bg.phishtankFeed;
})();
