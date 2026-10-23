// threat-rules.js: turns known-threat entries into Chrome's network-blocking rules.
//
// Chrome checks these rules BEFORE a page loads (declarativeNetRequest), so
// they stop typed addresses, redirects, and pop-ups too, not just clicks. They
// can only match addresses: they can't read what an ad says. That's still the
// analyzer's job.
//
// A threat entry: { type: 'domain' | 'url', value, source, trusted, addedAt, expiresAt? }
//   domain  a whole website and everything under it: "known-phish.example"
//   url     one address and everything below it: "https://hacked-blog.example/uploads/secure/"
//
// Only entries from a TRUSTED source become hard blocks. Others stay in the
// active list, so the click guard still warns, but Chrome never blocks them.
//
// This file only works things out; service-worker.js installs the rules.
// No chrome.* calls here, so tests can run it directly.

(function () {
  'use strict';
  const core = globalThis.GranblockCore = globalThis.GranblockCore || {};
  const bg = globalThis.GranblockBackground = globalThis.GranblockBackground || {};
  if (typeof require !== 'undefined' && !core.urlNormalizer) require('../core/url-normalizer.js');
  if (typeof require !== 'undefined' && !core.domainRules) require('../core/domain-rules.js');
  const { parseUrl, isPublicSuffix, isSameOrSubdomain } = core.urlNormalizer;
  const { officialBrandFor } = core.domainRules;

  // Above this many websites, one rule covers them all, and the blocked page
  // can't name the website. (Chrome limits how many redirect rules we may have.)
  const PER_SITE_RULE_LIMIT = 1000;
  const SUB_FRAME_CHUNK = 1000;

  // Reads one entry the same way the engine reads addresses. Returns
  // { entry } or { rejected: { value, reason } }.
  function normalizeEntry(raw) {
    const base = { source: raw.source || 'unknown', trusted: !!raw.trusted, addedAt: raw.addedAt || 0, expiresAt: raw.expiresAt || null };
    const value = String(raw.value || '').trim();
    const reject = reason => ({ rejected: { value, reason } });

    let hostname, url = null;
    if (raw.type === 'domain') {
      const parsed = parseUrl(`https://${value}/`);
      if (!parsed.ok || parsed.pathname !== '/' || /[/@:]/.test(value)) return reject('not a website name');
      hostname = parsed.hostname;
    } else if (raw.type === 'url') {
      const parsed = parseUrl(value);
      if (!parsed.ok || !parsed.isWeb) return reject('not a web address');
      if (parsed.pathname === '/' && !parsed.searchParams.toString()) return reject('a whole website: use type "domain"');
      hostname = parsed.hostname;
      url = `https://${hostname}${parsed.pathname}`;
    } else {
      return reject('type must be "domain" or "url"');
    }

    // Entries that would block far too much, or that are almost certainly a mistake.
    if (!hostname.includes('.') || hostname === 'localhost' || hostname.endsWith('.localhost')) return reject('too broad: not a public website');
    if (isPublicSuffix(hostname)) return reject('too broad: a whole website ending, shared by many owners');
    if (raw.type === 'domain' && officialBrandFor(hostname)) {
      return reject(`an official ${officialBrandFor(hostname).label} website: almost certainly a false positive`);
    }
    return { entry: { type: raw.type, value: raw.type === 'domain' ? hostname : url, hostname, ...base } };
  }

  // Is this entry removed by the allowlist (false positives someone removed)?
  //   allowlist  website names or addresses
  function isAllowlisted(entry, allowlist) {
    return (allowlist || []).some(allowed => {
      const a = String(allowed).trim().toLowerCase();
      if (!a) return false;
      if (a.includes('/')) return entry.type === 'url' && entry.value.startsWith(a.replace(/^http:/, 'https:'));
      return isSameOrSubdomain(entry.hostname, a);
    });
  }

  // Works out the active list: every entry that should count right now.
  //   lists      arrays of raw entries (bundled list, updates)
  //   allowlist  false positives to remove
  //   now        current time (ms)
  // Returns { entries, rejected: [{ value, reason }] }
  function activeEntries(lists, { allowlist = [], now = Date.now() } = {}) {
    const byKey = new Map();
    const rejected = [];
    for (const raw of lists.flat()) {
      const { entry, rejected: r } = normalizeEntry(raw);
      if (r) { rejected.push(r); continue; }
      if (entry.expiresAt && entry.expiresAt <= now) { rejected.push({ value: entry.value, reason: 'expired' }); continue; }
      if (isAllowlisted(entry, allowlist)) { rejected.push({ value: entry.value, reason: 'removed as a false positive (allowlist)' }); continue; }
      const key = `${entry.type}|${entry.value}`;
      const existing = byKey.get(key);
      // Duplicates: keep one. A trusted copy wins; then the one that lasts longest.
      if (!existing || (entry.trusted && !existing.trusted) ||
          (entry.trusted === existing.trusted && (entry.expiresAt === null || (existing.expiresAt !== null && entry.expiresAt > existing.expiresAt)))) {
        byKey.set(key, entry);
      }
    }
    // A single address already covered by a whole-website entry adds nothing.
    const entries = [...byKey.values()];
    const domains = entries.filter(e => e.type === 'domain');
    const kept = entries.filter(e => e.type === 'domain' ||
      !domains.some(d => isSameOrSubdomain(e.hostname, d.value) && (d.trusted || !e.trusted)));
    kept.sort((a, b) => a.type.localeCompare(b.type) || a.value.localeCompare(b.value));
    return { entries: kept, rejected };
  }

  // The entries as Chrome rules. Only trusted entries become rules.
  //   blockPage    the extension's blocked page address
  //   canRedirect  false when the person hasn't given website access: Chrome
  //                only sends a page to our blocked page with that access, but
  //                it can always stop it outright (Chrome shows its own error
  //                page instead). Either way the dangerous page never loads.
  // Returns an array of rules with ids 1, 2, 3...
  function buildRules(entries, blockPage, { canRedirect = true } = {}) {
    const trusted = entries.filter(e => e.trusted);
    const domains = trusted.filter(e => e.type === 'domain').map(e => e.value);
    const urls = trusted.filter(e => e.type === 'url');
    const rules = [];
    const add = (action, condition) => rules.push({ id: rules.length + 1, priority: 1, action, condition });
    const redirectTo = site => (canRedirect ? { type: 'redirect', redirect: { url: `${blockPage}#${encodeURIComponent(site)}` } } : { type: 'block' });

    // Whole websites. The page you were trying to open -> our blocked page.
    if (domains.length <= PER_SITE_RULE_LIMIT) {
      for (const d of domains) add(redirectTo(d), { requestDomains: [d], resourceTypes: ['main_frame'] });
    } else {
      add(canRedirect ? { type: 'redirect', redirect: { url: blockPage } } : { type: 'block' }, { requestDomains: domains, resourceTypes: ['main_frame'] });
    }
    // Inside a frame on another page (like an ad): just don't load it.
    for (let i = 0; i < domains.length; i += SUB_FRAME_CHUNK) {
      add({ type: 'block' }, { requestDomains: domains.slice(i, i + SUB_FRAME_CHUNK), resourceTypes: ['sub_frame'] });
    }

    // Single addresses: that address and everything below it, nothing else on
    // the website. "|" anchors the start or end; "http*" covers http and https.
    for (const e of urls) {
      const path = new URL(e.value).pathname;
      const start = `|http*://${e.hostname}${path}`;
      const filters = path.endsWith('/') ? [start] : [`${start}|`, `${start}/`, `${start}?`, `${start}#`];
      for (const urlFilter of filters) {
        add(redirectTo(e.hostname), { urlFilter, requestDomains: [e.hostname], resourceTypes: ['main_frame'] });
        add({ type: 'block' }, { urlFilter, requestDomains: [e.hostname], resourceTypes: ['sub_frame'] });
      }
    }
    return rules;
  }

  // The active list in the shape the engine uses (urlRules.useThreatEntries).
  function forEngine(entries) {
    return entries.map(({ type, value, source, trusted, expiresAt }) => ({ type, value, source, trusted, expiresAt }));
  }

  bg.threatRules = { PER_SITE_RULE_LIMIT, normalizeEntry, isAllowlisted, activeEntries, buildRules, forEngine };
  if (typeof module !== 'undefined') module.exports = bg.threatRules;
})();
