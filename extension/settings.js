// settings.js: the person's choices, shared by every part of the extension.
// Saved in chrome.storage.local (on this computer only). Nothing here is ever sent anywhere.
//
// Plain choices only. No scores, weights, or files to edit.

const Settings = (() => {
  'use strict';

  const DEFAULTS = {
    enabled: true,          // protection on or off
    checkEmail: true,       // check emails opened in Gmail
    siteMode: 'all',        // 'all': check every website except offSites; 'chosen': only onSites
    offSites: [],           // websites the person turned off (used when siteMode is 'all')
    onSites: [],            // websites the person chose (used when siteMode is 'chosen')
    readAloud: 'button',    // 'off' | 'button' (a Read to me button) | 'auto' (read warnings out loud on their own)
    speechSpeed: 'normal',  // 'slow' | 'normal' | 'fast'
    textSize: 'large',      // 'normal' | 'large' | 'xlarge'
  };

  const CHOICES = {
    siteMode: ['all', 'chosen'],
    readAloud: ['off', 'button', 'auto'],
    speechSpeed: ['slow', 'normal', 'fast'],
    textSize: ['normal', 'large', 'xlarge'],
  };
  const TEXT_PX = { normal: 20, large: 24, xlarge: 28 };
  const SPEECH_RATE = { slow: 0.75, normal: 0.9, fast: 1.1 };
  const MAX_SITES = 200;

  // "https://www.Example.com/path?x" -> "example.com". Returns '' if it isn't a usable website name.
  function normalizeHost(input) {
    if (typeof input !== 'string') return '';
    let text = input.trim().toLowerCase();
    if (!text) return '';
    if (!/^[a-z][a-z0-9+.-]*:\/\//.test(text)) text = `https://${text}`;
    try {
      const host = new URL(text).hostname.replace(/^www\./, '').replace(/\.$/, '');
      return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(host) || host === 'localhost' ? host : '';
    } catch (e) {
      return '';
    }
  }

  function cleanList(list) {
    const out = [];
    for (const item of Array.isArray(list) ? list : []) {
      const host = normalizeHost(item);
      if (host && !out.includes(host) && out.length < MAX_SITES) out.push(host);
    }
    return out;
  }

  // Anything missing or invalid falls back to the default, so a damaged setting can't break protection.
  function normalize(raw) {
    const r = raw && typeof raw === 'object' ? raw : {};
    const out = { ...DEFAULTS };
    for (const key of ['enabled', 'checkEmail']) if (typeof r[key] === 'boolean') out[key] = r[key];
    for (const [key, allowed] of Object.entries(CHOICES)) if (allowed.includes(r[key])) out[key] = r[key];
    out.offSites = cleanList(r.offSites);
    out.onSites = cleanList(r.onSites);
    return out;
  }

  const matches = (list, host) => list.some(site => host === site || host.endsWith(`.${site}`));

  // Should the extension look at this website?
  function shouldCheckSite(settings, host) {
    host = normalizeHost(host) || String(host || '').toLowerCase();
    if (!settings.enabled || !host) return false;
    if (settings.siteMode === 'chosen') return matches(settings.onSites, host);
    return !matches(settings.offSites, host);
  }

  // Should the extension look at emails opened in Gmail?
  const shouldCheckEmail = settings => settings.enabled && settings.checkEmail;

  // The same site with the setting flipped, for the popup's "turn on/off for this site" button.
  function withSiteToggled(settings, host, on) {
    host = normalizeHost(host);
    const key = settings.siteMode === 'chosen' ? 'onSites' : 'offSites';
    const without = settings[key].filter(s => s !== host && !host.endsWith(`.${s}`));
    // In 'all' mode a site is on unless listed; in 'chosen' mode it is off unless listed.
    const listed = settings.siteMode === 'chosen' ? on : !on;
    return { [key]: listed ? without.concat(host) : without };
  }

  const api = { DEFAULTS, CHOICES, TEXT_PX, SPEECH_RATE, normalize, normalizeHost, shouldCheckSite, shouldCheckEmail, withSiteToggled, current: { ...DEFAULTS } };

  // ---- storage (only inside the extension) ----
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    api.load = async () => {
      const { settings } = await chrome.storage.local.get('settings');
      api.current = normalize(settings);
      return api.current;
    };
    api.save = async partial => {
      const next = normalize({ ...api.current, ...partial });
      await chrome.storage.local.set({ settings: next });
      api.current = next;
      return next;
    };
    api.reset = async () => api.save({ ...DEFAULTS, offSites: [], onSites: [] });
    // callback(newSettings) runs whenever settings change anywhere (popup, options page, another tab).
    api.onChange = callback => chrome.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes.settings) { api.current = normalize(changes.settings.newValue); callback(api.current); }
    });
    api.ready = api.load();
  } else {
    // Outside the extension (tests, practice pages opened as files): the defaults, never changing.
    api.ready = Promise.resolve(api.current);
    api.onChange = () => {};
  }
  return api;
})();

// Lets tests load this file with Node. Chrome ignores this.
if (typeof module !== 'undefined') {
  module.exports = Settings;
}
