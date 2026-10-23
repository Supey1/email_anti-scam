// settings-sync.js: the person's reading and text settings, for the screens
// shown inside web pages (the warning and the Gmail panel).
//
// The settings live in chrome.storage.local (the service worker owns them;
// settings.html changes them). This reads them, keeps them up to date, and
// falls back to the defaults on practice pages or if storage can't be read.

const GranblockSettings = (() => {
  'use strict';
  const DEFAULTS = { textSize: 'large', autoRead: false, speechRate: 0.9 };
  const ZOOM = { large: 1, larger: 1.2, largest: 1.45 };
  let current = { ...DEFAULTS };
  const listeners = new Set();

  function apply(saved) {
    current = { ...DEFAULTS, ...(saved && typeof saved === 'object' ? saved : {}) };
    listeners.forEach(fn => { try { fn(current); } catch (e) { /* keep going */ } });
  }

  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.get('settings').then(items => apply(items.settings)).catch(() => {});
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area === 'local' && changes.settings) apply(changes.settings.newValue);
    });
  }

  return {
    get: () => current,
    zoom: () => ZOOM[current.textSize] || 1,
    onChange: fn => { listeners.add(fn); return () => listeners.delete(fn); },
  };
})();
