// threat-sync.js: gives the scam checks in this page the SAME known-threat
// list Chrome blocks with.
//
// The service worker builds the active list (the bundled list plus updates,
// minus expired entries and false positives someone removed) and saves it.
// This hands it to the engine, and keeps it up to date. Until it arrives, the
// engine uses the bundled data/threat-list.js.

// GranblockThreatSync.ready resolves once the saved list is in use (or there
// is none), for pages that check something straight away (ui/warning.js).

(() => {
  'use strict';
  const sync = globalThis.GranblockThreatSync = { ready: Promise.resolve() };
  if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.local) return; // practice pages
  const apply = list => GranblockCore.urlRules.useThreatEntries(Array.isArray(list) ? list : null);
  sync.ready = chrome.storage.local.get('activeThreats').then(items => apply(items.activeThreats)).catch(() => {});
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.activeThreats) apply(changes.activeThreats.newValue);
  });
})();
