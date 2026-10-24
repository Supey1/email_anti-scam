// content-scripts.js: which scripts run in which pages, decided by what the
// person has allowed.
//
// The extension asks for website access during onboarding (ui/options.html?welcome=1),
// not at install, and the person can take it back at any time in Chrome. So
// the scripts aren't listed in manifest.json; the service worker registers
// them for exactly the access that's been granted, and removes them when
// protection is turned off or access is taken away.
//
//   access 'all'    every website, ads and Gmail included
//   access 'gmail'  Gmail only (the person chose to protect just their email)
//   access 'none'   no scripts at all (known dangerous websites are still blocked by Chrome)
//
// No chrome.* calls here, so tests can run it directly.

(function () {
  'use strict';
  const bg = globalThis.GranblockBackground = globalThis.GranblockBackground || {};

  const ALL_SITES = ['http://*/*', 'https://*/*'];
  const GMAIL = ['https://mail.google.com/*'];

  // The scam checks (Person A), in this order.
  const ENGINE = [
    'data/threat-list.js', 'data/addresses.js', 'data/companies.js', 'data/services.js', 'data/people.js',
    'core/url-normalizer.js', 'core/domain-rules.js', 'core/url-rules.js', 'core/text-rules.js',
    'core/risk-policy.js', 'core/explanations.js', 'core/analyzer.js', 'rules.js', 'threat-sync.js',
  ];
  // Everywhere, in every frame (ads often load in their own frame): the engine,
  // the shared warning interface, and the click guard (Person B).
  const BASE = [
    ...ENGINE,
    'settings.js', 'speech.js', 'panel-styles.js', 'ui/explain.js', 'ui/warning-view.js', 'panel.js',
    'content/ad-signals.js', 'content/click-guard.js',
  ];
  // Ordinary websites, main page only: the page scanner and its glue.
  const PAGE = ['content/page-scanner.js', 'page.js'];
  // Gmail: reads the open email.
  const GMAIL_READER = ['content/gmail-adapter.js', 'content/gmail.js'];

  // The scripts that should be registered for this access.
  function desiredScripts(access, protectionEnabled) {
    if (!protectionEnabled || (access !== 'all' && access !== 'gmail')) return [];
    const scripts = [{
      id: 'granblock-guard',
      matches: access === 'all' ? ALL_SITES : GMAIL,
      js: BASE,
      allFrames: true,
      matchOriginAsFallback: true,
      runAt: 'document_start',
      persistAcrossSessions: true,
    }];
    if (access === 'all') {
      scripts.push({ id: 'granblock-page', matches: ALL_SITES, excludeMatches: GMAIL, js: PAGE, runAt: 'document_idle', persistAcrossSessions: true });
    }
    scripts.push({ id: 'granblock-gmail', matches: GMAIL, js: GMAIL_READER, runAt: 'document_idle', persistAcrossSessions: true });
    return scripts;
  }

  // What the person has allowed, from Chrome's permission check.
  //   permissions  { contains({ origins }) -> Promise<boolean> }   (chrome.permissions)
  async function currentAccess(permissions) {
    try {
      if (await permissions.contains({ origins: ALL_SITES })) return 'all';
      if (await permissions.contains({ origins: GMAIL })) return 'gmail';
    } catch (e) { /* treat as no access */ }
    return 'none';
  }

  // Makes the registered scripts match what's wanted, touching only what changed.
  //   scripting  { getRegisteredContentScripts(), registerContentScripts([...]), unregisterContentScripts({ ids }) }
  // Returns the ids now registered.
  async function syncScripts(scripting, wanted) {
    const registered = await scripting.getRegisteredContentScripts();
    const ours = registered.filter(s => s.id.startsWith('granblock-'));
    const same = (a, b) => JSON.stringify([a.matches, a.excludeMatches || [], a.js, !!a.allFrames, a.runAt]) ===
      JSON.stringify([b.matches, b.excludeMatches || [], b.js, !!b.allFrames, b.runAt]);
    const keep = new Set(wanted.filter(w => ours.some(r => r.id === w.id && same(r, w))).map(w => w.id));
    const remove = ours.filter(r => !keep.has(r.id)).map(r => r.id);
    if (remove.length) await scripting.unregisterContentScripts({ ids: remove });
    const add = wanted.filter(w => !keep.has(w.id));
    if (add.length) await scripting.registerContentScripts(add);
    return wanted.map(w => w.id);
  }

  bg.contentScripts = { ALL_SITES, GMAIL, ENGINE, BASE, PAGE, GMAIL_READER, desiredScripts, currentAccess, syncScripts };
  if (typeof module !== 'undefined') module.exports = bg.contentScripts;
})();
