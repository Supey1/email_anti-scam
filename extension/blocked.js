// blocked.js: blocked.html, the extension's own warning page.
// (Chrome extensions can't run code written inside an .html file, so it lives here.)
//
// Two ways to get here:
//   blocked.html#known-phish.example  Chrome blocked a known dangerous website (background/threat-rules.js)
//   blocked.html?t=TOKEN              OPEN_WARNING_PAGE: show an analyzer result saved under TOKEN (a risky click)
// A website can't change or fake this page. It is built from the same warning interface as the in-page card,
// so the same result reads the same everywhere. A "block" has no way through; a "warn" can be continued past.

(async () => {
  'use strict';

  const style = document.createElement('style');
  style.textContent = PANEL_CSS + WARNING_CSS + `
    body { margin: 0; background: #f4f4f4; }
    .card { margin: 32px auto; }`;
  document.head.append(style);

  const token = new URLSearchParams(location.search).get('t');
  const hostFromHash = decodeURIComponent(location.hash.slice(1));

  async function savedWarning() {
    if (!token || !chrome.storage || !chrome.storage.session) return null;
    try { return (await chrome.storage.session.get(`warning:${token}`))[`warning:${token}`] || null; } catch (e) { return null; }
  }

  // A site Chrome blocked on the way in: the engine's own answer for that address, or a plain block if it can't reproduce it.
  function resultForBlockedHost(host) {
    const asked = analyze({ source: 'link', pageUrl: '', pageTitle: '', visibleText: '', links: [{ text: '', url: `https://${host}/` }], forms: [], context: {} });
    if (asked.verdict === 'block') return asked;
    return {
      schemaVersion: 1, verdict: 'block', recommendedAction: 'GO_BACK', evidence: [],
      reasons: [{ code: 'KNOWN_THREAT', title: 'Known dangerous website', explanation: `${host} is on a list of known dangerous websites. It may try to steal passwords or money.` }],
    };
  }

  const saved = await savedWarning();
  const settings = (await chrome.storage.local.get('settings').catch(() => ({}))).settings || {};
  const prefs = { textSize: 'large', autoRead: false, speechRate: 0.9, ...settings };
  const zoom = { large: 1, larger: 1.2, largest: 1.45 }[prefs.textSize] || 1;

  let result, url = '', linkText = '', host = hostFromHash;
  if (saved) {
    ({ result, url, linkText = '' } = saved);
    try { host = new URL(url).hostname.replace(/^www\./, ''); } catch (e) { host = ''; }
  } else if (hostFromHash) {
    result = resultForBlockedHost(hostFromHash);
  } else {
    result = { schemaVersion: 1, verdict: 'unknown', reasons: [], recommendedAction: 'NONE', evidence: [] };
  }

  // Say what the link CLAIMED and where it REALLY goes, side by side: seeing both is what makes a
  // "hidden destination" warning make sense.
  function destinationLines() {
    if (!host) return [];
    if (!saved) return [`This address was blocked: ${host}`];
    const said = linkText.replace(/\s+/g, ' ').trim().slice(0, 100);
    return [said ? `You clicked a link that says: “${said}”` : 'You clicked a link', `It really goes to: ${host}`];
  }

  function leave() {
    if (history.length > 1) history.back();
    else chrome.tabs.getCurrent(tab => { if (tab) chrome.tabs.remove(tab.id); else location.replace('about:blank'); });
  }

  const model = Explain.describe(result);
  const { card, primary, speakNow } = WarningView.render(model, {
    key: `blocked|${location.search}${location.hash}`,
    rate: () => prefs.speechRate,
    textSizePx: 24 * zoom,
    destination: destinationLines(),
    onBack: leave,
    // Only a warning can be gone past, never a block.
    onContinue: /^https?:/.test(url) ? () => { location.href = url; } : null,
    onReport: () => chrome.runtime.sendMessage({ type: 'REPORT_FALSE_ALARM', schemaVersion: 1, report: { host, verdict: model.verdict, reasons: model.top.map(r => r.explanation), source: 'warning-page' } }).catch(() => {}),
  });
  document.getElementById('root').append(card);
  document.title = `${model.label}: ${model.headline}`;
  primary.focus();
  if (prefs.autoRead && (model.verdict === 'warn' || model.verdict === 'block')) speakNow();
})();
