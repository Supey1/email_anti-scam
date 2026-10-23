// warning.js: the extension-owned warning page.
// A suspicious website can't remove or change this page the way it could an in-page panel.
//
// Reached two ways:
//   ui/warning.html?kind=dnr&url=<address>                      a known-dangerous site was blocked on the way in
//   ui/warning.html?kind=click&intent=same|tab&text=..&url=..   click-guard.js stopped a click on a link
// The page checks the address again itself (it does not trust the link's own claims about
// the verdict), so a block always stays a block and has no "continue" button.

(async () => {
  'use strict';
  await Settings.ready;

  const search = location.search;
  const at = search.indexOf('&url=');
  const params = new URLSearchParams(at === -1 ? search : search.slice(0, at));
  let target = at === -1 ? '' : search.slice(at + 5);
  try { target = decodeURIComponent(target); } catch (e) { /* use it as it is */ }
  const text = params.get('text') || '';

  const style = document.createElement('style');
  style.textContent = PANEL_CSS + WARNING_CSS + `
    body { margin: 0; background: #f4f4f4; }
    .card { margin: 32px auto; }
    .page-footer { text-align: center; color: #444; font: 16px Arial, sans-serif; margin: 12px; }`;
  document.head.append(style);

  const adText = params.get('adtext') || '';
  const result = analyzeLink({ text, href: target }, adText ? { ad: { text: adText, signals: [] } } : undefined);
  const model = Explain.describe(result);
  let host = result.host || '';
  try { host = new URL(target).hostname; } catch (e) { /* keep what the analyzer gave */ }

  // Say what the link CLAIMED and where it REALLY goes, side by side. Seeing both is what makes a
  // "hidden destination" warning make sense.
  function destinationLines() {
    if (!host) return [];
    if (params.get('kind') !== 'click') return [`This address was blocked: ${host}`];
    const said = text.replace(/\s+/g, ' ').trim().slice(0, 100);
    return [said ? `You clicked a link that says: \u201c${said}\u201d` : 'You clicked a link', `It really goes to: ${host}`];
  }

  function leave() {
    window.speechSynthesis.cancel();
    if (history.length > 1) { history.back(); return; }
    // Opened in its own tab: close that tab.
    chrome.tabs.getCurrent(tab => { if (tab) chrome.tabs.remove(tab.id); else location.replace('about:blank'); });
  }

  const prefs = Settings.current;
  const { card, primary, startReading } = WarningView.render(model, {
    textSizePx: Settings.TEXT_PX[prefs.textSize],
    speechRate: Settings.SPEECH_RATE[prefs.speechSpeed],
    showRead: prefs.readAloud !== 'off',
    destination: destinationLines(),
    onBack: leave,
    onContinue: () => chrome.runtime.sendMessage({ type: 'CONTINUE', url: target, text }),
    onReport: () => chrome.runtime.sendMessage({ type: 'REPORT_FALSE_ALARM', report: { host, verdict: model.verdict, reasons: model.top.map(r => r.explanation), source: 'warning-page' } }),
  });
  document.getElementById('root').append(card);
  document.title = `${model.label}: ${model.headline}`;
  primary.focus();
  if (prefs.readAloud === 'auto' && (model.verdict === 'warn' || model.verdict === 'block')) startReading();
})();
