// blocked.js: blocked.html, the extension's own warning page.
// (Chrome extensions can't run code written inside an .html file, so it lives here.)
//
// Two ways to get here:
//   blocked.html#known-phish.example  Chrome blocked a known dangerous website (service-worker.js)
//   blocked.html?t=TOKEN              OPEN_WARNING_PAGE: show an analyzer result saved under TOKEN
// A website can't change or fake this page, which is why it's the safest place for a warning.

let site = decodeURIComponent(window.location.hash.slice(1));
if (site) document.getElementById('site').textContent = site;

const token = new URLSearchParams(window.location.search).get('t');
if (token && chrome.storage && chrome.storage.session) {
  chrome.storage.session.get(`warning:${token}`).then(items => {
    const saved = items[`warning:${token}`];
    if (!saved) return;
    const { result, url } = saved;
    let host = '';
    try { host = new URL(url).hostname.replace(/^www\./, ''); } catch (e) { /* no address */ }
    site = host;
    if (result.verdict !== 'block') {
      document.getElementById('title').textContent = 'Stop and check this link';
      const where = document.getElementById('where');
      where.replaceChildren('This link really goes to: ', Object.assign(document.createElement('strong'), { textContent: host || 'an unknown address' }));
    } else if (host) {
      document.getElementById('site').textContent = host;
    }
    const list = document.getElementById('reasons');
    list.replaceChildren(...result.reasons.slice(0, 4).map(r => Object.assign(document.createElement('li'), { textContent: r.explanation || r.title || '' })));
    document.getElementById('why').hidden = !result.reasons.length;
    // Only a warning can be gone past, never a block.
    const go = document.getElementById('continue');
    go.hidden = result.verdict !== 'warn' || !/^https?:/.test(url);
    go.addEventListener('click', () => { window.location.href = url; });
  });
}

document.getElementById('back').addEventListener('click', () => {
  // Back to the page with the link. If there isn't one (the address was typed), close the tab.
  if (window.history.length > 1) window.history.back();
  else chrome.tabs.getCurrent(tab => chrome.tabs.remove(tab.id));
});

document.getElementById('read').addEventListener('click', () => {
  const advice = [...document.querySelectorAll('#advice li')].map(li => li.textContent);
  const reasons = [...document.querySelectorAll('#reasons li')].map(li => li.textContent);
  window.speechSynthesis.cancel();
  const speech = new SpeechSynthesisUtterance([
    document.getElementById('title').textContent,
    document.getElementById('where').textContent,
    ...reasons,
    'Here is what to do.',
    ...advice,
  ].join(' '));
  speech.rate = 0.9;
  window.speechSynthesis.speak(speech);
});
