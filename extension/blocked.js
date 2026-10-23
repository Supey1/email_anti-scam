// blocked.js: the buttons on blocked.html.
// (Chrome extensions can't run code written inside an .html file, so it lives here.)

const site = decodeURIComponent(window.location.hash.slice(1));
if (site) document.getElementById('site').textContent = site;

document.getElementById('back').addEventListener('click', () => {
  // Back to the page with the link. If there isn't one (the address was typed), close the tab.
  if (window.history.length > 1) window.history.back();
  else chrome.tabs.getCurrent(tab => chrome.tabs.remove(tab.id));
});

document.getElementById('read').addEventListener('click', () => {
  const advice = [...document.querySelectorAll('#advice li')].map(li => li.textContent);
  window.speechSynthesis.cancel();
  const speech = new SpeechSynthesisUtterance([
    'Stop. We blocked a dangerous website.',
    `The website ${site || ''} is on a list of known dangerous websites.`,
    'Here is what to do.',
    ...advice,
  ].join(' '));
  speech.rate = 0.9;
  window.speechSynthesis.speak(speech);
});
