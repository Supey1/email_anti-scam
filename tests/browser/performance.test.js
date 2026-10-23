// Performance measurements, in real Chromium with the real extension. Run with:  node tests/browser/performance.test.js
// Records how long the extension takes and how much it blocks the page's main thread. Budgets are generous on purpose
// (this machine is not a person's old laptop); they catch a regression, not a goal. Results: tests/results/performance.json

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { launch } = require('./harness');
const { analyze } = require('../../extension/analyzer.js');
const cases = require('../corpus/cases.js');
const { run: runCase } = require('../metrics.js');

const EXT = path.join(__dirname, '..', '..', 'extension');
const BUDGET = { scanMs: 500, analyzeMs: 50, clickMs: 25, longestTaskMs: 700, stormTasksPer5s: 12 };
const measures = {};
const problems = [];
const record = (label, value, ok = true, why = '') => { measures[label] = value; if (!ok) problems.push(`${label}: ${value} (${why})`); };

// A page with thousands of links, a lot of text, and many ads.
const huge = () => {
  const links = Array.from({ length: 5000 }, (_, i) => `<a href="https://site${i % 300}.example/p${i}">link ${i}</a>`).join(' ');
  const ads = Array.from({ length: 150 }, (_, i) => `<div class="ad-slot"><p>Sale ${i}: great prices on things.</p><a href="https://shop${i}.example/s">Shop</a></div>`).join('');
  return `<!doctype html><title>Huge page</title><body><p>${'lorem ipsum dolor sit amet '.repeat(8000)}</p>${links}${ads}<div id="storm"></div>`;
};

const LONGTASKS = () => {
  window.__tasks = [];
  new PerformanceObserver(list => { for (const e of list.getEntries()) window.__tasks.push(e.duration); }).observe({ type: 'longtask', buffered: true });
};

(async () => {
  // ---------- analyzer speed (Node) ----------
  const timings = [];
  for (let round = 0; round < 20; round++) for (const c of cases) { const t = process.hrtime.bigint(); runCase(c); timings.push(Number(process.hrtime.bigint() - t) / 1e6); }
  timings.sort((a, b) => a - b);
  const avg = timings.reduce((a, b) => a + b, 0) / timings.length;
  record('Analyzer: average per check (Node)', `${avg.toFixed(3)} ms`, avg < BUDGET.analyzeMs, `budget ${BUDGET.analyzeMs} ms`);
  record('Analyzer: slowest 1% (Node)', `${timings[Math.floor(timings.length * 0.99)].toFixed(3)} ms`);

  const env = await launch();
  const page = await env.context.newPage();
  await page.addInitScript(LONGTASKS);
  await page.route('https://perf.example/**', route => route.fulfill({ contentType: 'text/html', body: huge() }));

  // ---------- load a huge page with the extension running ----------
  await page.goto('https://perf.example/');
  await page.waitForTimeout(3000);
  const loadTasks = await page.evaluate(() => window.__tasks.slice());
  const longest = Math.max(0, ...loadTasks);
  record('Huge page (5000 links, 150 ads, ~40k words): longest main-thread block while loading', `${longest.toFixed(0)} ms`, longest < BUDGET.longestTaskMs, `budget ${BUDGET.longestTaskMs} ms`);
  record('Huge page: number of long tasks (over 50 ms) while loading', String(loadTasks.length));

  // ---------- the scanner and analyzer on that page, timed in the page itself ----------
  for (const f of ['rules.js', 'threats.js', 'analyzer.js', 'content/ad-signals.js', 'content/page-scanner.js']) await page.addScriptTag({ path: path.join(EXT, f) });
  const inPage = await page.evaluate(() => {
    const t0 = performance.now();
    let evidence;
    const s = PageScanner.start({ onEvidence: e => { evidence = e; } });
    const scanMs = performance.now() - t0;
    s.stop();
    const t1 = performance.now();
    const result = analyze(evidence);
    const analyzeMs = performance.now() - t1;
    // What happens on one click: ad context plus link analysis.
    const anchor = document.querySelector('.ad-slot a');
    const t2 = performance.now();
    for (let i = 0; i < 100; i++) analyzeLink({ text: anchor.textContent, href: anchor.href }, { ad: AdSignals.contextFor(anchor) });
    const clickMs = (performance.now() - t2) / 100;
    return { scanMs, analyzeMs, clickMs, links: evidence.links.length, ads: evidence.context.ads.length, textChars: evidence.visibleText.length, verdict: result.verdict };
  });
  record('Scanner: first scan of the huge page', `${inPage.scanMs.toFixed(0)} ms (kept ${inPage.links} links, ${inPage.ads} ads, ${inPage.textChars} characters)`, inPage.scanMs < BUDGET.scanMs, `budget ${BUDGET.scanMs} ms`);
  record('Analyzer: that page\'s evidence, in the browser', `${inPage.analyzeMs.toFixed(1)} ms`, inPage.analyzeMs < BUDGET.analyzeMs, `budget ${BUDGET.analyzeMs} ms`);
  record('Click guard: work done on one click, on that page', `${inPage.clickMs.toFixed(2)} ms`, inPage.clickMs < BUDGET.clickMs, `budget ${BUDGET.clickMs} ms`);

  // ---------- constantly changing ads: 1000 insertions over 5 seconds ----------
  await page.evaluate(() => { window.__tasks.length = 0; });
  await page.evaluate(() => new Promise(resolve => {
    let n = 0;
    const timer = setInterval(() => {
      const d = document.createElement('div');
      d.className = 'ad-slot';
      d.innerHTML = `<p>Rotating ad ${n} with some words in it.</p><a href="https://rot${n}.example/x">Open</a>`;
      document.getElementById('storm').append(d);
      if (++n >= 1000) { clearInterval(timer); resolve(); }
    }, 5);
  }));
  await page.waitForTimeout(2500);
  const stormTasks = await page.evaluate(() => window.__tasks.slice());
  record('Changing ads (1000 insertions in ~5 s): long tasks', `${stormTasks.length}, longest ${Math.max(0, ...stormTasks).toFixed(0)} ms`, stormTasks.length <= BUDGET.stormTasksPer5s, `budget ${BUDGET.stormTasksPer5s}`);

  await env.close();
  fs.writeFileSync(path.join(__dirname, '..', 'results', 'performance.json'), JSON.stringify({ measures, budgets: BUDGET }, null, 2) + '\n');
  for (const [k, v] of Object.entries(measures)) console.log(`${k}: ${v}`);
  console.log(problems.length ? `\nFAIL  over budget:\n  ${problems.join('\n  ')}` : '\nAll performance budgets held');
  process.exit(problems.length ? 1 : 0);
})();
