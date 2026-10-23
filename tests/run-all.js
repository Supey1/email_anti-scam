// Runs every automated test and prints one summary.  node tests/run-all.js [--no-browser]
// Browser tests need Playwright (npm install) and Chromium (set CHROMIUM_PATH if Playwright cannot find it).
// They run one after another because each one starts its own browser.

const { spawnSync } = require('child_process');
const path = require('path');

// The scam checks (Person A), then the screens and settings (Person B).
const node = ['contract', 'rules', 'regression', 'robustness', 'service-worker', 'screens', 'explain', 'scanner-merge', 'settings', 'usability-score']
  .map(n => `tests/${n}.test.js`).concat('tests/metrics.js');
const browser = ['blocking', 'scanner', 'click-guard', 'ads', 'gmail-adapter', 'settings', 'systematic', 'click-matrix', 'performance'].map(n => `tests/browser/${n}.test.js`);

const files = process.argv.includes('--no-browser') ? node : node.concat(browser);
const summary = [];
for (const file of files) {
  const started = Date.now();
  const run = spawnSync(process.execPath, [file], { cwd: path.join(__dirname, '..'), encoding: 'utf8', env: process.env, timeout: 15 * 60 * 1000 });
  const out = (run.stdout || '') + (run.stderr || '');
  const skipped = /^SKIP /m.test(out);
  const tally = out.trim().split('\n').filter(l => /passed|failed|held/i.test(l)).pop() || '';
  summary.push({ file, ok: run.status === 0, skipped, seconds: ((Date.now() - started) / 1000).toFixed(0) });
  console.log(`${run.status === 0 ? (skipped ? 'SKIP' : 'PASS') : 'FAIL'}  ${file.padEnd(36)} ${tally}  (${summary[summary.length - 1].seconds}s)`);
  if (run.status !== 0) console.log(out.split('\n').filter(l => /FAIL|Error|failed|FAILED/.test(l)).slice(0, 12).map(l => `      ${l}`).join('\n'));
}
const failed = summary.filter(s => !s.ok);
console.log(`\n${summary.length - failed.length}/${summary.length} test files passed${summary.some(s => s.skipped) ? ' (some skipped: Playwright is not installed)' : ''}`);
process.exit(failed.length ? 1 : 0);
