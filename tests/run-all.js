// Runs every test that doesn't need a browser, and says if any failed.
// Run with:  node tests/run-all.js
// (The browser test is separate, because it needs Playwright: node tests/browser/acceptance.test.js)

const { spawnSync } = require('child_process');
const path = require('path');

const SUITES = ['contract.test.js', 'rules.test.js', 'regression.test.js', 'robustness.test.js', 'service-worker.test.js', 'speech.test.js'];
let failed = 0;
for (const suite of SUITES) {
  const run = spawnSync(process.execPath, [path.join(__dirname, suite)], { encoding: 'utf8', timeout: 180000 });
  const output = `${run.stdout || ''}${run.stderr || ''}`;
  const summary = output.trim().split('\n').filter(l => /passed|failed/.test(l)).pop() || '(no summary)';
  const ok = run.status === 0;
  if (!ok) failed++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${suite.padEnd(24)} ${summary}`);
  if (!ok) console.log(output.split('\n').filter(l => l.startsWith('FAIL')).map(l => `      ${l}`).join('\n'));
}
console.log(failed ? `\n${failed} suite(s) failed` : '\nAll suites passed');
process.exitCode = failed ? 1 : 0;
